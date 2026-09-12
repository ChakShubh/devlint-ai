import json
import base64
import re
import traceback
import boto3

bedrock = boto3.client("bedrock-runtime", region_name="us-east-1")

HEADERS = {
    "Content-Type": "application/json",
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Methods": "OPTIONS,POST",
    "Access-Control-Allow-Headers": "Content-Type"
}

SYSTEM_PROMPT = """You are DevLint AI, an elite security auditor and syntax explainer.
Evaluate the code according to its specific domain:

1. SHELL / BASH:
   - DANGEROUS: Remote execution (`curl/wget | bash`), `eval` abuse, unquoted variables in destructive commands (`rm`, `chown`), inline secrets/passwords, or reverse shell patterns (`/dev/tcp`).
   - CAUTION: Overly permissive rights (`chmod 777`), parsing `ls` output, insecure temp files (not using `mktemp`), missing error traps (`set -euo pipefail`).
   - SECURE: Strict error handling (`set -euo pipefail`), properly quoted variables (`"$VAR"`), using `[[ ]]` for tests.

2. DOCKERFILE:
   - DANGEROUS: Hardcoded secrets in ENV/ARG, running as `USER root`, using `ADD` to fetch remote URLs (can auto-extract and bypass checks), curling untested scripts directly.
   - CAUTION: Unpinned tags (`:latest`), missing package cache cleanup (`rm -rf /var/lib/apt/lists/*`), missing `WORKDIR`, running `apt-get upgrade` (breaks determinism).
   - SECURE: Multi-stage builds, SHA256 image digests (`@sha256:...`), explicit non-root `USER`, least-privilege `COPY --chown`.

3. REGULAR EXPRESSIONS (REGEX):
   - DANGEROUS: Catastrophic backtracking/ReDoS vulnerabilities (nested quantifiers like `(a+)*` or overlapping alternations). Unanchored sensitive input validation allowing prefix/suffix injection.
   - CAUTION: Unescaped dots (`.`) in domain/URL patterns allowing spoofing. Excessive use of greedy `.*` matches.
   - SECURE: Strictly anchored (`^`, `$`), explicitly bounded quantifiers (`{1,64}`), mutually exclusive alternations.

CRITICAL FORMAT RULES:
- Output MUST be a strictly valid JSON object.
- NEVER include trailing commas.
- Escape all internal double quotes (`\\"`) and newlines (`\\n`).
- NO markdown fences, NO conversational preamble."""

USER_PROMPT_TEMPLATE = """Domain: {snippet_type}
Snippet:
{snippet_content}

Analyze the snippet and return ONLY a JSON object. You must construct the JSON yourself using EXACTLY the following keys:
- "safety_score": (integer) Calculate a score between 10 and 100 based on risk.
- "verdict": (string) Must be exactly "SECURE", "CAUTION", or "DANGEROUS".
- "summary": (string) Concise risk analysis.
- "security_findings": (array of objects) Each object must have "severity", "issue", and "detail" string keys.
- "step_by_step_explanation": (array of strings) Token or line-by-line breakdown.
- "sanitized_snippet": (string) Corrected safe code. Escape newlines as \\n.
- "best_practices": (array of strings) Actionable recommendations."""

def extract_json(raw_text):
    text = raw_text.strip()
    
    if "```json" in text:
        text = text.split("```json", 1)[1].split("```", 1)[0].strip()
    elif "```" in text:
        text = text.split("```", 1)[1].split("```", 1)[0].strip()

    match = re.search(r"\{.*\}", text, re.DOTALL)
    if match:
        text = match.group(0)

    text = re.sub(r',\s*\}', '}', text)
    text = re.sub(r',\s*\]', ']', text)

    try:
        return json.loads(text, strict=False)
    except json.JSONDecodeError:
        sanitized = re.sub(r'(?<!\\)\n', r'\\n', text)
        return json.loads(sanitized, strict=False)

def apply_heuristics(snippet_type, snippet_content):
    findings = []
    verdict = None

    if snippet_type == "regex":
        if re.search(r"\([^)]*[+*][^)]*\)[+*]", snippet_content):
            verdict = "DANGEROUS"
            findings.append({
                "severity": "CRITICAL",
                "issue": "Catastrophic Backtracking (ReDoS)",
                "detail": "Nested quantifiers cause exponential evaluation time on non-matching inputs, creating Denial of Service vulnerabilities."
            })
        elif re.search(r"(https?:\/\/)?([a-zA-Z0-9-]+\.[a-zA-Z0-9-]+)", snippet_content) and r"\." not in snippet_content and "." in snippet_content:
            verdict = "CAUTION" if not verdict else verdict
            findings.append({
                "severity": "WARNING",
                "issue": "Unescaped Dot in Domain Pattern",
                "detail": "An unescaped `.` matches any character, allowing spoofed domains (e.g., sitexcom instead of site.com)."
            })
        elif not snippet_content.startswith("^") and not snippet_content.endswith("$") and ".*" in snippet_content:
            verdict = "CAUTION" if not verdict else verdict
            findings.append({
                "severity": "WARNING",
                "issue": "Unanchored Greedy Match",
                "detail": "Missing anchors (`^`, `$`) combined with `.*` can cause unintended partial matches in security contexts."
            })

    elif snippet_type == "shell":
        if re.search(r"(curl|wget).*\|\s*(bash|sh)", snippet_content):
            verdict = "DANGEROUS"
            findings.append({
                "severity": "CRITICAL",
                "issue": "Remote Script Piped to Shell",
                "detail": "Executing unverified remote scripts directly opens the system to arbitrary code execution."
            })
        if "chmod 777" in snippet_content:
            verdict = "CAUTION" if not verdict else verdict
            findings.append({
                "severity": "WARNING",
                "issue": "Overly Permissive File Rights (777)",
                "detail": "Setting permissions to 777 grants read, write, and execute access to every user on the system."
            })

    elif snippet_type == "dockerfile":
        if "USER root" in snippet_content or ("USER " not in snippet_content and "FROM " in snippet_content):
            verdict = "CAUTION" if not verdict else verdict
            findings.append({
                "severity": "WARNING",
                "issue": "Root Execution Privilege",
                "detail": "Containers should drop privileges to a non-root user to mitigate container escape vulnerabilities."
            })
        if re.search(r"FROM [^\s]+:latest", snippet_content):
            verdict = "CAUTION" if not verdict else verdict
            findings.append({
                "severity": "WARNING",
                "issue": "Unpinned Base Image (:latest)",
                "detail": "Using floating tags leads to non-deterministic builds and introduces breaking upstream changes."
            })
        if re.search(r"^ADD\s+http", snippet_content, re.MULTILINE):
            verdict = "CAUTION" if not verdict else verdict
            findings.append({
                "severity": "WARNING",
                "issue": "ADD used for Remote URLs",
                "detail": "Using `ADD` to fetch remote files is discouraged. Use `curl`/`wget` to fetch, verify checksums, and extract within a single `RUN` layer to minimize image size."
            })

    return verdict, findings
    
def lambda_handler(event, context):
    try:
        if event.get("requestContext", {}).get("http", {}).get("method") == "OPTIONS":
            return {"statusCode": 204, "headers": HEADERS, "body": ""}

        raw_body = event.get("body", "{}")
        if event.get("isBase64Encoded", False):
            raw_body = base64.b64decode(raw_body).decode("utf-8")

        payload = json.loads(raw_body) if isinstance(raw_body, str) else (raw_body or {})

        snippet_type = payload.get("type", "shell").strip().lower()
        snippet_content = payload.get("content", "").strip()

        if not snippet_content:
            return {"statusCode": 400, "headers": HEADERS, "body": json.dumps({"error": "Snippet empty"})}

        heuristic_verdict, heuristic_findings = apply_heuristics(snippet_type, snippet_content)

        request_payload = {
            "system": [{"text": SYSTEM_PROMPT}],
            "messages": [{"role": "user", "content": [{"text": USER_PROMPT_TEMPLATE.format(
                snippet_type=snippet_type, 
                snippet_content=snippet_content[:4000]
            )}]}],
            "inferenceConfig": {"maxTokens": 2048, "temperature": 0.0}
        }

        response = bedrock.invoke_model(
            modelId="amazon.nova-micro-v1:0",
            body=json.dumps(request_payload),
            accept="application/json",
            contentType="application/json"
        )
        
        parsed_audit = extract_json(json.loads(response["body"].read())["output"]["message"]["content"][0]["text"])

        parsed_audit.setdefault("security_findings", [])
        parsed_audit.setdefault("step_by_step_explanation", ["No breakdown available."])
        parsed_audit.setdefault("sanitized_snippet", snippet_content)
        parsed_audit.setdefault("best_practices", [])

        existing_issues = {f.get("issue") for f in parsed_audit["security_findings"]}
        for hf in heuristic_findings:
            if hf["issue"] not in existing_issues:
                parsed_audit["security_findings"].insert(0, hf)

        verdict = parsed_audit.get("verdict", "CAUTION").upper()
        
        if heuristic_verdict == "DANGEROUS":
            verdict = "DANGEROUS"
        elif heuristic_verdict == "CAUTION" and verdict == "SECURE":
            verdict = "CAUTION"

        # FOOLPROOF CLAMP: It is mathematically impossible to return 0 or misaligned scores now
        score = int(parsed_audit.get("safety_score", 50))
        
        if verdict == "DANGEROUS":
            parsed_audit["safety_score"] = 25 if (score > 40 or score < 10) else score
        elif verdict == "SECURE":
            parsed_audit["safety_score"] = 92 if (score < 85) else score
        elif verdict == "CAUTION":
            parsed_audit["safety_score"] = 65 if (score < 45 or score > 75) else score

        parsed_audit["verdict"] = verdict

        return {
            "statusCode": 200,
            "headers": HEADERS,
            "body": json.dumps(parsed_audit)
        }

    except Exception as exc:
        print("DevLint Fatal Error:")
        traceback.print_exc()
        return {
            "statusCode": 500,
            "headers": HEADERS,
            "body": json.dumps({"error": str(exc)})
        }
