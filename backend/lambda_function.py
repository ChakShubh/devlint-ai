import json
import base64
import re
import traceback
import boto3

bedrock = boto3.client("bedrock-runtime", region_name="us-east-1")

SYSTEM_PROMPT = (
    "You are DevLint AI, a high-precision developer security linter and code explainer.\n"
    "Analyze the provided snippet (Shell script, Dockerfile, or Regular Expression).\n"
    "Perform three core evaluations:\n"
    "1. Security & Hygiene Audit: Check for dangerous patterns, unsafe flags, unquoted variables, "
    "root execution, catastrophic backtracking, or secret leaks.\n"
    "2. Plain-English Breakdown: Explain what each line or token actually does in sequence.\n"
    "3. Sanitized Fix: Provide an improved, hardened version of the snippet.\n"
    "CRITICAL FORMAT RULES:\n"
    "- Respond STRICTLY with a valid JSON object matching the schema.\n"
    "- Do NOT output any markdown backticks, explanations, or text outside the JSON.\n"
    "- All strings inside the JSON MUST be valid JSON strings (properly escape newlines as \\n and double quotes as \\\")."
)

USER_PROMPT_TEMPLATE = """
Snippet Type: {snippet_type}
Snippet Content:
{snippet_content}

Output Schema:
{{
  "safety_score": 85,
  "verdict": "SECURE | CAUTION | DANGEROUS",
  "summary": "High-level summary of what this code does and its risks.",
  "security_findings": [
    {{
      "severity": "CRITICAL | WARNING | INFO",
      "issue": "Brief description of the problem",
      "detail": "Why this is dangerous or bad practice"
    }}
  ],
  "step_by_step_explanation": [
    "Step 1 or token 1 explanation",
    "Step 2 or token 2 explanation"
  ],
  "sanitized_snippet": "# Sanitized code with newlines escaped as \\n",
  "best_practices": [
    "Key actionable recommendation"
  ]
}}
"""

def extract_json(raw_text):
    text = raw_text.strip()
    
    # Strip markdown wrappers if present
    if "```json" in text:
        text = text.split("```json", 1)[1].split("```", 1)[0].strip()
    elif "```" in text:
        text = text.split("```", 1)[1].split("```", 1)[0].strip()

    # Locate outermost JSON braces
    match = re.search(r"\{.*\}", text, re.DOTALL)
    if match:
        text = match.group(0)

    try:
        # strict=False allows unescaped control characters (like raw tabs/newlines inside strings)
        return json.loads(text, strict=False)
    except json.JSONDecodeError:
        # Fallback: sanitize raw carriage returns and newlines that break JSON string boundaries
        sanitized = re.sub(r'(?<!\\)\n', r'\\n', text)
        return json.loads(sanitized, strict=False)


def lambda_handler(event, context):
    try:
        raw_body = event.get("body", "{}")
        if event.get("isBase64Encoded", False):
            raw_body = base64.b64decode(raw_body).decode("utf-8")

        payload = json.loads(raw_body) if isinstance(raw_body, str) else (raw_body or {})

        snippet_type = payload.get("type", "shell").strip().lower()
        snippet_content = payload.get("content", "").strip()

        if not snippet_content:
            return {
                "statusCode": 400,
                "headers": {"Content-Type": "application/json"},
                "body": json.dumps({"error": "Snippet content is empty."})
            }

        formatted_user_prompt = USER_PROMPT_TEMPLATE.format(
            snippet_type=snippet_type,
            snippet_content=snippet_content[:4000]
        )

        request_payload = {
            "system": [{"text": SYSTEM_PROMPT}],
            "messages": [
                {
                    "role": "user",
                    "content": [{"text": formatted_user_prompt}]
                }
            ],
            "inferenceConfig": {
                "maxTokens": 2048,
                "temperature": 0.1
            }
        }

        response = bedrock.invoke_model(
            modelId="amazon.nova-micro-v1:0",
            body=json.dumps(request_payload),
            accept="application/json",
            contentType="application/json"
        )

        response_body = json.loads(response["body"].read())
        raw_output = response_body["output"]["message"]["content"][0]["text"].strip()

        parsed_audit = extract_json(raw_output)

        return {
            "statusCode": 200,
            "headers": {"Content-Type": "application/json"},
            "body": json.dumps(parsed_audit)
        }

    except Exception as exc:
        print("DevLint Execution Traceback:")
        traceback.print_exc()
        return {
            "statusCode": 500,
            "headers": {"Content-Type": "application/json"},
            "body": json.dumps({"error": str(exc)})
        }