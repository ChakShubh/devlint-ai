# DevLint AI

> Real-time developer security linter and plain-English syntax explainer for Shell scripts, Dockerfiles, and Regular Expressions. Built on AWS serverless primitives.

---

## Overview

Developers frequently encounter complex shell one-liners, unverified Dockerfiles, or dense regular expressions. Running or committing these snippets without a line-by-line understanding introduces severe security risks-ranging from command injection and privilege escalation to ReDoS (Regular Expression Denial of Service).

**DevLint AI** provides an instant, zero-setup diagnostic workspace where developers can inspect snippets to receive:
* **Deterministic Security Audits:** Identification of dangerous execution patterns, unquoted variables, unpinned images, and ReDoS vulnerabilities.
* **Plain-English Explanations:** Sequential breakdowns of cryptic syntax tokens and command flags.
* **Automated Sanitized Fixes:** Ready-to-copy hardened alternatives implementing least-privilege standards.
* **Safety Scoring:** Immediate 0–100 safety indexing with actionable verdicts (`SECURE`, `CAUTION`, `DANGEROUS`).

---

## Architecture

```text
┌────────────────────────────────────────────────────────┐
│                   AWS Amplify Hosting                  │
│       (Glassmorphic Vanilla Single-Page App)           │
└──────────────────────────┬─────────────────────────────┘
                           │
                           │ 1. HTTPS POST (JSON snippet payload)
                           ▼
┌────────────────────────────────────────────────────────┐
│               AWS Lambda (Python 3.14)                 │
│         (DevLint-Engine + Lambda Function URL)         │
└──────────────────────────┬─────────────────────────────┘
                           │
                           │ 2. Parameter Sanitization & Prompt Contract
                           ▼
┌────────────────────────────────────────────────────────┐
│               Amazon Bedrock Runtime                   │
│             (amazon.nova-micro-v1:0)                   │
└──────────────────────────┬─────────────────────────────┘
                           │
                           │ 3. Structured JSON Schema Verdict
                           ▼
┌────────────────────────────────────────────────────────┐
│                  Amplify Frontend UI                   │
│        (Instant Verdict, Dissection, & Fix Display)    │
└────────────────────────────────────────────────────────┘
```

## AWS Services Used

* **AWS Amplify Hosting:** Fast, static single-page application hosting with global edge CDN distribution and automated SSL termination.
* **AWS Lambda (Python 3.14):** Serverless compute utilizing standard library modules for sub-second execution with zero external package dependencies.
* **Lambda Function URLs:** High-speed, low-latency HTTPS endpoint with direct CORS controls, bypassing the need for dedicated API Gateway overhead.
* **Amazon Bedrock (`amazon.nova-micro-v1:0`):** Ultra-fast foundation model inference extracting semantic risk patterns, generating explanations, and producing code fixes in strict JSON format.

---

## Getting Started

### Backend Setup

1. Create an AWS Lambda function running **Python 3.14**.
2. Paste the contents of `backend/lambda_function.py`.
3. Set the function timeout to `20` seconds.
4. Attach an IAM policy permitting `bedrock:InvokeModel`.
5. Enable **Function URL** (Auth type `NONE`) with CORS enabled (`Allow origin: *`, `Allow methods: POST, OPTIONS`).

### Frontend Deployment

1. Replace `YOUR_LAMBDA_FUNCTION_URL_HERE` in `frontend/index.html` with your deployed Lambda Function URL.
2. Connect this repository to **AWS Amplify Hosting** (or upload the `frontend/` directory directly).
3. Access your live app at the provided Amplify domain.
