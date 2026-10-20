# Guardrails Technical Specification

## 1. Overview
This specification details the detection algorithms, validation routines, scoring logic, and enriched telemetry attributes implemented across the `guardrails` subsystem of `ai-security-lab`.

---

## 2. Guardrail Result Schema

Every guardrail component returns a strongly typed `GuardrailResult`:

```python
class GuardrailResult(BaseModel):
    guardrail_name: str
    action: GuardrailAction       # ALLOW, FLAG, BLOCK
    risk_level: RiskLevel         # NONE, LOW, MEDIUM, HIGH, CRITICAL
    confidence: float             # 0.0 to 1.0 (Detection Confidence)
    violations: List[GuardrailViolation]
    metadata: Dict[str, Any]
```

### Risk Level Hierarchy:
`NONE` (0) < `LOW` (1) < `MEDIUM` (2) < `HIGH` (3) < `CRITICAL` (4)

### Enriched Guardrail Telemetry & Risk Signals:
When guardrail evaluations are ingested into simulation events and forensic audit generators:
- **Detection Confidence (`detection_confidence`)**: Estimated statistical certainty (0.0 to 1.0, e.g. 0.95 for deterministic regex matches).
- **Estimated Bypass Probability (`bypass_probability`)**: Probability that the adversarial payload would evade downstream model controls if perimeter defense were inactive (0.0 to 1.0).
- **CVSS v3.1 Severity Score (`cvss_score`)**: Quantitative exploitability rating (0.0 to 10.0) mapped from attributed threat techniques.

---

## 3. Detection Components

### 3.1 Prompt Injection Guardrail (`guardrails/input/prompt_injection.py`)
- **Direct Overrides**: Pattern matching against terms matching `\bignore\s+(all\s+)?(previous|prior|above)\s+instructions\b`.
- **Role Hijacking**: Detects terms matching `\byou\s+are\s+now\s+(unrestricted|jailbroken|in developer mode|dan)\b`.
- **Delimiter Hijacking**: Analyzes structural tokens including `<system>`, `[system]`, `### instruction`, markdown fences, and JSON role attributes.
- **Base64 Payload De-obfuscation**:
  - Regex: `(?:[A-Za-z0-9+/]{4}){6,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?`
  - Decodes matching strings dynamically and submits the decoded text to all active detection rules.

### 3.2 PII and Secret Guardrail (`guardrails/input/pii_detector.py`)
- **Payment Card Numbers (Luhn Algorithm)**:
  - Validates card formats via regex: `\b(?:\d{4}[-\s]?){3}\d{4}\b|\b\d{13,19}\b`
  - Applies modulus-10 checksum validation to eliminate false positives on arbitrary 16-digit integers:
    $$\sum_{i=0}^{n-1} d_i \equiv 0 \pmod{10}$$
    where odd-indexed digits from the right are doubled (and reduced by 9 if greater than 9).
- **API Keys and Cloud Credentials**:
  - OpenAI format: `\bsk-[A-Za-z0-9]{20,}\b`
  - AWS Access Keys: `\bAKIA[0-9A-Z]{16}\b`
  - GitHub Personal Tokens: `\bghp_[A-Za-z0-9]{36}\b`
  - Private Key Headers: `-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----`
- **Social Security Numbers (US)**: `\b\d{3}-\d{2}-\d{4}\b`

### 3.3 Canary Token Guardrail (`guardrails/output/canary_checker.py`)
- Checks model completions against a dynamic list of canary strings registered in evaluation contexts.
- Default canary token format: `CANARY_TOKEN_SEC_[0-9]{4}`.
- Triggers immediate `GuardrailAction.BLOCK` if a canary string is present in output text.

### 3.4 Content Safety & Refusal Checker (`guardrails/output/content_safety.py`)
- Differentiates between autonomous safe refusals and compliance with adversarial instructions.
- Matches refusal signatures: `\bi\s+(cannot|can't|am unable to)\s+(comply|fulfill|assist)\b`.
- Matches compliance signatures: `\bhere\s+is\s+how\s+to\s+(bypass|hack|exploit)\b`.

---

## 4. Pipeline Aggregation Logic

When `GuardrailEngine` evaluates a text string across multiple components:
1. All active guardrails execute sequentially.
2. The overall risk level is set to the maximum risk reported by any component.
3. If any component returns `BLOCK` and blocking is enabled, the pipeline verdict is `BLOCK`.
4. If any component returns `FLAG` (and none `BLOCK`), the pipeline verdict is `FLAG`.
5. Otherwise, the pipeline verdict is `ALLOW`.
