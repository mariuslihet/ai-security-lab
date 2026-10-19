# System Architecture Specification

## 1. Overview
The `ai-security-lab` is a modular software framework designed to evaluate foundation models and runtime defense mechanisms against adversarial inputs. It operates as an automated test harness and inspection pipeline, decoupling client provider implementations from safety guardrail policies and metric evaluation engines.

---

## 2. Core Architectural Layers

The framework is organized into five decoupled layers:

```
[ Test Payloads / Benchmarks (data/) ]
                 |
                 v
[ Perimeter Input Guardrails (guardrails/input/) ]
                 |
         +-------+-------+
         |               |
   (If Allowed)     (If Blocked)
         |               |
         v               v
[ Provider Clients ]  [ Metrics Evaluator (evals/) ]
(OpenAI, Claude,         ^
 Azure, Bedrock)         |
         |               |
         v               |
[ Egress Output Guardrails (guardrails/output/) ]
         |               |
         +---------------+
                 |
                 v
[ Reports & Dashboard (reports/, dashboard/) ]
```

### 2.1 Provider Client Abstraction (`core/`)
The `core` module standardizes interaction across different LLM cloud providers through the `BaseLLMClient` abstract interface:
- **`OpenAIClient`**: Wraps the official OpenAI SDK for direct inference.
- **`AnthropicClient`**: Interacts with the Anthropic Claude API using structured message formats.
- **`AzureAIClient`**: Connects to Azure OpenAI Service deployments.
- **`BedrockClient`**: Utilizes the AWS Boto3 Bedrock-Runtime Converse API.
- **`Factory`**: Resolves provider names dynamically (`get_llm_client`). Provides deterministic diagnostic simulation when API credentials are omitted, preventing execution failure during automated CI pipelines.

### 2.2 Guardrail Engine (`guardrails/`)
The `GuardrailEngine` orchestrates multi-tiered evaluation:
- **Input Pipeline**: Inspects incoming text for instruction overrides, role-hijacking signatures, delimiter breakouts, embedded Base64 payloads, and Personally Identifiable Information (PII).
- **Output Pipeline**: Inspects completions for secret canary leakage, model compliance with adversarial payloads, and PII reflection.
- **Policy Enforcement**: Aggregates violation scores into categorical actions (`ALLOW`, `FLAG`, `BLOCK`).

### 2.3 Automated Test Harness (`harness/`)
The `SecurityHarness` runs parameterized test definitions (`SecurityTestCase`) against model endpoints:
- Loads benchmark specifications from YAML and JSON files (`harness/loader.py`).
- Supports synchronous batch execution and asynchronous task concurrency via `asyncio.Semaphore`.
- Tracks defense-layer attribution: whether an attack was neutralized by the perimeter input filter, an autonomous model refusal, or an output egress filter.

### 2.4 Evaluation and Risk Scoring (`evals/`)
Aggregates telemetry into standardized metrics:
- **Attack Success Rate (ASR)**: Proportion of adversarial payloads that successfully bypassed defenses.
- **Robustness Score**: Normalized defense metric computed as `100.0 * (1.0 - ASR)`.
- **OWASP Risk Scorer**: Groups vulnerability findings into OWASP Top 10 for LLM categories and assigns severity ratings.

### 2.5 Real-Time Telemetry and Reporting (`reports/`, `dashboard/`)
- Outputs machine-readable JSON logs for CI/CD status gates.
- Generates formatted Markdown summaries for security audit records.
- Provides a FastAPI-powered WebSocket telemetry server for real-time trace streaming.
