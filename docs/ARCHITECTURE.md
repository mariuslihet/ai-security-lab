# System Architecture Specification

## 1. Overview
The `ai-security-lab` is a modular, production-ready security evaluation laboratory and red-teaming harness designed to evaluate foundation models and runtime defense mechanisms against adversarial inputs. It operates as an automated test harness, real-time WebSocket inspection pipeline, and forensic audit generator, decoupling client provider implementations from safety guardrail policies, metrics engines, and reporting backends.

---

## 2. Core Architectural Layers

The framework is organized into five decoupled layers:

```
[ Test Payloads / Benchmarks (data/*.yaml) ]
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
 - Markdown & JSON Reporters
 - Forensic SimulationReportGenerator
 - Real-Time SecOps Control Plane (FastAPI + WebSocket)
 - Styled Report Viewer & Print/PDF Engine (/reports/{filename})
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

### 2.3 Automated Test Harness & Simulation Engine (`harness/`)
The `SecurityHarness` and `AdvancedSimulationRunner` run parameterized test definitions (`SecurityTestCase`) against model endpoints:
- Loads benchmark specifications across 7 probe suites from YAML and JSON files (`harness/loader.py`).
- Supports synchronous batch execution and asynchronous task concurrency via `asyncio.Semaphore`.
- **Advanced Simulation Engine (`harness/simulation.py`)**:
  - Executes single-probe and full batch suite evaluations (`run_batch_suite`).
  - Simulates multi-turn crescendo attacks (`run_multi_turn_crescendo`) and indirect context poisoning (`run_rag_data_poisoning`).
  - Emits microsecond-precision `SimulationStepEvent` objects with enriched telemetry: `detection_confidence`, `bypass_probability`, `cvss_score`, `threat_category`, `technique_label`, and token footprint.
- Tracks defense-layer attribution: whether an attack was neutralized by the perimeter input filter, an autonomous model refusal, or an output egress filter.

### 2.4 Evaluation and Risk Scoring (`evals/`)
Aggregates telemetry into standardized metrics:
- **Attack Success Rate (ASR)**: Proportion of adversarial payloads that successfully bypassed defenses.
- **Robustness Score**: Normalized defense metric computed as `100.0 * (1.0 - ASR)`.
- **Threat Risk Scorer**: Groups vulnerability findings into threat categories and assigns severity ratings.

### 2.5 Real-Time Telemetry and Forensic Reporting (`reports/`, `dashboard/`)
- **`SimulationReportGenerator` (`reports/simulation_report.py`)**: Transforms streaming WebSocket execution traces into exhaustive, publication-grade security audit reports (Markdown & structured JSON). Includes executive summaries, threat taxonomy, vulnerability mechanisms, business impacts, adversarial payload forensics, stage execution traces, and prioritized hardening roadmaps.
- **`MarkdownReporter` (`reports/markdown.py`)**: Generates defense-in-depth attribution tables with ASCII bar charts, compliance benchmark indicators, and threat coverage breakdowns.
- **`JSONReporter` (`reports/json_reporter.py`)**: Outputs machine-readable logs for CI/CD quality gates.
- **FastAPI SecOps Control Plane (`dashboard/app.py`)**:
  - WebSocket `/ws/simulate`: Streams real-time pipeline events with single-probe and batch suite support.
  - Document Viewer `/reports/{filename}`: Renders `.md` and `.json` audit artifacts in an interactive, print-optimized document view with PDF export capabilities (`templates/report_view.html`).
  - REST Endpoints: `/api/simulate-and-report`, `/api/reports/{stem}/summary`, `/api/check-prompt`, and `/api/status`.
