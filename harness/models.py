"""
Data models representing test cases, test suites, and execution outcomes.
"""

from __future__ import annotations

from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field
from core.base import LLMResponse
from guardrails.base import GuardrailResult, RiskLevel


class SecurityCategory(str, Enum):
    """OWASP Top 10 for LLMs and core AI security threat taxonomies."""
    PROMPT_INJECTION = "prompt_injection"          # LLM01: Prompt Injection
    JAILBREAK = "jailbreak"                        # LLM01 / Adversarial Alignment Bypass
    PII_LEAKAGE = "pii_leakage"                    # LLM06: Sensitive Information Disclosure
    SYSTEM_PROMPT_LEAK = "system_prompt_leak"      # LLM07: System Prompt & Data Exfiltration
    INSECURE_OUTPUT = "insecure_output"            # LLM02: Insecure Output Handling


class ExpectedBehavior(str, Enum):
    """Expected model or system defense action."""
    REFUSE = "refuse"    # Model itself refuses the adversarial request
    BLOCK = "block"      # Guardrail blocks the request before model or output
    MASK = "mask"        # Sensitive data is masked or redacted


class SecurityTestCase(BaseModel):
    """Defines an individual security benchmark test payload."""
    id: str
    name: str
    category: SecurityCategory
    severity: RiskLevel = RiskLevel.HIGH
    prompt: str
    system_prompt: Optional[str] = None
    canary: Optional[str] = None
    expected_behavior: ExpectedBehavior = ExpectedBehavior.BLOCK
    description: Optional[str] = None
    tags: List[str] = Field(default_factory=list)
    metadata: Dict[str, Any] = Field(default_factory=dict)


class TestExecutionResult(BaseModel):
    """Detailed telemetry and verdict for an individual test execution."""
    __test__ = False

    test_case: SecurityTestCase
    input_guardrail_result: Optional[GuardrailResult] = None
    llm_response: Optional[LLMResponse] = None
    output_guardrail_result: Optional[GuardrailResult] = None
    is_attack_prevented: bool
    attack_succeeded: bool
    defense_layer_triggered: Optional[str] = None  # e.g., 'input_guardrail', 'model_refusal', 'output_guardrail', 'none'
    execution_time_ms: float
    notes: Optional[str] = None
