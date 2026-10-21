"""Versioned test definitions and evidence recorded by the shared harness."""

from __future__ import annotations
from enum import Enum
from typing import Any
from pydantic import BaseModel, ConfigDict, Field, model_validator
from core.base import LLMResponse
from guardrails.base import GuardrailResult, RiskLevel


class SecurityCategory(str, Enum):
    PROMPT_INJECTION = "prompt_injection"
    JAILBREAK = "jailbreak"
    PII_LEAKAGE = "pii_leakage"
    SYSTEM_PROMPT_LEAK = "system_prompt_leak"
    INSECURE_OUTPUT = "insecure_output"
    TOOL_ABUSE = "tool_abuse"
    BENIGN = "benign"


class ExpectedBehavior(str, Enum):
    REFUSE = "refuse"
    BLOCK = "block"
    MASK = "mask"
    ALLOW = "allow"


class SecurityTestCase(BaseModel):
    model_config = ConfigDict(extra="forbid")
    id: str = Field(min_length=1, max_length=100)
    name: str
    category: SecurityCategory
    severity: RiskLevel = RiskLevel.HIGH
    prompt: str = Field(min_length=1, max_length=20000)
    system_prompt: str | None = None
    canary: str | None = None
    expected_behavior: ExpectedBehavior = ExpectedBehavior.BLOCK
    description: str | None = None
    tags: list[str] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)
    threat_category: str | None = None
    taxonomy_version: str = "OWASP-LLM-2025"
    technique: str | None = None
    cvss_score: float | None = Field(default=None, ge=0, le=10)
    defense_layer_expected: str | None = None
    dataset_version: str = "2.1"
    source: str = "AI Security Lab synthetic fixtures"
    license: str = "Apache-2.0"
    language: str = "en"
    objective: str = "Do not follow unauthorized instructions."
    success_contains: list[str] = Field(default_factory=list)
    safe_contains: list[str] = Field(default_factory=list)
    messages: list[dict[str, str]] = Field(default_factory=list, max_length=20)
    documents: list[str] = Field(default_factory=list, max_length=10)
    forbidden_tools: list[str] = Field(default_factory=list)
    is_adversarial: bool = True
    demo_response: str = "Synthetic target returned an unspecified answer."
    demo_safe_response: str = "Authorized task completed without protected data."
    demo_behavior: str = Field(
        default="comply", pattern="^(comply|refuse|safe|ambiguous|error)$"
    )

    @model_validator(mode="after")
    def benign_policy(self):
        for message in self.messages:
            if (
                set(message) != {"role", "content"}
                or message["role"] != "user"
                or not message["content"].strip()
                or len(message["content"]) > 20000
            ):
                raise ValueError(
                    "Conversation fixtures require nonempty user turns of at most 20000 characters"
                )
        if any(len(document) > 20000 for document in self.documents):
            raise ValueError("Fixture documents must be at most 20000 characters")
        if self.category == SecurityCategory.BENIGN:
            self.is_adversarial = False
            self.expected_behavior = ExpectedBehavior.ALLOW
        return self


class TestExecutionResult(BaseModel):
    __test__ = False
    test_case: SecurityTestCase
    input_guardrail_result: GuardrailResult | None = None
    llm_response: LLMResponse | None = None
    output_guardrail_result: GuardrailResult | None = None
    is_attack_prevented: bool = False
    attack_succeeded: bool = False
    defense_layer_triggered: str | None = None
    execution_time_ms: float = 0
    notes: str | None = None
    verdict: str | None = None
    model_attack_succeeded: bool | None = None
    evaluator: str = "objective-v2"
    evidence: list[str] = Field(default_factory=list)
    events: list[dict[str, Any]] = Field(default_factory=list)
    delivered_content: str | None = None
    tool_calls: list[dict[str, Any]] = Field(default_factory=list)
    error: str | None = None
    execution_mode: str = "demo"
