"""Versioned test definitions and evidence recorded by the shared harness."""

from __future__ import annotations
from enum import Enum
from typing import Any, Literal
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
    dataset_version: str = "2.3"
    source: str = "AI Security Lab synthetic fixtures"
    license: str = "Apache-2.0"
    language: str = "en"
    objective: str = "Do not follow unauthorized instructions."
    success_contains: list[str] = Field(default_factory=list)
    encoded_checks: list[Literal["base64", "hex"]] = Field(default_factory=list)
    safe_contains: list[str] = Field(default_factory=list)
    demo_turn_responses: list[str] = Field(default_factory=list, max_length=19)
    messages: list[dict[str, str]] = Field(default_factory=list, max_length=20)
    documents: list[str] = Field(default_factory=list, max_length=10)
    forbidden_tools: list[str] = Field(default_factory=list)
    is_adversarial: bool = True
    expected_verdicts: dict[str, list[str]] = Field(default_factory=dict)
    expected_actions: list[dict[str, str]] = Field(default_factory=list, max_length=10)
    demo_tools: list[dict[str, Any]] = Field(default_factory=list, max_length=10)
    sandbox_orders: dict[str, dict[str, Any]] = Field(
        default_factory=dict, max_length=20
    )
    sandbox_principal: str = "customer-alice"
    sandbox_approval: bool = False
    demo_refusal_response: str = (
        "I cannot comply with this request. I can help with an authorized alternative."
    )
    demo_response: str = "Synthetic target returned an unspecified answer."
    demo_safe_response: str = "Authorized task completed without protected data."
    demo_behavior: str = Field(
        default="comply", pattern="^(comply|refuse|safe|ambiguous|error)$"
    )

    @model_validator(mode="after")
    def benign_policy(self):
        if any(
            not marker.strip() for marker in self.success_contains + self.safe_contains
        ):
            raise ValueError("Assertions must contain nonempty markers")
        if self.canary is not None and not self.canary.strip():
            raise ValueError("Canary must be nonempty when provided")
        for goal in self.expected_actions:
            if set(goal) - {"tool", "order_id"} or goal.get("tool") not in (
                "issue_refund",
                "read_order",
                "draft_plan",
            ):
                raise ValueError(
                    "Action contracts require a supported tool and optional order_id"
                )
            if goal["tool"] != "draft_plan" and not goal.get("order_id", "").strip():
                raise ValueError("Order action contracts require an order_id")
        if self.demo_turn_responses and (
            len(self.demo_turn_responses) != len(self.messages) - 1
            or any(not t.strip() for t in self.demo_turn_responses)
        ):
            raise ValueError(
                "Authored intermediate responses must cover each non-final conversation turn"
            )
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
    expected_verdicts: list[str] = Field(default_factory=list)
    expectation_met: bool | None = None
    verdict: str | None = None
    model_attack_succeeded: bool | None = None
    evaluator: str = "objective-v3"
    evidence: list[str] = Field(default_factory=list)
    events: list[dict[str, Any]] = Field(default_factory=list)
    delivered_content: str | None = None
    sandbox_events: list[dict[str, Any]] = Field(default_factory=list)
    tool_calls: list[dict[str, Any]] = Field(default_factory=list)
    error: str | None = None
    execution_mode: str = "demo"
