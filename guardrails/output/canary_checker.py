"""
System Prompt Canary & Secret Extraction Guardrail.
Monitors generated responses for leaks of secret canary tokens or system prompt markers.
"""

from __future__ import annotations

import re
from typing import Any, Dict, List, Optional
from guardrails.base import (
    BaseGuardrail,
    GuardrailAction,
    GuardrailResult,
    GuardrailViolation,
    RiskLevel,
)


class CanaryLeakGuardrail(BaseGuardrail):
    """
    Checks model output to determine if designated canary tokens or protected system secrets
    were accidentally leaked by the LLM in violation of privacy and security policies.
    """

    DEFAULT_CANARIES = [
        "CANARY_TOKEN_SEC_9942",
        "SECRET_CONFIDENTIAL_DIRECTIVE",
        "CANARY_SYSTEM_PROMPT_DO_NOT_REVEAL",
    ]

    def __init__(
        self, name: str = "CanaryLeakChecker", canary_tokens: Optional[List[str]] = None
    ) -> None:
        super().__init__(name=name)
        self.canary_tokens = (
            list(canary_tokens) if canary_tokens else list(self.DEFAULT_CANARIES)
        )

    def add_canary(self, token: str) -> None:
        if token not in self.canary_tokens:
            self.canary_tokens.append(token)

    def evaluate(
        self, text: str, context: Optional[Dict[str, Any]] = None
    ) -> GuardrailResult:
        violations: List[GuardrailViolation] = []
        tokens_to_check = list(self.canary_tokens)

        # Allow passing dynamic canary in evaluation context
        if context and "canary" in context and context["canary"]:
            tokens_to_check.append(str(context["canary"]))

        for canary in tokens_to_check:
            if not canary:
                continue
            if canary.lower() in text.lower():
                violations.append(
                    GuardrailViolation(
                        rule_name="CanaryLeak",
                        description=f"Secret canary marker '{canary}' detected in model output.",
                        snippet=canary,
                        severity=RiskLevel.CRITICAL,
                    )
                )

        if violations:
            return GuardrailResult(
                guardrail_name=self.name,
                action=GuardrailAction.BLOCK,
                risk_level=RiskLevel.CRITICAL,
                confidence=None,
                violations=violations,
                metadata={"leaked_canary_count": len(violations)},
            )

        return GuardrailResult(
            guardrail_name=self.name,
            action=GuardrailAction.ALLOW,
            risk_level=RiskLevel.NONE,
            confidence=None,
            violations=[],
        )
