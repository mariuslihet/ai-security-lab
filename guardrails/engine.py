"""
Central Guardrail Engine and Pipeline Coordinator.
Orchestrates input and output guardrails into a composable defense-in-depth pipeline.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional
from guardrails.base import BaseGuardrail, GuardrailAction, GuardrailResult, GuardrailViolation, RiskLevel
from guardrails.input.prompt_injection import PromptInjectionGuardrail
from guardrails.input.pii_detector import PIIDetectorGuardrail
from guardrails.output.canary_checker import CanaryLeakGuardrail
from guardrails.output.content_safety import ContentSafetyGuardrail


class GuardrailEngine:
    """
    Manages and runs defensive guardrail layers across input prompts and model outputs.
    """

    def __init__(
        self,
        input_guardrails: Optional[List[BaseGuardrail]] = None,
        output_guardrails: Optional[List[BaseGuardrail]] = None,
        block_on_input_violation: bool = True,
        block_on_output_violation: bool = True
    ) -> None:
        self.block_on_input_violation = block_on_input_violation
        self.block_on_output_violation = block_on_output_violation

        # Default configured guardrail suite
        self.input_guardrails: List[BaseGuardrail] = (
            input_guardrails if input_guardrails is not None else [
                PromptInjectionGuardrail(),
                PIIDetectorGuardrail()
            ]
        )
        self.output_guardrails: List[BaseGuardrail] = (
            output_guardrails if output_guardrails is not None else [
                CanaryLeakGuardrail(),
                ContentSafetyGuardrail(),
                PIIDetectorGuardrail(name="OutputPIIDetector")
            ]
        )

    def add_input_guardrail(self, guardrail: BaseGuardrail) -> None:
        self.input_guardrails.append(guardrail)

    def add_output_guardrail(self, guardrail: BaseGuardrail) -> None:
        self.output_guardrails.append(guardrail)

    def _aggregate_results(
        self,
        pipeline_name: str,
        results: List[GuardrailResult],
        enforce_block: bool
    ) -> GuardrailResult:
        """Combines multiple guardrail findings into a single consolidated verdict."""
        all_violations: List[GuardrailViolation] = []
        highest_risk = RiskLevel.NONE
        blocked = False
        flagged = False

        order = [RiskLevel.NONE, RiskLevel.LOW, RiskLevel.MEDIUM, RiskLevel.HIGH, RiskLevel.CRITICAL]

        for res in results:
            all_violations.extend(res.violations)
            if order.index(res.risk_level) > order.index(highest_risk):
                highest_risk = res.risk_level
            if res.action == GuardrailAction.BLOCK:
                blocked = True
            elif res.action == GuardrailAction.FLAG:
                flagged = True

        action = GuardrailAction.ALLOW
        if blocked and enforce_block:
            action = GuardrailAction.BLOCK
        elif flagged or (blocked and not enforce_block):
            action = GuardrailAction.FLAG

        return GuardrailResult(
            guardrail_name=pipeline_name,
            action=action,
            risk_level=highest_risk,
            confidence=1.0,
            violations=all_violations,
            metadata={
                "evaluated_guardrails": [r.guardrail_name for r in results],
                "blocked_guardrails": [r.guardrail_name for r in results if r.action == GuardrailAction.BLOCK]
            }
        )

    def inspect_input(self, prompt: str, context: Optional[Dict[str, Any]] = None) -> GuardrailResult:
        """Runs prompt text through all enabled input guardrails."""
        results = [
            g.evaluate(prompt, context)
            for g in self.input_guardrails
            if g.enabled
        ]
        return self._aggregate_results("InputPipeline", results, self.block_on_input_violation)

    def inspect_output(self, completion: str, context: Optional[Dict[str, Any]] = None) -> GuardrailResult:
        """Runs generated completion through all enabled output guardrails."""
        results = [
            g.evaluate(completion, context)
            for g in self.output_guardrails
            if g.enabled
        ]
        return self._aggregate_results("OutputPipeline", results, self.block_on_output_violation)
