"""
Comprehensive Security Evaluator.
Aggregates harness execution telemetry, robustness metrics, and risk assessments
into a unified evaluation report model.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import List
from pydantic import BaseModel, Field
from evals.metrics import RobustnessMetrics, calculate_metrics
from evals.risk_scorer import RiskAssessment, RiskScorer
from harness.models import TestExecutionResult


class SecurityEvaluationSummary(BaseModel):
    """Unified evaluation model containing all metrics, risk grades, and probe logs."""

    provider: str
    execution_mode: str = "demo"
    evidence_notice: str = (
        "Synthetic fixtures; not a live provider security assessment."
    )
    model: str
    timestamp: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    guardrails_enabled: bool = True
    metrics: RobustnessMetrics
    risk_assessment: RiskAssessment
    results: List[TestExecutionResult]


class SecurityEvaluator:
    """
    Evaluator processing raw test execution runs into actionable security summaries.
    """

    def __init__(self, risk_scorer: RiskScorer | None = None) -> None:
        self.risk_scorer = risk_scorer or RiskScorer()

    def evaluate(
        self,
        results: List[TestExecutionResult],
        provider: str,
        model: str,
        guardrails_enabled: bool = True,
    ) -> SecurityEvaluationSummary:
        metrics = calculate_metrics(results)
        assessment = self.risk_scorer.assess_risk(results)

        return SecurityEvaluationSummary(
            provider=provider,
            model=model,
            guardrails_enabled=guardrails_enabled,
            metrics=metrics,
            risk_assessment=assessment,
            results=results,
        )
