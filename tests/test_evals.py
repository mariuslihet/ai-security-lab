"""
Unit tests for Metrics, Risk Scorer, and Security Evaluator.
"""

from evals.metrics import calculate_metrics
from evals.risk_scorer import RiskScorer
from evals.evaluator import SecurityEvaluator
from guardrails.base import RiskLevel
from harness.models import SecurityCategory, SecurityTestCase, TestExecutionResult


def _create_mock_result(test_id: str, prevented: bool, severity: RiskLevel = RiskLevel.HIGH) -> TestExecutionResult:
    tc = SecurityTestCase(
        id=test_id,
        name=f"Test {test_id}",
        category=SecurityCategory.PROMPT_INJECTION,
        severity=severity,
        prompt="Test probe"
    )
    return TestExecutionResult(
        test_case=tc,
        is_attack_prevented=prevented,
        attack_succeeded=not prevented,
        defense_layer_triggered="input_guardrail" if prevented else None,
        execution_time_ms=15.0
    )


def test_metrics_calculation_100_percent_defense():
    results = [
        _create_mock_result("T1", prevented=True),
        _create_mock_result("T2", prevented=True),
    ]
    metrics = calculate_metrics(results)
    assert metrics.total_tests == 2
    assert metrics.prevented_attacks == 2
    assert metrics.successful_attacks == 0
    assert metrics.attack_success_rate == 0.0
    assert metrics.robustness_score == 100.0


def test_metrics_calculation_with_failures():
    results = [
        _create_mock_result("T1", prevented=True),
        _create_mock_result("T2", prevented=False),
    ]
    metrics = calculate_metrics(results)
    assert metrics.total_tests == 2
    assert metrics.prevented_attacks == 1
    assert metrics.successful_attacks == 1
    assert metrics.attack_success_rate == 0.5
    assert metrics.robustness_score == 50.0


def test_risk_scorer_identifies_critical_exposure():
    scorer = RiskScorer()
    results = [
        _create_mock_result("T1", prevented=False, severity=RiskLevel.CRITICAL),
        _create_mock_result("T2", prevented=False, severity=RiskLevel.CRITICAL),
    ]
    assessment = scorer.assess_risk(results)
    assert assessment.overall_risk == RiskLevel.CRITICAL
    assert len(assessment.critical_findings) > 0
    assert len(assessment.remediation_recommendations) > 0


def test_security_evaluator_produces_complete_summary():
    evaluator = SecurityEvaluator()
    results = [_create_mock_result("T1", prevented=True)]
    summary = evaluator.evaluate(results, provider="openai", model="gpt-4o")
    assert summary.provider == "openai"
    assert summary.model == "gpt-4o"
    assert summary.metrics.robustness_score == 100.0
    assert summary.risk_assessment.overall_risk == RiskLevel.NONE
