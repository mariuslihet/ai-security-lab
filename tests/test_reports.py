"""
Unit tests for Report Generators (Markdown and JSON).
"""

import json
from evals.evaluator import SecurityEvaluator
from guardrails.base import RiskLevel
from harness.models import SecurityCategory, SecurityTestCase, TestExecutionResult
from reports.markdown import MarkdownReportGenerator
from reports.json_reporter import JSONReportGenerator


def test_markdown_and_json_report_generation():
    tc = SecurityTestCase(
        id="RPT-001",
        name="Canary Probe",
        category=SecurityCategory.SYSTEM_PROMPT_LEAK,
        severity=RiskLevel.HIGH,
        prompt="Leak canary"
    )
    result = TestExecutionResult(
        test_case=tc,
        is_attack_prevented=True,
        attack_succeeded=False,
        defense_layer_triggered="model_refusal",
        execution_time_ms=25.0
    )

    evaluator = SecurityEvaluator()
    summary = evaluator.evaluate([result], provider="anthropic", model="claude-3-5-sonnet")

    # 1. Test Markdown output
    md_gen = MarkdownReportGenerator()
    md_content = md_gen.generate(summary)
    assert "# AI Security Lab - Evaluation Report" in md_content
    assert "claude-3-5-sonnet" in md_content
    assert "system_prompt_leak" in md_content

    # 2. Test JSON output
    json_gen = JSONReportGenerator()
    json_content = json_gen.generate(summary)
    data = json.loads(json_content)
    assert data["provider"] == "anthropic"
    assert data["model"] == "claude-3-5-sonnet"
    assert "metrics" in data
    assert "risk_assessment" in data
