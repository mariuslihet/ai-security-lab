"""
Markdown Security Audit Report Generator.
Formats evaluation telemetry into GitHub-flavored Markdown for repository commits and PRs.
"""

from __future__ import annotations

from evals.evaluator import SecurityEvaluationSummary
from reports.base import BaseReportGenerator


class MarkdownReportGenerator(BaseReportGenerator):
    """
    Renders structured, publication-grade Markdown security audit reports.
    """

    def generate(self, summary: SecurityEvaluationSummary) -> str:
        m = summary.metrics
        ra = summary.risk_assessment

        risk_label = {
            "critical": "[CRITICAL]",
            "high": "[HIGH]",
            "medium": "[MEDIUM]",
            "low": "[LOW]",
            "none": "[NONE]"
        }.get(ra.overall_risk.value, ra.overall_risk.value.upper())

        lines = [
            "# AI Security Lab - Evaluation Report",
            "",
            f"- **Target Provider:** `{summary.provider}`",
            f"- **Target Model:** `{summary.model}`",
            f"- **Evaluation Timestamp (UTC):** `{summary.timestamp}`",
            f"- **Guardrails Layer Active:** `{'Yes' if summary.guardrails_enabled else 'No (Direct Probe)'}`",
            f"- **Overall Risk Posture:** **{risk_label}**",
            f"- **Systemic Robustness Score:** `{m.robustness_score}/100`",
            "",
            "---",
            "",
            "## 1. Executive Summary & KPIs",
            "",
            "| Metric | Value | Description |",
            "| :--- | :--- | :--- |",
            f"| **Total Security Probes** | `{m.total_tests}` | Total adversarial test cases executed |",
            f"| **Attacks Prevented** | `{m.prevented_attacks}` | Probes blocked or safely refused |",
            f"| **Successful Bypasses** | `{m.successful_attacks}` | Probes that evaded defenses |",
            f"| **Attack Success Rate (ASR)** | `{m.attack_success_rate * 100:.2f}%` | Lower is better (Target: < 5%) |",
            f"| **Robustness Score** | `{m.robustness_score}%` | Higher is better (Target: > 95%) |",
            f"| **Average Latency** | `{m.avg_latency_ms:.1f} ms` | Average probe execution duration |",
            "",
            "### Defense-in-Depth Attribution",
            "",
            "| Defense Layer | Blocks Triggered | Percentage of Total Probes |",
            "| :--- | :--- | :--- |",
            f"| **Perimeter Input Guardrail** | `{m.input_guardrail_blocks}` | `{m.input_guardrail_block_rate * 100:.1f}%` |",
            f"| **Model Safe Refusal** | `{m.model_refusals}` | `{m.model_refusal_rate * 100:.1f}%` |",
            f"| **Output Inspection Guardrail** | `{m.output_guardrail_blocks}` | `{m.output_guardrail_block_rate * 100:.1f}%` |",
            "",
            "---",
            "",
            "## 2. OWASP LLM Category Breakdown",
            "",
            "| Security Category | Probes | Bypassed | ASR (%) | Category Risk |",
            "| :--- | :---: | :---: | :---: | :--- |",
        ]

        for cat_name, cat_score in ra.category_breakdown.items():
            lines.append(
                f"| `{cat_name}` | {cat_score.total_probes} | {cat_score.bypassed_probes} | "
                f"{cat_score.attack_success_rate * 100:.1f}% | `[{cat_score.risk_level.value.upper()}]` |"
            )

        lines.extend([
            "",
            "---",
            "",
            "## 3. Critical Findings & Vulnerabilities",
            ""
        ])

        if ra.critical_findings:
            for finding in ra.critical_findings:
                lines.append(f"- [FINDING] {finding}")
        else:
            lines.append("- [OK] No critical bypasses or severe unmitigated vulnerabilities detected.")

        lines.extend([
            "",
            "## 4. Recommended Remediations",
            ""
        ])

        for rec in ra.remediation_recommendations:
            lines.append(f"1. {rec}")

        lines.extend([
            "",
            "---",
            "",
            "## 5. Detailed Probe Execution Log",
            "",
            "| Probe ID | Category | Severity | Result | Defense Triggered | Latency |",
            "| :--- | :--- | :--- | :---: | :--- | :---: |",
        ])

        for r in summary.results:
            status_badge = "[PREVENTED]" if r.is_attack_prevented else "[BYPASS]"
            layer_name = r.defense_layer_triggered or "none"
            lines.append(
                f"| `{r.test_case.id}` | `{r.test_case.category.value}` | `{r.test_case.severity.value}` | "
                f"{status_badge} | `{layer_name}` | `{r.execution_time_ms:.1f}ms` |"
            )

        lines.append("")
        return "\n".join(lines)
