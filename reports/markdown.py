"""Evidence-based demo report; no compliance or calibrated probability claims."""

from reports.base import BaseReportGenerator


def pct(value):
    return "N/A" if value is None else f"{value * 100:.1f}%"


def cell(value):
    return str(value or "—").replace("|", "\\|").replace("\n", " ")


class MarkdownReportGenerator(BaseReportGenerator):
    def generate(self, summary):
        m = summary.metrics
        lines = [
            "# AI Security Lab - Evaluation Report",
            "",
            "**DEMO — synthetic fixtures. No live provider calls or external actions.**",
            "",
            f"Target label: {summary.provider} / {summary.model}",
            f"Timestamp: {summary.timestamp}",
            f"Guardrails: {'enabled' if summary.guardrails_enabled else 'disabled'}",
            "",
            "## Metrics",
            "",
            "| Metric | Value |",
            "|---|---|",
            f"| Tests executed | {m.total_tests} |",
            f"| Scored adversarial probes | {m.scored_attacks} / {m.adversarial_tests} |",
            f"| System attack success rate | {pct(m.attack_success_rate)} |",
            f"| Robustness on scored attacks | {pct(None if m.robustness_score is None else m.robustness_score/100)} |",
            f"| Model ASR on observed, scored responses | {pct(m.model_attack_success_rate)} |",
            f"| Benign false-positive rate | {pct(m.false_positive_rate)} |",
            f"| Errors / inconclusive | {m.errors} / {m.inconclusive} |",
            f"| Estimated tokens (whitespace) | {m.estimated_tokens} |",
            f"| Local execution median / p95 | {m.median_latency_ms} / {m.p95_latency_ms} ms |",
            "",
            "Model ASR excludes input-blocked probes. Run a paired baseline for an unfiltered comparison.",
            "Synthetic outcomes demonstrate functionality; they do not estimate commercial model security.",
            "",
            "## Probe evidence",
            "",
            "| ID | Category | Verdict | Layer | Evidence |",
            "|---|---|---|---|---|",
        ]
        for r in summary.results:
            lines.append(
                f"| {cell(r.test_case.id)} | {cell(r.test_case.category.value)} | {cell(r.verdict or ('BLOCKED' if r.is_attack_prevented else 'EXPOSED'))} | {cell(r.defense_layer_triggered)} | {cell('; '.join(r.evidence) or r.notes)} |"
            )
        lines.extend(
            [
                "",
                "## Interpretation",
                "",
                "Inspect full JSON for prompts, raw synthetic responses, delivered output, tool proposals and per-turn traces.",
                "Errors and inconclusive results are excluded from ASR. Empty denominators are N/A.",
                "No regulatory compliance certification or calibrated confidence is implied.",
            ]
        )
        return "\n".join(lines)
