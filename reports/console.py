"""
Console Security Dashboard Printer.
Renders vibrant terminal dashboards with Rich tables and color-coded status pills.
"""

from __future__ import annotations

from evals.evaluator import SecurityEvaluationSummary

try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table
    from rich.text import Text
    HAS_RICH = True
except ImportError:
    HAS_RICH = False


class ConsoleReporter:
    """Prints evaluation summaries to stdout."""

    def __init__(self) -> None:
        if HAS_RICH:
            self.console = Console()
        else:
            self.console = None

    def print_summary(self, summary: SecurityEvaluationSummary) -> None:
        if HAS_RICH and self.console:
            self._print_rich(summary)
        else:
            self._print_plain(summary)

    def _print_rich(self, summary: SecurityEvaluationSummary) -> None:
        m = summary.metrics
        ra = summary.risk_assessment

        risk_color = {
            "critical": "bold red",
            "high": "red",
            "medium": "yellow",
            "low": "green",
            "none": "bold green"
        }.get(ra.overall_risk.value, "white")

        # Top Banner Panel
        header = Text()
        header.append(f"AI Security Lab Audit\n", style="bold cyan")
        header.append(f"Target: {summary.provider} / {summary.model}  |  ")
        header.append(f"Guardrails: {'ACTIVE' if summary.guardrails_enabled else 'DISABLED'}  |  ")
        header.append(f"Risk: ", style="bold")
        header.append(f"{ra.overall_risk.value.upper()}\n", style=risk_color)
        header.append(f"Robustness Score: {m.robustness_score}/100  |  ASR: {m.attack_success_rate * 100:.1f}%\n")
        self.console.print(Panel(header, border_style="cyan"))

        # Category Table
        cat_table = Table(title="OWASP Category Breakdown", border_style="dim")
        cat_table.add_column("Category", style="cyan")
        cat_table.add_column("Probes", justify="right")
        cat_table.add_column("Bypassed", justify="right")
        cat_table.add_column("ASR (%)", justify="right")
        cat_table.add_column("Risk Level", justify="center")

        for cat_name, cat in ra.category_breakdown.items():
            cat_table.add_row(
                cat_name,
                str(cat.total_probes),
                str(cat.bypassed_probes),
                f"{cat.attack_success_rate * 100:.1f}%",
                f"[{risk_color}]{cat.risk_level.value.upper()}[/{risk_color}]"
            )
        self.console.print(cat_table)

        # Failures Table
        failures = [r for r in summary.results if r.attack_succeeded]
        if failures:
            fail_table = Table(title="[BYPASS] Detected Defense Bypasses", border_style="red")
            fail_table.add_column("ID", style="bold yellow")
            fail_table.add_column("Category", style="cyan")
            fail_table.add_column("Severity", style="red")
            fail_table.add_column("Notes", style="white")

            for f in failures:
                fail_table.add_row(
                    f.test_case.id,
                    f.test_case.category.value,
                    f.test_case.severity.value.upper(),
                    f.notes or "Attack payload succeeded."
                )
            self.console.print(fail_table)

    def _print_plain(self, summary: SecurityEvaluationSummary) -> None:
        m = summary.metrics
        ra = summary.risk_assessment
        print("\n" + "=" * 60)
        print("          AI SECURITY LAB - EVALUATION REPORT")
        print("=" * 60)
        print(f"Target:      {summary.provider} ({summary.model})")
        print(f"Guardrails:  {'Active' if summary.guardrails_enabled else 'Disabled'}")
        print(f"Risk Level:  {ra.overall_risk.value.upper()}")
        print(f"Robustness:  {m.robustness_score}/100")
        print(f"ASR:         {m.attack_success_rate * 100:.2f}%")
        print("-" * 60)
        print("Category Breakdown:")
        for cat_name, cat in ra.category_breakdown.items():
            print(f" - {cat_name:20}: Probes={cat.total_probes:2} | Bypassed={cat.bypassed_probes:2} | Risk={cat.risk_level.value}")
        print("=" * 60 + "\n")
