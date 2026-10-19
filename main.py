"""
AI Security Lab - Command Line Interface.
Fast, modular CLI to run LLM red-teaming benchmarks, inspect guardrails, and generate audit reports.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path
from typing import Optional
import typer
from dotenv import load_dotenv

# Ensure UTF-8 console output on Windows
if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8")
        sys.stderr.reconfigure(encoding="utf-8")
    except Exception:
        pass

# Load local environment variables
load_dotenv()

from core.factory import get_llm_client, list_available_providers
from guardrails.engine import GuardrailEngine
from harness.loader import load_all_suites, load_test_cases_from_file
from harness.runner import SecurityHarness
from evals.evaluator import SecurityEvaluator
from reports.console import ConsoleReporter
from reports.markdown import MarkdownReportGenerator
from reports.json_reporter import JSONReportGenerator
from dashboard.app import start_dashboard

app = typer.Typer(
    name="ai-security-lab",
    help="Open-Source LLM Security Benchmark and Guardrail Evaluation Laboratory.",
    add_completion=False
)


@app.command()
def run_lab(
    provider: str = typer.Option("openai", "--provider", "-p", help="Target LLM provider: 'openai', 'anthropic', 'azure', 'bedrock'."),
    model: Optional[str] = typer.Option(None, "--model", "-m", help="Target model identifier (optional, uses provider default if omitted)."),
    suite: Optional[str] = typer.Option("all", "--suite", "-s", help="Specific test suite file/name or 'all'."),
    data_dir: Path = typer.Option(Path("data"), "--data-dir", "-d", help="Directory containing test suite YAML/JSON files."),
    with_guardrails: bool = typer.Option(True, "--with-guardrails/--no-guardrails", help="Enable or disable defensive guardrail pipelines."),
    report_format: str = typer.Option("all", "--report-format", "-r", help="Report format to export: 'markdown', 'json', 'all', 'none'."),
    output_dir: Path = typer.Option(Path("reports_output"), "--output-dir", "-o", help="Directory to save generated security reports.")
) -> None:
    """
    Executes automated security benchmark against the specified LLM provider.
    """
    typer.secho(f"\n[INIT] Starting AI Security Lab benchmark...", fg=typer.colors.CYAN, bold=True)
    typer.echo(f"   Provider:    {provider}")
    typer.echo(f"   Model:       {model or 'default'}")
    typer.echo(f"   Guardrails:  {'ENABLED' if with_guardrails else 'DISABLED'}")
    typer.echo(f"   Data Dir:    {data_dir}")

    # 1. Initialize Foundation Model Client
    try:
        client = get_llm_client(provider=provider, model=model)
    except Exception as err:
        typer.secho(f"[ERROR] Failed to initialize provider client: {err}", fg=typer.colors.RED, err=True)
        raise typer.Exit(code=1)

    # 2. Load Test Suites
    if suite == "all":
        all_suites = load_all_suites(data_dir)
        test_cases = [tc for cases in all_suites.values() for tc in cases]
    else:
        suite_path = data_dir / f"{suite}.yaml" if not suite.endswith((".yaml", ".json")) else data_dir / suite
        if not suite_path.is_file():
            typer.secho(f"[ERROR] Suite file not found: {suite_path}", fg=typer.colors.RED, err=True)
            raise typer.Exit(code=1)
        test_cases = load_test_cases_from_file(suite_path)

    if not test_cases:
        typer.secho("[WARN] No test cases found to execute.", fg=typer.colors.YELLOW)
        raise typer.Exit(code=0)

    typer.echo(f"   Test Cases:  {len(test_cases)} loaded.\n")

    # 3. Configure Guardrails and Harness
    guardrail_engine = GuardrailEngine() if with_guardrails else None
    harness = SecurityHarness(
        llm_client=client,
        guardrail_engine=guardrail_engine,
        use_guardrails=with_guardrails
    )

    # 4. Execute Benchmark
    typer.secho("[RUN] Running security test suite...", fg=typer.colors.BRIGHT_BLUE)
    results = harness.run_suite(test_cases)

    # 5. Evaluate Metrics and Assess Risk
    evaluator = SecurityEvaluator()
    summary = evaluator.evaluate(
        results=results,
        provider=client.provider_name,
        model=client.model_name,
        guardrails_enabled=with_guardrails
    )

    # 6. Render Console Telemetry
    console_reporter = ConsoleReporter()
    console_reporter.print_summary(summary)

    # 7. Generate Export Reports
    if report_format != "none":
        output_dir.mkdir(parents=True, exist_ok=True)
        timestamp_str = summary.timestamp.replace(":", "-").replace(".", "-")
        base_name = f"security_report_{provider}_{summary.model}_{timestamp_str}"

        if report_format in ("markdown", "all"):
            md_gen = MarkdownReportGenerator()
            md_file = output_dir / f"{base_name}.md"
            md_gen.save_to_file(summary, md_file)
            typer.secho(f"[REPORT] Markdown report saved: {md_file}", fg=typer.colors.GREEN)

        if report_format in ("json", "all"):
            json_gen = JSONReportGenerator()
            json_file = output_dir / f"{base_name}.json"
            json_gen.save_to_file(summary, json_file)
            typer.secho(f"[REPORT] JSON report saved:     {json_file}", fg=typer.colors.GREEN)


@app.command()
def check_prompt(
    prompt: str = typer.Argument(..., help="Prompt string to inspect with security guardrails.")
) -> None:
    """
    Ad-hoc security inspection of a single prompt using active guardrails.
    """
    typer.secho(f"\n[INSPECT] Inspecting prompt:\n'{prompt}'\n", fg=typer.colors.CYAN)
    engine = GuardrailEngine()
    result = engine.inspect_input(prompt)

    action_color = {
        "allow": typer.colors.GREEN,
        "flag": typer.colors.YELLOW,
        "block": typer.colors.RED
    }.get(result.action.value, typer.colors.WHITE)

    typer.secho(f"Action:     {result.action.value.upper()}", fg=action_color, bold=True)
    typer.echo(f"Risk Level: {result.risk_level.value.upper()}")

    if result.violations:
        typer.secho("\nViolations Detected:", fg=typer.colors.RED, bold=True)
        for v in result.violations:
            typer.echo(f" - [{v.severity.value.upper()}] {v.rule_name}: {v.description}")
            if v.snippet:
                typer.echo(f"   Snippet: '{v.snippet}'")
    else:
        typer.secho("[PASS] No security violations detected. Prompt allowed.", fg=typer.colors.GREEN)


@app.command()
def list_providers_cmd() -> None:
    """
    Inspects environment variables and reports status for foundation model providers.
    """
    typer.secho("\n[STATUS] Foundation Model Provider Status:", fg=typer.colors.CYAN, bold=True)
    status = list_available_providers()
    for name, info in status.items():
        is_cfg = info.get("configured", False)
        status_text = "CONFIGURED (Live API)" if is_cfg else "UNCONFIGURED (Diagnostic Fallback)"
        color = typer.colors.GREEN if is_cfg else typer.colors.YELLOW
        typer.secho(f" - {name.upper():12} : {status_text} (Default: {info.get('default_model')})", fg=color)
    typer.echo("")


@app.command()
def inspect_suites(
    data_dir: Path = typer.Option(Path("data"), "--data-dir", "-d", help="Directory containing test suites.")
) -> None:
    """
    Lists and summarizes all available security test suites.
    """
    typer.secho(f"\n[SUITES] Inspecting test suites in '{data_dir}':", fg=typer.colors.CYAN, bold=True)
    suites = load_all_suites(data_dir)
    if not suites:
        typer.echo("No test suites found.")
        return

    for suite_name, cases in suites.items():
        typer.secho(f"\nSuite: {suite_name} ({len(cases)} test cases)", fg=typer.colors.BRIGHT_MAGENTA, bold=True)
        for c in cases:
            typer.echo(f"   [{c.id}] {c.name} ({c.category.value}) - Severity: {c.severity.value}")


@app.command()
def dashboard(
    host: str = typer.Option("127.0.0.1", "--host", "-h", help="Host address to bind dashboard server."),
    port: int = typer.Option(8501, "--port", "-p", help="Port number for dashboard web server."),
    open_browser: bool = typer.Option(True, "--open-browser/--no-browser", help="Automatically launch default web browser.")
) -> None:
    """
    Launches the interactive AI Security Lab SecOps Control Plane.
    """
    typer.secho(f"\n[SERVER] Starting Control Plane on http://{host}:{port}...", fg=typer.colors.CYAN, bold=True)
    start_dashboard(host=host, port=port, open_browser=open_browser)


@app.command()
def serve(
    host: str = typer.Option("127.0.0.1", "--host", "-h", help="Host address to bind dashboard server."),
    port: int = typer.Option(8501, "--port", "-p", help="Port number for dashboard web server."),
    open_browser: bool = typer.Option(True, "--open-browser/--no-browser", help="Automatically launch default web browser.")
) -> None:
    """
    Starts the FastAPI + WebSocket SecOps Control Plane server (alias for dashboard).
    """
    dashboard(host=host, port=port, open_browser=open_browser)


if __name__ == "__main__":
    app()
