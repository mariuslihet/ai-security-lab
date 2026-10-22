"""Offline demo CLI; uses the same persisted run service as the dashboard."""

from pathlib import Path
import json
import typer
from core.demo_client import PROVIDERS, PROFILES
from guardrails.engine import GuardrailEngine
from harness.service import RunRequest, RunService, RunStore, ROOT
from harness.loader import load_all_suites
from evals.evaluator import SecurityEvaluationSummary
from reports.markdown import MarkdownReportGenerator

app = typer.Typer(
    name="ai-security-lab",
    help="Offline LLM security evaluation demo. No API keys or external actions.",
    add_completion=False,
)


@app.command()
def run_lab(
    scenario: str = typer.Option(
        "suite", "--scenario", help="suite, support, documents or agent"
    ),
    policy_json: str = typer.Option(
        "{}", "--policy-json", help="Guardrail policy JSON overrides"
    ),
    named_policies_json: str = typer.Option(
        "{}",
        "--named-policies-json",
        help="Up to three named policy JSON objects; adds a shared baseline",
    ),
    provider: str = typer.Option("openai", "--provider", "-p"),
    model: str = typer.Option(
        "balanced",
        "--model",
        "-m",
        help="Demo profile: balanced, resilient, permissive.",
    ),
    suite: str = typer.Option("all", "--suite", "-s"),
    data_dir: Path = typer.Option(ROOT / "data", "--data-dir", "-d"),
    with_guardrails: bool = typer.Option(True, "--with-guardrails/--no-guardrails"),
    compare: bool = typer.Option(
        False, "--compare", help="Run paired baseline and defended arms."
    ),
    seed: int = typer.Option(42, "--seed"),
    repetitions: int = typer.Option(1, "--repetitions"),
    max_tests: int = typer.Option(500, "--max-tests"),
    max_tokens: int = typer.Option(100000, "--max-tokens"),
    max_seconds: int = typer.Option(60, "--max-seconds"),
    report_format: str = typer.Option("all", "--report-format", "-r"),
    output_dir: Path = typer.Option(
        Path.cwd() / "reports_output", "--output-dir", "-o"
    ),
):
    """Execute synthetic fixtures with explicit objective evidence."""
    if report_format not in ("all", "markdown", "json", "none"):
        raise typer.BadParameter("Report format must be all, markdown, json or none")
    try:
        request = RunRequest(
            scenario=scenario,
            policy=json.loads(policy_json),
            named_policies=json.loads(named_policies_json),
            provider=provider,
            profile=model,
            suite=Path(suite).stem if suite != "all" else suite,
            guardrails=with_guardrails,
            compare=compare,
            seed=seed,
            repetitions=repetitions,
            max_tests=max_tests,
            max_tokens=max_tokens,
            max_seconds=max_seconds,
        )
        service = RunService(RunStore(output_dir / "demo_runs.sqlite3"), data_dir)
        try:
            identifier = service.start(request, background=False)
            run = service.store.get(identifier)
        finally:
            service.close()
    except (ValueError, RuntimeError) as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(1)
    typer.echo(
        f"DEMO ONLY · {identifier} · {run['status']} · {run['completed']}/{run['planned']} tests"
    )
    for name, arm in run["arms"].items():
        m = arm["metrics"]
        asr = (
            "N/A"
            if m["attack_success_rate"] is None
            else format(m["attack_success_rate"] * 100, ".1f") + "%"
        )
        typer.echo(
            f"{name}: ASR {asr}, {m['errors']} errors, {m['inconclusive']} inconclusive, {m['false_positives']} benign false positives"
        )
    if report_format in ("all", "json"):
        (output_dir / f"demo-{identifier}.json").write_text(
            json.dumps(run, indent=2, ensure_ascii=False), encoding="utf-8"
        )
    if report_format in ("all", "markdown"):
        text = f"# Demo run {identifier}\n\nStatus: {run['status']}\nDataset SHA256: {run['dataset_sha256']}\n"
        for name, arm in run["arms"].items():
            text += f"\n## {name}\n\n" + MarkdownReportGenerator().generate(
                SecurityEvaluationSummary.model_validate(arm)
            )
        (output_dir / f"demo-{identifier}.md").write_text(text, encoding="utf-8")
    if run["status"] in ("error", "limit_reached", "cancelled", "interrupted"):
        raise typer.Exit(1)


@app.command()
def check_prompt(prompt: str = typer.Argument(...)):
    """Inspect text using the local heuristic guardrails."""
    typer.echo(GuardrailEngine().inspect_input(prompt).model_dump_json(indent=2))


@app.command()
def list_providers_cmd():
    """List simulated labels, without reading credentials or calling SDKs."""
    for identifier, name in PROVIDERS.items():
        typer.echo(
            f"{identifier}: {name} · SIMULATED · profiles: {', '.join(PROFILES)}"
        )


@app.command()
def inspect_suites(data_dir: Path = typer.Option(ROOT / "data", "--data-dir", "-d")):
    for name, cases in load_all_suites(data_dir).items():
        typer.echo(
            f"{name}: {len(cases)} synthetic fixtures ({sum(not c.is_adversarial for c in cases)} benign)"
        )


@app.command()
def dashboard(
    host: str = typer.Option("127.0.0.1", "--host", "-h"),
    port: int = typer.Option(8501, "--port", "-p"),
    open_browser: bool = typer.Option(True, "--open-browser/--no-browser"),
):
    """Open the local offline demo dashboard."""
    from dashboard.app import start_dashboard

    typer.echo(f"DEMO dashboard: http://{host}:{port}")
    start_dashboard(host, port, open_browser)


@app.command()
def serve(
    host: str = typer.Option("127.0.0.1", "--host"),
    port: int = typer.Option(8501, "--port"),
    open_browser: bool = typer.Option(True, "--open-browser/--no-browser"),
):
    from dashboard.app import start_dashboard

    start_dashboard(host, port, open_browser)


if __name__ == "__main__":
    app()
