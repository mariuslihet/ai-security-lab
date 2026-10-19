"""
Quickstart Example for AI Security Lab.
Demonstrates running a security benchmark evaluation programmatically.
"""

import sys
from pathlib import Path

# Add repository root to Python path
sys.path.insert(0, str(Path(__file__).parent.parent.resolve()))

from core.factory import get_llm_client
from guardrails.engine import GuardrailEngine
from harness.loader import load_test_cases_from_file
from harness.runner import SecurityHarness
from evals.evaluator import SecurityEvaluator
from reports.console import ConsoleReporter
from reports.markdown import MarkdownReportGenerator


def main() -> None:
    print("Initializing AI Security Lab Quickstart...")

    # 1. Resolve Provider Client (supports openai, anthropic, azure, bedrock)
    # If API keys are not in environment, resilient diagnostic fallback operates automatically.
    client = get_llm_client(provider="openai", model="gpt-4o-mini")
    print(f"Provider: {client.provider_name} (Configured: {client.is_configured()})")

    # 2. Configure Defense Pipeline
    guardrails = GuardrailEngine()

    # 3. Load Benchmark Test Suite
    suite_file = Path("data/prompt_injections.yaml")
    test_cases = load_test_cases_from_file(suite_file)
    print(f"Loaded {len(test_cases)} test cases from {suite_file.name}")

    # 4. Execute Benchmark Harness
    harness = SecurityHarness(
        llm_client=client,
        guardrail_engine=guardrails,
        use_guardrails=True
    )
    results = harness.run_suite(test_cases)

    # 5. Evaluate Results & Compute Robustness
    evaluator = SecurityEvaluator()
    summary = evaluator.evaluate(
        results=results,
        provider=client.provider_name,
        model=client.model_name,
        guardrails_enabled=True
    )

    # 6. Print Console Dashboard
    reporter = ConsoleReporter()
    reporter.print_summary(summary)

    # 7. Export Markdown Report
    output_path = Path("reports_output/quickstart_report.md")
    md_generator = MarkdownReportGenerator()
    md_generator.save_to_file(summary, output_path)
    print(f"Report exported to: {output_path.resolve()}")


if __name__ == "__main__":
    main()
