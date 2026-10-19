"""
JSON Security Report Generator.
Serializes evaluation results into structured JSON for CI/CD gates and security dashboards.
"""

from __future__ import annotations

import json
from evals.evaluator import SecurityEvaluationSummary
from reports.base import BaseReportGenerator


class JSONReportGenerator(BaseReportGenerator):
    """
    Renders machine-readable JSON evaluation payloads.
    """

    def __init__(self, indent: int = 2) -> None:
        self.indent = indent

    def generate(self, summary: SecurityEvaluationSummary) -> str:
        return summary.model_dump_json(indent=self.indent)
