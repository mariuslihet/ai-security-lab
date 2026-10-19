"""
Base Report Generator Interface.
"""

from __future__ import annotations

import abc
from pathlib import Path
from typing import Union
from evals.evaluator import SecurityEvaluationSummary


class BaseReportGenerator(abc.ABC):
    """Abstract contract for security evaluation report generation."""

    @abc.abstractmethod
    def generate(self, summary: SecurityEvaluationSummary) -> str:
        """Renders summary data into formatted string representation."""
        raise NotImplementedError

    def save_to_file(self, summary: SecurityEvaluationSummary, output_path: Union[str, Path]) -> Path:
        """Renders and saves report to file."""
        content = self.generate(summary)
        path = Path(output_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
        return path
