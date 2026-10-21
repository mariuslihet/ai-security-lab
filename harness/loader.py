"""
Security Test Suite Loader.
Loads, validates, and normalizes test payloads from YAML and JSON files.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Union
import yaml
from harness.models import SecurityTestCase


def load_test_cases_from_file(file_path: Union[str, Path]) -> List[SecurityTestCase]:
    """
    Loads and validates test cases from a specified YAML or JSON file.

    Args:
        file_path: Path to the test definition file.

    Returns:
        List of validated SecurityTestCase models.
    """
    path = Path(file_path)
    if not path.is_file():
        raise FileNotFoundError(f"Test case file not found: {file_path}")

    with open(path, "r", encoding="utf-8") as f:
        if path.suffix.lower() in (".yaml", ".yml"):
            raw_data = yaml.safe_load(f)
        elif path.suffix.lower() == ".json":
            raw_data = json.load(f)
        else:
            raise ValueError(
                f"Unsupported file extension: {path.suffix}. Expected .yaml, .yml or .json"
            )

    if not raw_data:
        return []

    # Format can be either a top-level list or a dictionary with 'tests' or 'test_cases' key
    if isinstance(raw_data, dict):
        if "tests" in raw_data:
            raw_items = raw_data["tests"]
        elif "test_cases" in raw_data:
            raw_items = raw_data["test_cases"]
        else:
            raise ValueError(
                f"Invalid test suite structure in {file_path}. Expected list or dict with 'tests' or 'test_cases' key."
            )
    elif isinstance(raw_data, list):
        raw_items = raw_data
    else:
        raise ValueError(
            f"Invalid test suite structure in {file_path}. Expected list or dict with 'tests' or 'test_cases' key."
        )

    test_cases: List[SecurityTestCase] = []
    for item in raw_items:
        if isinstance(item, dict) and "expected_behavior" in item:
            eb = str(item["expected_behavior"]).lower()
            if "block" in eb:
                item["expected_behavior"] = "block"
            elif "refuse" in eb:
                item["expected_behavior"] = "refuse"
            elif "mask" in eb:
                item["expected_behavior"] = "mask"
            elif eb == "allow":
                item["expected_behavior"] = "allow"
            else:
                raise ValueError(f"Unknown expected behavior: {eb}")
        test_case = SecurityTestCase.model_validate(item)
        test_cases.append(test_case)

    return test_cases


def load_all_suites(data_dir: Union[str, Path]) -> Dict[str, List[SecurityTestCase]]:
    """
    Recursively scans the data directory and loads all test cases grouped by suite name.

    Args:
        data_dir: Directory containing test suite files.

    Returns:
        Dictionary mapping suite name to list of SecurityTestCase models.
    """
    dir_path = Path(data_dir)
    if not dir_path.is_dir():
        return {}

    suites: Dict[str, List[SecurityTestCase]] = {}
    for ext in ("*.yaml", "*.yml", "*.json"):
        for file in sorted(dir_path.rglob(ext)):
            suite_name = file.stem
            cases = load_test_cases_from_file(file)
            if suite_name in suites:
                raise ValueError(f"Duplicate suite name: {suite_name}")
            if cases:
                suites[suite_name] = cases

    ids = [case.id for cases in suites.values() for case in cases]
    if len(ids) != len(set(ids)):
        raise ValueError("Duplicate test IDs across datasets")

    return suites
