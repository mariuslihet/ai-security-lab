from copy import deepcopy
import pytest
from core.demo_client import DemoLLMClient
from harness.runner import SecurityHarness
from harness.scenarios import scenario_cases
from evals.objectives import evaluate_actions
from harness.models import SecurityTestCase


@pytest.mark.parametrize(
    "mutation",
    [
        "missing",
        "wrong_resource",
        "wrong_tool",
        "unapproved",
        "wrong_owner",
        "unchanged",
        "extra",
        "external",
    ],
)
def test_success_text_cannot_replace_action_evidence(mutation):
    c = scenario_cases("support")[0]
    r = SecurityHarness(DemoLLMClient(model_name="permissive")).run_test(c)
    assert r.verdict == "ALLOWED"
    assert "refunded false → true" in r.delivered_content
    events = deepcopy(r.sandbox_events)
    if mutation == "missing":
        events = []
    elif mutation == "wrong_resource":
        events[0]["arguments"]["order_id"] = "ORDER-B"
    elif mutation == "wrong_tool":
        events[0]["tool"] = "read_order"
    elif mutation == "unapproved":
        c.sandbox_approval = False
    elif mutation == "wrong_owner":
        events[0]["after"]["orders"]["ORDER-A"]["owner"] = "other"
    elif mutation == "unchanged":
        events[0]["after"] = deepcopy(events[0]["before"])
    elif mutation == "extra":
        events.append(deepcopy(events[0]))
    elif mutation == "external":
        events[0]["external_action"] = True
    assert evaluate_actions(c, events)[0] is None


def test_refund_claim_without_tool_execution_is_unknown():
    c = scenario_cases("support")[0]
    c.demo_tools = []
    c.demo_safe_response = "Refund completed successfully."
    c.safe_contains = ["Refund completed successfully."]
    r = SecurityHarness(DemoLLMClient(model_name="permissive")).run_test(c)
    assert r.verdict == "INCONCLUSIVE" and not r.attack_succeeded


@pytest.mark.parametrize(
    "values",
    [
        {"success_contains": [""]},
        {"safe_contains": [" "]},
        {"canary": " "},
        {"expected_actions": [{"tool": "shell"}]},
    ],
)
def test_invalid_grading_contracts_are_rejected(values):
    with pytest.raises(ValueError):
        SecurityTestCase(
            id="X", name="Invalid", category="benign", prompt="Demo", **values
        )
