from harness.sandbox import simulate_tools
from harness.scenarios import scenario_cases
from harness.runner import SecurityHarness
from core.demo_client import DemoLLMClient
import pytest


@pytest.mark.parametrize(
    "principal,approval,order,allowed",
    [
        ("customer-alice", True, "ORDER-A", True),
        ("customer-alice", False, "ORDER-A", False),
        ("customer-alice", True, "ORDER-B", False),
        ("customer-bob", True, "ORDER-B", True),
        ("customer-alice", True, "missing", False),
    ],
)
def test_refund_authorization_and_state(principal, approval, order, allowed):
    action = simulate_tools(
        [{"name": "issue_refund", "arguments": {"order_id": order}}],
        principal,
        approval,
        True,
    )[0]
    assert action["executed_in_memory"] is allowed
    assert action["external_action"] is False
    if not allowed:
        assert action["before"] == action["after"]
    else:
        assert action["after"]["orders"][order]["refunded"]


def test_baseline_effects_are_isolated_and_unknown_tools_never_execute():
    call = {"name": "issue_refund", "arguments": {"order_id": "ORDER-A"}}
    action = simulate_tools([call], "customer-alice", False, False)[0]
    assert not action["authorized"] and action["after"]["orders"]["ORDER-A"]["refunded"]
    assert not simulate_tools([call], "customer-alice", False, True)[0]["before"][
        "orders"
    ]["ORDER-A"]["refunded"]
    assert not simulate_tools(
        [{"name": "shell", "arguments": {}}], "customer-alice", True, False
    )[0]["executed_in_memory"]


@pytest.mark.parametrize("profile", ["permissive", "resilient", "balanced"])
def test_support_outcomes_include_business_evidence(profile):
    h = SecurityHarness(DemoLLMClient(model_name=profile))
    results = h.run_suite(scenario_cases("support"))
    assert results[0].verdict == "ALLOWED"
    assert results[0].sandbox_events[0]["after"]["orders"]["ORDER-A"]["refunded"]
    assert all(r.verdict in ("BLOCKED", "REFUSED", "SAFE") for r in results[1:])


def test_verify_endpoint_preserves_original_and_includes_benign(tmp_path):
    from dashboard.app import create_app
    from fastapi.testclient import TestClient
    import time

    with TestClient(create_app(tmp_path / "verify.db")) as client:

        def wait(key):
            for _ in range(300):
                r = client.get("/api/runs/" + key).json()
                if r["status"] not in ("running", "queued"):
                    return r
                time.sleep(0.01)
            raise AssertionError("timeout")

        source = wait(
            client.post(
                "/api/runs",
                json={
                    "scenario": "support",
                    "profile": "permissive",
                    "guardrails": False,
                },
            ).json()["id"]
        )
        new = wait(client.post("/api/runs/" + source["id"] + "/verify").json()["id"])
        assert source["fixture_snapshot"] == new["fixture_snapshot"]
        assert new["arms"]["defended"]["metrics"]["attack_success_rate"] == 0
        assert new["arms"]["defended"]["metrics"]["false_positives"] == 0
        assert client.get("/api/runs/" + source["id"]).json() == source
        assert new["source_run"] == source["id"]
        assert new["config"]["guardrails"]
        assert client.post("/api/runs/missing/verify").status_code == 404
