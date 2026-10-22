import pytest
from harness.service import RunService, RunStore, RunRequest, GuardrailPolicy


@pytest.mark.parametrize("scenario", ["support", "documents", "agent"])
def test_application_contracts_and_policy_regressions(tmp_path, scenario):
    service = RunService(RunStore(tmp_path / "runs.sqlite3"))
    try:

        def run(policy):
            key = service.start(
                RunRequest(
                    scenario=scenario, profile="permissive", compare=True, policy=policy
                ),
                background=False,
            )
            return service.store.get(key)

        defended = run(GuardrailPolicy())
        assert defended["completed"] == 8
        assert defended["status"] == "completed"
        assert all(
            r["expectation_met"]
            for a in defended["arms"].values()
            for r in a["results"]
        )
        opened = run(
            GuardrailPolicy(injection=False, pii=False, canary=False, content=False)
        )
        results = opened["arms"]["defended"]["results"]
        assert opened["status"] == "needs_review"
        assert sum(r["expectation_met"] is False for r in results) == (
            1 if scenario == "support" else 2
        )
        assert results[-1]["verdict"] == "BLOCKED"  # tool boundary cannot be disabled
        assert [r["verdict"] for r in defended["arms"]["baseline"]["results"]] == [
            r["verdict"] for r in opened["arms"]["baseline"]["results"]
        ]
    finally:
        service.close()


def test_observe_only_and_strict_configuration(tmp_path):
    from pydantic import ValidationError

    with pytest.raises(ValidationError):
        RunRequest(scenario="unknown")
    with pytest.raises(ValidationError):
        GuardrailPolicy(unknown=True)
    service = RunService(RunStore(tmp_path / "runs.sqlite3"))
    try:
        key = service.start(
            RunRequest(
                scenario="support",
                profile="permissive",
                policy=GuardrailPolicy(enforce_input=False, enforce_output=False),
            ),
            background=False,
        )
        results = service.store.get(key)["arms"]["defended"]["results"]
        assert results[1]["verdict"] == "EXPOSED"
        assert results[1]["input_guardrail_result"]["violations"]
        assert results[-1]["verdict"] == "BLOCKED"
    finally:
        service.close()


def test_dashboard_scenario_api_replay_and_reports(tmp_path):
    from fastapi.testclient import TestClient
    from dashboard.app import create_app
    import time

    app = create_app(tmp_path / "web.sqlite3")
    with TestClient(app) as client:
        assert set(client.get("/api/status").json()["scenarios"]) == {
            "support",
            "documents",
            "agent",
        }
        home = client.get("/").text
        assert 'id="scenario"' in home and 'id="policy-canary"' in home
        assert client.post("/api/runs", json={"scenario": "invalid"}).status_code == 422
        payload = {
            "scenario": "support",
            "profile": "permissive",
            "compare": True,
            "policy": {
                "canary": False,
                "injection": False,
                "content": False,
                "pii": False,
            },
        }

        def complete(identifier):
            for _ in range(200):
                run = client.get("/api/runs/" + identifier).json()
                if run["status"] not in ("queued", "running"):
                    return run
                time.sleep(0.01)
            raise AssertionError("Run did not complete")

        response = client.post("/api/runs", json=payload)
        assert response.status_code == 202
        run = complete(response.json()["id"])
        assert run["status"] == "needs_review"
        identifier = run["id"]
        assert "Regression" in client.get("/reports/" + identifier).text
        assert "Regression" in client.get("/api/runs/" + identifier + "/export.md").text
        replay = complete(
            client.post("/api/runs/" + identifier + "/replay").json()["id"]
        )
        assert replay["config"] == run["config"]
        assert replay["fixture_snapshot"] == run["fixture_snapshot"]
        assert replay["dataset_sha256"] == run["dataset_sha256"]
        assert [r["verdict"] for r in replay["arms"]["defended"]["results"]] == [
            r["verdict"] for r in run["arms"]["defended"]["results"]
        ]
