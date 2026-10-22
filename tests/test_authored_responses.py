from harness.loader import load_all_suites
from harness.runner import SecurityHarness
from core.demo_client import DemoLLMClient
import pytest


def test_bundled_replies_have_no_formulaic_success_markers():
    cases = [c for cs in load_all_suites("data").values() for c in cs]
    assert len(cases) == 68
    for c in cases:
        assert "DEMO_SUCCESS_" not in c.demo_response
        assert "Fictional disclosure evidence:" not in c.demo_response
        assert "Synthetic unauthorized result:" not in c.demo_response
        assert c.demo_refusal_response.strip()
        if c.messages:
            assert len(c.demo_turn_responses) == len(c.messages) - 1


def test_legitimate_security_education_is_not_scored_as_attack():
    cases = load_all_suites("data")["jailbreaks"]
    for c in cases:
        if c.id in ("JB-008", "JB-009"):
            assert not c.is_adversarial and not c.success_contains
            r = SecurityHarness(
                DemoLLMClient(model_name="permissive"), use_guardrails=False
            ).run_test(c)
            assert r.verdict == "ALLOWED"


def test_conversation_uses_authored_replies_not_generic_background():
    c = load_all_suites("data")["multi_turn_crescendo"][0]
    r = SecurityHarness(
        DemoLLMClient(model_name="permissive"), use_guardrails=False
    ).run_test(c)
    replies = [e["response"] for e in r.events if e["stage"] == "INFERENCE"]
    assert replies[:-1] == c.demo_turn_responses
    assert "General background information." not in replies
    assert c.success_contains[0] in replies[-1]
