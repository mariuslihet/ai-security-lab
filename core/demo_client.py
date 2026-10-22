"""Offline target fixtures. Responses never depend on guardrail settings."""

from __future__ import annotations
import hashlib
from core.base import BaseLLMClient, GenerationConfig, LLMResponse, TokenUsage

PROVIDERS = {
    "openai": "OpenAI",
    "anthropic": "Anthropic Claude",
    "azure": "Azure AI",
    "bedrock": "AWS Bedrock",
}
PROFILES = ("balanced", "resilient", "permissive")


class DemoLLMClient(BaseLLMClient):
    def __init__(self, provider="openai", model_name="balanced", seed=42):
        if provider not in PROVIDERS:
            raise ValueError("Unknown simulated provider")
        if model_name not in PROFILES:
            raise ValueError("Choose balanced, resilient or permissive demo profile")
        super().__init__(model_name=model_name, enable_diagnostic_fallback=False)
        self._provider, self.seed = provider, seed

    @property
    def provider_name(self):
        return self._provider

    def is_configured(self):
        return True

    def generate(self, prompt, config=None):
        cfg = config or GenerationConfig()
        case = cfg.extra_params.get("test_case", {})
        behavior, identifier = case.get("demo_behavior", "ambiguous"), case.get(
            "id", "custom"
        )
        variant = int(
            hashlib.sha256(f"{identifier}:{self.seed}".encode()).hexdigest()[:8], 16
        )
        if behavior == "error":
            raise RuntimeError("Synthetic provider timeout (demo fault fixture)")
        if case.get("is_adversarial", True) and behavior == "comply":
            if self.model_name == "resilient" or (
                self.model_name == "balanced" and variant % 4 == 0
            ):
                behavior = "refuse"
        calls = []
        if behavior == "refuse":
            content = case.get(
                "demo_refusal_response",
                "I cannot comply with this request. I can help with an authorized alternative.",
            )
        elif behavior == "safe":
            content = case.get(
                "demo_safe_response",
                "Authorized task completed without protected data.",
            )
        elif behavior == "ambiguous":
            content = (
                "The available information is insufficient to determine an answer."
            )
        else:
            content = case.get(
                "demo_response", "Synthetic target returned an unspecified answer."
            )
            if case.get("forbidden_tools"):
                calls = [
                    {
                        "name": case["forbidden_tools"][0],
                        "arguments": {"record": "DEMO-ONLY"},
                        "executed": False,
                    }
                ]
                content += (
                    " Proposed sandbox action; no external operation was executed."
                )
            if case.get("metadata", {}).get("mixed_refusal"):
                content = "I cannot provide that. Nevertheless, " + content
        if behavior in ("safe", "comply") and case.get("demo_tools"):
            calls = [{**c, "executed": False} for c in case["demo_tools"]]
        input_words = len(prompt.split()) + len((cfg.system_prompt or "").split())
        usage = TokenUsage(
            prompt_tokens=input_words,
            completion_tokens=len(content.split()),
            total_tokens=input_words + len(content.split()),
        )
        return LLMResponse(
            content=content,
            model=self.model_name,
            provider=self.provider_name,
            latency_ms=0,
            usage=usage,
            is_emulated=True,
            raw_response={
                "mode": "demo",
                "fixture": identifier,
                "seed": self.seed,
                "token_accounting": "whitespace estimate",
                "tool_calls": calls,
            },
        )

    async def generate_async(self, prompt, config=None):
        return self.generate(prompt, config)
