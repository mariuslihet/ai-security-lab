"""
Unified LLM Provider Interface for AI Security Lab.
Defines standard protocols, configurations, and response representations
across heterogeneous foundation model APIs (OpenAI, Claude, Azure AI, AWS Bedrock).
"""

from __future__ import annotations

import abc
import time
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class GenerationConfig(BaseModel):
    """Configuration options for model inference generation."""
    temperature: float = Field(default=0.0, ge=0.0, le=2.0, description="Sampling temperature.")
    max_tokens: int = Field(default=1024, ge=1, description="Maximum tokens generated.")
    top_p: float = Field(default=1.0, ge=0.0, le=1.0, description="Nucleus sampling probability.")
    system_prompt: Optional[str] = Field(default=None, description="System instruction prompt.")
    stop_sequences: Optional[List[str]] = Field(default=None, description="Sequences terminating output.")
    extra_params: Dict[str, Any] = Field(default_factory=dict, description="Provider-specific flags.")


class TokenUsage(BaseModel):
    """Normalized token accounting structure."""
    prompt_tokens: int = 0
    completion_tokens: int = 0
    total_tokens: int = 0


class LLMResponse(BaseModel):
    """Standardized response payload returned by all provider clients."""
    content: str
    model: str
    provider: str
    latency_ms: float
    usage: TokenUsage = Field(default_factory=TokenUsage)
    raw_response: Optional[Dict[str, Any]] = None
    is_emulated: bool = Field(
        default=False,
        description="True if returned by local diagnostic engine when remote credentials are absent."
    )


class BaseLLMClient(abc.ABC):
    """Abstract Base Class specifying common contract for foundation model clients."""

    def __init__(
        self,
        model_name: str,
        api_key: Optional[str] = None,
        timeout: float = 30.0,
        enable_diagnostic_fallback: bool = True
    ) -> None:
        self.model_name = model_name
        self.api_key = api_key
        self.timeout = timeout
        self.enable_diagnostic_fallback = enable_diagnostic_fallback

    @property
    @abc.abstractmethod
    def provider_name(self) -> str:
        """Normalized identifier for the provider (e.g. 'openai', 'anthropic')."""
        raise NotImplementedError

    @abc.abstractmethod
    def is_configured(self) -> bool:
        """Returns True if the required credentials and SDK dependencies are available."""
        raise NotImplementedError

    @abc.abstractmethod
    def generate(self, prompt: str, config: Optional[GenerationConfig] = None) -> LLMResponse:
        """Synchronous text completion request."""
        raise NotImplementedError

    @abc.abstractmethod
    async def generate_async(self, prompt: str, config: Optional[GenerationConfig] = None) -> LLMResponse:
        """Asynchronous text completion request."""
        raise NotImplementedError

    def _generate_diagnostic_response(
        self,
        prompt: str,
        config: Optional[GenerationConfig] = None,
        reason: str = "Unconfigured API key"
    ) -> LLMResponse:
        """
        Provides deterministic, contextual response simulation when live remote API
        credentials are not configured in local environment or CI/CD pipelines.
        Prevents test crashes while clearly marking the response as emulated.
        """
        start = time.perf_counter()
        normalized_prompt = prompt.lower()
        
        # Emulate standard model baseline response dynamics
        if "ignore previous instructions" in normalized_prompt or "jailbreak" in normalized_prompt:
            content = (
                "I cannot comply with requests that attempt to override system instructions "
                "or bypass safety policies."
            )
        elif "canary" in normalized_prompt or "system prompt" in normalized_prompt:
            content = "I am an AI assistant designed to follow strict safety and privacy constraints."
        elif "password" in normalized_prompt or "secret key" in normalized_prompt:
            content = "I am unable to reveal sensitive credentials or protected operational secrets."
        else:
            content = f"Standard response to: {prompt[:80]}... [Diagnostic Mode: {reason}]"

        latency = (time.perf_counter() - start) * 1000.0
        prompt_tokens = len(prompt.split())
        completion_tokens = len(content.split())

        return LLMResponse(
            content=content,
            model=self.model_name,
            provider=self.provider_name,
            latency_ms=round(latency, 2),
            usage=TokenUsage(
                prompt_tokens=prompt_tokens,
                completion_tokens=completion_tokens,
                total_tokens=prompt_tokens + completion_tokens
            ),
            raw_response={"diagnostic_reason": reason, "mode": "emulated_execution"},
            is_emulated=True
        )
