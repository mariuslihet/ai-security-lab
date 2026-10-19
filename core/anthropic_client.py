"""
Anthropic Claude Provider Client Implementation for AI Security Lab.
Supports Claude 3.5 Sonnet, Claude 3 Opus, Claude 3 Haiku via official Anthropic SDK.
"""

from __future__ import annotations

import os
import time
from typing import Optional
from core.base import BaseLLMClient, GenerationConfig, LLMResponse, TokenUsage


class AnthropicClient(BaseLLMClient):
    """Client for Anthropic Claude Foundation Models."""

    def __init__(
        self,
        model_name: str = "claude-3-5-sonnet-20241022",
        api_key: Optional[str] = None,
        timeout: float = 30.0,
        enable_diagnostic_fallback: bool = True
    ) -> None:
        resolved_key = api_key or os.getenv("ANTHROPIC_API_KEY")
        super().__init__(
            model_name=model_name,
            api_key=resolved_key,
            timeout=timeout,
            enable_diagnostic_fallback=enable_diagnostic_fallback
        )
        self._sync_client = None
        self._async_client = None
        self._initialize_sdk()

    @property
    def provider_name(self) -> str:
        return "anthropic"

    def is_configured(self) -> bool:
        return bool(self.api_key and self._sync_client is not None)

    def _initialize_sdk(self) -> None:
        """Dynamically initialize Anthropic SDK."""
        if not self.api_key:
            return
        try:
            from anthropic import Anthropic, AsyncAnthropic
            self._sync_client = Anthropic(api_key=self.api_key, timeout=self.timeout)
            self._async_client = AsyncAnthropic(api_key=self.api_key, timeout=self.timeout)
        except ImportError:
            self._sync_client = None
            self._async_client = None

    def generate(self, prompt: str, config: Optional[GenerationConfig] = None) -> LLMResponse:
        cfg = config or GenerationConfig()
        if not self.is_configured():
            if self.enable_diagnostic_fallback:
                return self._generate_diagnostic_response(
                    prompt=prompt,
                    config=cfg,
                    reason="Anthropic SDK not installed or ANTHROPIC_API_KEY not configured"
                )
            raise RuntimeError("Anthropic client is not configured and diagnostic fallback is disabled.")

        start = time.perf_counter()
        try:
            kwargs = {
                "model": self.model_name,
                "messages": [{"role": "user", "content": prompt}],
                "max_tokens": cfg.max_tokens,
                "temperature": cfg.temperature,
                "top_p": cfg.top_p,
            }
            if cfg.system_prompt:
                kwargs["system"] = cfg.system_prompt
            if cfg.stop_sequences:
                kwargs["stop_sequences"] = cfg.stop_sequences
            kwargs.update(cfg.extra_params)

            response = self._sync_client.messages.create(**kwargs)
            latency = (time.perf_counter() - start) * 1000.0

            content_text = ""
            for block in response.content:
                if hasattr(block, "text"):
                    content_text += block.text

            return LLMResponse(
                content=content_text,
                model=response.model or self.model_name,
                provider=self.provider_name,
                latency_ms=round(latency, 2),
                usage=TokenUsage(
                    prompt_tokens=response.usage.input_tokens,
                    completion_tokens=response.usage.output_tokens,
                    total_tokens=response.usage.input_tokens + response.usage.output_tokens
                ),
                raw_response=response.model_dump() if hasattr(response, "model_dump") else None,
                is_emulated=False
            )
        except Exception as err:
            if self.enable_diagnostic_fallback:
                return self._generate_diagnostic_response(
                    prompt=prompt,
                    config=cfg,
                    reason=f"Anthropic API runtime error: {err}"
                )
            raise

    async def generate_async(self, prompt: str, config: Optional[GenerationConfig] = None) -> LLMResponse:
        cfg = config or GenerationConfig()
        if not self.is_configured():
            if self.enable_diagnostic_fallback:
                return self._generate_diagnostic_response(
                    prompt=prompt,
                    config=cfg,
                    reason="Anthropic SDK not installed or ANTHROPIC_API_KEY not configured"
                )
            raise RuntimeError("Anthropic client is not configured and diagnostic fallback is disabled.")

        start = time.perf_counter()
        try:
            kwargs = {
                "model": self.model_name,
                "messages": [{"role": "user", "content": prompt}],
                "max_tokens": cfg.max_tokens,
                "temperature": cfg.temperature,
                "top_p": cfg.top_p,
            }
            if cfg.system_prompt:
                kwargs["system"] = cfg.system_prompt
            if cfg.stop_sequences:
                kwargs["stop_sequences"] = cfg.stop_sequences
            kwargs.update(cfg.extra_params)

            response = await self._async_client.messages.create(**kwargs)
            latency = (time.perf_counter() - start) * 1000.0

            content_text = ""
            for block in response.content:
                if hasattr(block, "text"):
                    content_text += block.text

            return LLMResponse(
                content=content_text,
                model=response.model or self.model_name,
                provider=self.provider_name,
                latency_ms=round(latency, 2),
                usage=TokenUsage(
                    prompt_tokens=response.usage.input_tokens,
                    completion_tokens=response.usage.output_tokens,
                    total_tokens=response.usage.input_tokens + response.usage.output_tokens
                ),
                raw_response=response.model_dump() if hasattr(response, "model_dump") else None,
                is_emulated=False
            )
        except Exception as err:
            if self.enable_diagnostic_fallback:
                return self._generate_diagnostic_response(
                    prompt=prompt,
                    config=cfg,
                    reason=f"Anthropic API async runtime error: {err}"
                )
            raise
