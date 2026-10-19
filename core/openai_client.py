"""
OpenAI Provider Client Implementation for AI Security Lab.
Supports GPT-4o, GPT-4-turbo, GPT-3.5 and compatible endpoints with resilient fallbacks.
"""

from __future__ import annotations

import os
import time
from typing import Optional
from core.base import BaseLLMClient, GenerationConfig, LLMResponse, TokenUsage


class OpenAIClient(BaseLLMClient):
    """Client for OpenAI Foundation Models."""

    def __init__(
        self,
        model_name: str = "gpt-4o-mini",
        api_key: Optional[str] = None,
        base_url: Optional[str] = None,
        timeout: float = 30.0,
        enable_diagnostic_fallback: bool = True
    ) -> None:
        resolved_key = api_key or os.getenv("OPENAI_API_KEY")
        super().__init__(
            model_name=model_name,
            api_key=resolved_key,
            timeout=timeout,
            enable_diagnostic_fallback=enable_diagnostic_fallback
        )
        self.base_url = base_url or os.getenv("OPENAI_BASE_URL")
        self._sync_client = None
        self._async_client = None
        self._initialize_sdk()

    @property
    def provider_name(self) -> str:
        return "openai"

    def is_configured(self) -> bool:
        return bool(self.api_key and self._sync_client is not None)

    def _initialize_sdk(self) -> None:
        """Dynamically initialize official OpenAI SDK if available."""
        if not self.api_key:
            return
        try:
            from openai import OpenAI, AsyncOpenAI
            self._sync_client = OpenAI(
                api_key=self.api_key,
                base_url=self.base_url,
                timeout=self.timeout
            )
            self._async_client = AsyncOpenAI(
                api_key=self.api_key,
                base_url=self.base_url,
                timeout=self.timeout
            )
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
                    reason="OpenAI SDK not installed or OPENAI_API_KEY not configured"
                )
            raise RuntimeError("OpenAI client is not configured and diagnostic fallback is disabled.")

        messages = []
        if cfg.system_prompt:
            messages.append({"role": "system", "content": cfg.system_prompt})
        messages.append({"role": "user", "content": prompt})

        start = time.perf_counter()
        try:
            response = self._sync_client.chat.completions.create(
                model=self.model_name,
                messages=messages,
                temperature=cfg.temperature,
                max_tokens=cfg.max_tokens,
                top_p=cfg.top_p,
                stop=cfg.stop_sequences,
                **cfg.extra_params
            )
            latency = (time.perf_counter() - start) * 1000.0
            choice = response.choices[0]
            usage = response.usage
            return LLMResponse(
                content=choice.message.content or "",
                model=response.model or self.model_name,
                provider=self.provider_name,
                latency_ms=round(latency, 2),
                usage=TokenUsage(
                    prompt_tokens=usage.prompt_tokens if usage else 0,
                    completion_tokens=usage.completion_tokens if usage else 0,
                    total_tokens=usage.total_tokens if usage else 0
                ),
                raw_response=response.model_dump() if hasattr(response, "model_dump") else None,
                is_emulated=False
            )
        except Exception as err:
            if self.enable_diagnostic_fallback:
                return self._generate_diagnostic_response(
                    prompt=prompt,
                    config=cfg,
                    reason=f"OpenAI API runtime error: {err}"
                )
            raise

    async def generate_async(self, prompt: str, config: Optional[GenerationConfig] = None) -> LLMResponse:
        cfg = config or GenerationConfig()
        if not self.is_configured():
            if self.enable_diagnostic_fallback:
                return self._generate_diagnostic_response(
                    prompt=prompt,
                    config=cfg,
                    reason="OpenAI SDK not installed or OPENAI_API_KEY not configured"
                )
            raise RuntimeError("OpenAI client is not configured and diagnostic fallback is disabled.")

        messages = []
        if cfg.system_prompt:
            messages.append({"role": "system", "content": cfg.system_prompt})
        messages.append({"role": "user", "content": prompt})

        start = time.perf_counter()
        try:
            response = await self._async_client.chat.completions.create(
                model=self.model_name,
                messages=messages,
                temperature=cfg.temperature,
                max_tokens=cfg.max_tokens,
                top_p=cfg.top_p,
                stop=cfg.stop_sequences,
                **cfg.extra_params
            )
            latency = (time.perf_counter() - start) * 1000.0
            choice = response.choices[0]
            usage = response.usage
            return LLMResponse(
                content=choice.message.content or "",
                model=response.model or self.model_name,
                provider=self.provider_name,
                latency_ms=round(latency, 2),
                usage=TokenUsage(
                    prompt_tokens=usage.prompt_tokens if usage else 0,
                    completion_tokens=usage.completion_tokens if usage else 0,
                    total_tokens=usage.total_tokens if usage else 0
                ),
                raw_response=response.model_dump() if hasattr(response, "model_dump") else None,
                is_emulated=False
            )
        except Exception as err:
            if self.enable_diagnostic_fallback:
                return self._generate_diagnostic_response(
                    prompt=prompt,
                    config=cfg,
                    reason=f"OpenAI API async runtime error: {err}"
                )
            raise
