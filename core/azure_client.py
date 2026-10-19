"""
Azure OpenAI Provider Client Implementation for AI Security Lab.
Supports enterprise-managed GPT-4o, GPT-4, and custom fine-tuned deployments.
"""

from __future__ import annotations

import os
import time
from typing import Optional
from core.base import BaseLLMClient, GenerationConfig, LLMResponse, TokenUsage


class AzureAIClient(BaseLLMClient):
    """Client for Azure OpenAI Foundation Model deployments."""

    def __init__(
        self,
        deployment_name: Optional[str] = None,
        model_name: Optional[str] = None,
        api_key: Optional[str] = None,
        endpoint: Optional[str] = None,
        api_version: str = "2024-02-15-preview",
        timeout: float = 30.0,
        enable_diagnostic_fallback: bool = True
    ) -> None:
        resolved_deployment = deployment_name or os.getenv("AZURE_OPENAI_DEPLOYMENT_NAME") or "gpt-4o"
        resolved_model = model_name or resolved_deployment
        resolved_key = api_key or os.getenv("AZURE_OPENAI_API_KEY")
        super().__init__(
            model_name=resolved_model,
            api_key=resolved_key,
            timeout=timeout,
            enable_diagnostic_fallback=enable_diagnostic_fallback
        )
        self.deployment_name = resolved_deployment
        self.endpoint = endpoint or os.getenv("AZURE_OPENAI_ENDPOINT")
        self.api_version = api_version or os.getenv("AZURE_OPENAI_API_VERSION", "2024-02-15-preview")
        self._sync_client = None
        self._async_client = None
        self._initialize_sdk()

    @property
    def provider_name(self) -> str:
        return "azure"

    def is_configured(self) -> bool:
        return bool(self.api_key and self.endpoint and self._sync_client is not None)

    def _initialize_sdk(self) -> None:
        """Dynamically initialize AzureOpenAI SDK client."""
        if not (self.api_key and self.endpoint):
            return
        try:
            from openai import AzureOpenAI, AsyncAzureOpenAI
            self._sync_client = AzureOpenAI(
                api_key=self.api_key,
                azure_endpoint=self.endpoint,
                api_version=self.api_version,
                timeout=self.timeout
            )
            self._async_client = AsyncAzureOpenAI(
                api_key=self.api_key,
                azure_endpoint=self.endpoint,
                api_version=self.api_version,
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
                    reason="Azure OpenAI SDK not installed or AZURE_OPENAI_API_KEY / ENDPOINT missing"
                )
            raise RuntimeError("Azure AI client is not configured and diagnostic fallback is disabled.")

        messages = []
        if cfg.system_prompt:
            messages.append({"role": "system", "content": cfg.system_prompt})
        messages.append({"role": "user", "content": prompt})

        start = time.perf_counter()
        try:
            response = self._sync_client.chat.completions.create(
                model=self.deployment_name,
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
                model=self.deployment_name,
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
                    reason=f"Azure OpenAI API error: {err}"
                )
            raise

    async def generate_async(self, prompt: str, config: Optional[GenerationConfig] = None) -> LLMResponse:
        cfg = config or GenerationConfig()
        if not self.is_configured():
            if self.enable_diagnostic_fallback:
                return self._generate_diagnostic_response(
                    prompt=prompt,
                    config=cfg,
                    reason="Azure OpenAI SDK not installed or AZURE_OPENAI_API_KEY / ENDPOINT missing"
                )
            raise RuntimeError("Azure AI client is not configured and diagnostic fallback is disabled.")

        messages = []
        if cfg.system_prompt:
            messages.append({"role": "system", "content": cfg.system_prompt})
        messages.append({"role": "user", "content": prompt})

        start = time.perf_counter()
        try:
            response = await self._async_client.chat.completions.create(
                model=self.deployment_name,
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
                model=self.deployment_name,
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
                    reason=f"Azure OpenAI API async error: {err}"
                )
            raise
