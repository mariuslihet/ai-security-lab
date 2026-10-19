"""
AWS Bedrock Provider Client Implementation for AI Security Lab.
Supports Amazon Bedrock foundation models (Claude 3, Llama 3, Amazon Titan)
via modern AWS SDK Bedrock-Runtime Converse API.
"""

from __future__ import annotations

import asyncio
import os
import time
from typing import Optional
from core.base import BaseLLMClient, GenerationConfig, LLMResponse, TokenUsage


class BedrockClient(BaseLLMClient):
    """Client for AWS Bedrock Foundation Models."""

    def __init__(
        self,
        model_id: str = "anthropic.claude-3-sonnet-20240229-v1:0",
        region_name: Optional[str] = None,
        timeout: float = 30.0,
        enable_diagnostic_fallback: bool = True
    ) -> None:
        super().__init__(
            model_name=model_id,
            api_key=os.getenv("AWS_ACCESS_KEY_ID"),
            timeout=timeout,
            enable_diagnostic_fallback=enable_diagnostic_fallback
        )
        self.region_name = region_name or os.getenv("AWS_REGION", "us-east-1")
        self._runtime_client = None
        self._initialize_sdk()

    @property
    def provider_name(self) -> str:
        return "bedrock"

    def is_configured(self) -> bool:
        return bool(self._runtime_client is not None)

    def _initialize_sdk(self) -> None:
        """Dynamically initialize boto3 bedrock-runtime client."""
        try:
            import boto3
            # Check basic AWS credential environment or profile presence
            has_creds = bool(
                os.getenv("AWS_ACCESS_KEY_ID")
                or os.getenv("AWS_PROFILE")
                or os.path.exists(os.path.expanduser("~/.aws/credentials"))
            )
            if not has_creds:
                self._runtime_client = None
                return

            self._runtime_client = boto3.client(
                service_name="bedrock-runtime",
                region_name=self.region_name
            )
        except Exception:
            self._runtime_client = None

    def generate(self, prompt: str, config: Optional[GenerationConfig] = None) -> LLMResponse:
        cfg = config or GenerationConfig()
        if not self.is_configured():
            if self.enable_diagnostic_fallback:
                return self._generate_diagnostic_response(
                    prompt=prompt,
                    config=cfg,
                    reason="boto3 not installed or AWS credentials not configured"
                )
            raise RuntimeError("AWS Bedrock client is not configured and diagnostic fallback is disabled.")

        messages = [
            {
                "role": "user",
                "content": [{"text": prompt}]
            }
        ]
        inference_config = {
            "temperature": cfg.temperature,
            "maxTokens": cfg.max_tokens,
            "topP": cfg.top_p
        }
        if cfg.stop_sequences:
            inference_config["stopSequences"] = cfg.stop_sequences

        kwargs = {
            "modelId": self.model_name,
            "messages": messages,
            "inferenceConfig": inference_config
        }
        if cfg.system_prompt:
            kwargs["system"] = [{"text": cfg.system_prompt}]

        start = time.perf_counter()
        try:
            response = self._runtime_client.converse(**kwargs)
            latency = (time.perf_counter() - start) * 1000.0

            output_message = response.get("output", {}).get("message", {})
            content_blocks = output_message.get("content", [])
            text_result = "".join(b.get("text", "") for b in content_blocks if "text" in b)

            usage_raw = response.get("usage", {})
            return LLMResponse(
                content=text_result,
                model=self.model_name,
                provider=self.provider_name,
                latency_ms=round(latency, 2),
                usage=TokenUsage(
                    prompt_tokens=usage_raw.get("inputTokens", 0),
                    completion_tokens=usage_raw.get("outputTokens", 0),
                    total_tokens=usage_raw.get("totalTokens", 0)
                ),
                raw_response=response,
                is_emulated=False
            )
        except Exception as err:
            if self.enable_diagnostic_fallback:
                return self._generate_diagnostic_response(
                    prompt=prompt,
                    config=cfg,
                    reason=f"AWS Bedrock Converse API error: {err}"
                )
            raise

    async def generate_async(self, prompt: str, config: Optional[GenerationConfig] = None) -> LLMResponse:
        return await asyncio.to_thread(self.generate, prompt, config)
