"""
Provider Client Factory for AI Security Lab.
Allows dynamic resolution and instantiation of LLM provider clients.
"""

from __future__ import annotations

from enum import Enum
from typing import Any, Dict, Optional, Type
from core.base import BaseLLMClient
from core.openai_client import OpenAIClient
from core.anthropic_client import AnthropicClient
from core.azure_client import AzureAIClient
from core.bedrock_client import BedrockClient


class ProviderType(str, Enum):
    """Enumeration of supported foundation model providers."""
    OPENAI = "openai"
    ANTHROPIC = "anthropic"
    AZURE = "azure"
    BEDROCK = "bedrock"


_CLIENT_REGISTRY: Dict[str, Type[BaseLLMClient]] = {
    ProviderType.OPENAI.value: OpenAIClient,
    ProviderType.ANTHROPIC.value: AnthropicClient,
    ProviderType.AZURE.value: AzureAIClient,
    ProviderType.BEDROCK.value: BedrockClient,
}


def get_llm_client(
    provider: str | ProviderType,
    model: Optional[str] = None,
    api_key: Optional[str] = None,
    enable_diagnostic_fallback: bool = True,
    **kwargs: Any
) -> BaseLLMClient:
    """
    Factory function resolving and instantiating an LLM client.

    Args:
        provider: Provider identifier ('openai', 'anthropic', 'azure', 'bedrock').
        model: Specific model identifier or deployment. If None, default provider model is used.
        api_key: Optional explicit API key.
        enable_diagnostic_fallback: If True, falls back to safe diagnostic responses when credentials are missing.
        **kwargs: Extra parameters passed directly to provider client constructor.

    Returns:
        Instance conforming to BaseLLMClient interface.
    """
    normalized_provider = provider.value if isinstance(provider, ProviderType) else str(provider).lower()
    client_class = _CLIENT_REGISTRY.get(normalized_provider)

    if not client_class:
        supported = ", ".join(_CLIENT_REGISTRY.keys())
        raise ValueError(
            f"Unsupported provider '{provider}'. Supported providers are: {supported}"
        )

    constructor_kwargs: Dict[str, Any] = {
        "enable_diagnostic_fallback": enable_diagnostic_fallback,
        **kwargs
    }
    if api_key:
        constructor_kwargs["api_key"] = api_key

    if model:
        if normalized_provider == ProviderType.AZURE.value:
            constructor_kwargs["deployment_name"] = model
        elif normalized_provider == ProviderType.BEDROCK.value:
            constructor_kwargs["model_id"] = model
        else:
            constructor_kwargs["model_name"] = model

    return client_class(**constructor_kwargs)


def list_available_providers() -> Dict[str, Dict[str, Any]]:
    """
    Inspects environment and dependencies to report configuration status for all providers.
    """
    status: Dict[str, Dict[str, Any]] = {}
    for name, client_cls in _CLIENT_REGISTRY.items():
        try:
            instance = client_cls()
            status[name] = {
                "configured": instance.is_configured(),
                "default_model": instance.model_name,
                "provider": name
            }
        except Exception as err:
            status[name] = {
                "configured": False,
                "default_model": "unknown",
                "provider": name,
                "error": str(err)
            }
    return status
