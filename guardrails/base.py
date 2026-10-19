"""
Base definitions and interfaces for AI Security Lab Guardrails.
"""

from __future__ import annotations

import abc
from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class GuardrailAction(str, Enum):
    """Action dictated by a guardrail evaluation."""
    ALLOW = "allow"
    FLAG = "flag"
    BLOCK = "block"


class RiskLevel(str, Enum):
    """Categorical risk severity assessment."""
    NONE = "none"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class GuardrailViolation(BaseModel):
    """Specific policy or security boundary violation detail."""
    rule_name: str
    description: str
    snippet: Optional[str] = None
    severity: RiskLevel = RiskLevel.MEDIUM


class GuardrailResult(BaseModel):
    """Normalized outcome produced by input or output guardrail inspection."""
    guardrail_name: str
    action: GuardrailAction = GuardrailAction.ALLOW
    risk_level: RiskLevel = RiskLevel.NONE
    confidence: float = Field(default=1.0, ge=0.0, le=1.0)
    violations: List[GuardrailViolation] = Field(default_factory=list)
    metadata: Dict[str, Any] = Field(default_factory=dict)

    @property
    def is_blocked(self) -> bool:
        return self.action == GuardrailAction.BLOCK

    @property
    def is_flagged(self) -> bool:
        return self.action in (GuardrailAction.FLAG, GuardrailAction.BLOCK)


class BaseGuardrail(abc.ABC):
    """Abstract contract for security guardrails inspecting LLM prompts or completions."""

    def __init__(self, name: Optional[str] = None, enabled: bool = True) -> None:
        self.name = name or self.__class__.__name__
        self.enabled = enabled

    @abc.abstractmethod
    def evaluate(self, text: str, context: Optional[Dict[str, Any]] = None) -> GuardrailResult:
        """Evaluates given text against safety policies and returns GuardrailResult."""
        raise NotImplementedError
