"""
Prompt Injection & Jailbreak Heuristic Detector.
Inspects incoming prompts for override signatures, role hijacking, delimiter escapes,
and obfuscated payloads (e.g. Base64 encoding).
"""

from __future__ import annotations

import base64
import re
import unicodedata
from typing import Any, Dict, List, Optional
from guardrails.base import (
    BaseGuardrail,
    GuardrailAction,
    GuardrailResult,
    GuardrailViolation,
    RiskLevel,
)


class PromptInjectionGuardrail(BaseGuardrail):
    """
    Detects direct and indirect prompt injection attempts using weighted heuristic patterns,
    syntactic delimiter escape analysis, and base64 payload de-obfuscation.
    """

    # Instruction override patterns
    OVERRIDE_PATTERNS = [
        (
            r"(?i)\bignora\s+(toate\s+)?instructiunile\s+anterioare\b",
            RiskLevel.CRITICAL,
        ),
        (r"(?i)\bdivulga\s+(secretele|datele\s+confidentiale)\b", RiskLevel.HIGH),
        (
            r"(?i)\bignore\s+(all\s+)?(previous|prior|above|earlier)\s+(instructions|directives|prompts|rules)",
            RiskLevel.CRITICAL,
        ),
        (
            r"(?i)\bdisregard\s+(all\s+)?(previous|prior|system)\s+(guidelines|instructions|rules|filters)",
            RiskLevel.CRITICAL,
        ),
        (
            r"(?i)\bforget\s+(everything\s+)?(you\s+know|about\s+your\s+rules|previous\s+instructions)",
            RiskLevel.HIGH,
        ),
        (r"(?i)\bfrom\s+now\s+on\b.*?\byou\s+(must|shall|will)\b", RiskLevel.MEDIUM),
        (
            r"(?i)\boverride\s+(system|safety|security)\s+(prompt|settings|filters)",
            RiskLevel.CRITICAL,
        ),
    ]

    # Role hijacking & persona bypass patterns
    ROLE_HIJACK_PATTERNS = [
        (
            r"(?i)\byou\s+are\s+now\s+(unrestricted|jailbroken|evil|dan|in\s+developer\s+mode)",
            RiskLevel.CRITICAL,
        ),
        (r"(?i)\bdo\s+anything\s+now\b", RiskLevel.HIGH),
        (
            r"(?i)\boperating\s+without\s+(any\s+)?(restrictions|ethical\s+guidelines|constraints)",
            RiskLevel.CRITICAL,
        ),
        (
            r"(?i)\bpretend\s+to\s+be\s+(an\s+unfiltered|a\s+malicious|an\s+adversarial)",
            RiskLevel.HIGH,
        ),
        (r"(?i)\bhypothetical\s+unrestricted\s+scenario\b", RiskLevel.MEDIUM),
    ]

    # Delimiter hijacking & structural prompt escape
    DELIMITER_PATTERNS = [
        (r"(?i)\[\s*system\s*\]|\{\s*\"role\"\s*:\s*\"system\"", RiskLevel.HIGH),
        (r"(?i)<\s*/?\s*system\s*>", RiskLevel.HIGH),
        (r"(?i)###\s*(instruction|system|new\s+role)", RiskLevel.MEDIUM),
        (r"(?i)human:\s*.*?\s*assistant:", RiskLevel.HIGH),
    ]

    # System instruction / canary exfiltration probes
    LEAK_PROBE_PATTERNS = [
        (
            r"(?i)\brepeat\s+(all\s+)?(text\s+above|the\s+system\s+prompt|your\s+initial\s+instructions)",
            RiskLevel.HIGH,
        ),
        (
            r"(?i)\bprint\s+(the\s+entire|verbatim|full)\s+(system\s+prompt|developer\s+message)",
            RiskLevel.HIGH,
        ),
        (
            r"(?i)\bwhat\s+(are\s+your|was\s+the)\s+(secret\s+canary|system\s+instructions|system\s+prompt)",
            RiskLevel.HIGH,
        ),
    ]

    BASE64_REGEX = re.compile(
        r"(?:[A-Za-z0-9+/]{4}){6,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?"
    )

    def __init__(
        self,
        name: str = "PromptInjectionDetector",
        block_threshold: RiskLevel = RiskLevel.HIGH,
    ) -> None:
        super().__init__(name=name)
        self.block_threshold = block_threshold

    def evaluate(
        self, text: str, context: Optional[Dict[str, Any]] = None
    ) -> GuardrailResult:
        text = "".join(
            c
            for c in unicodedata.normalize("NFKD", text)
            if not unicodedata.combining(c)
        )
        violations: List[GuardrailViolation] = []
        highest_risk = RiskLevel.NONE

        def elevate_risk(new_risk: RiskLevel) -> None:
            nonlocal highest_risk
            order = [
                RiskLevel.NONE,
                RiskLevel.LOW,
                RiskLevel.MEDIUM,
                RiskLevel.HIGH,
                RiskLevel.CRITICAL,
            ]
            if order.index(new_risk) > order.index(highest_risk):
                highest_risk = new_risk

        # 1. Direct pattern matching
        all_rules = [
            (
                "InstructionOverride",
                self.OVERRIDE_PATTERNS,
                "Attempt to override or disregard prior system instructions.",
            ),
            (
                "RoleHijacking",
                self.ROLE_HIJACK_PATTERNS,
                "Attempt to force model into unrestricted persona or jailbreak role.",
            ),
            (
                "DelimiterHijacking",
                self.DELIMITER_PATTERNS,
                "Attempt to break prompt boundaries using structural formatting.",
            ),
            (
                "PromptLeakProbe",
                self.LEAK_PROBE_PATTERNS,
                "Attempt to exfiltrate secret system prompt or canary tokens.",
            ),
        ]

        for rule_category, patterns, desc in all_rules:
            for pattern, severity in patterns:
                match = re.search(pattern, text)
                if match:
                    elevate_risk(severity)
                    violations.append(
                        GuardrailViolation(
                            rule_name=rule_category,
                            description=desc,
                            snippet=match.group(0)[:120],
                            severity=severity,
                        )
                    )

        # 2. De-obfuscation: detect and inspect embedded Base64 chunks
        for b64_match in self.BASE64_REGEX.finditer(text):
            chunk = b64_match.group(0)
            try:
                decoded = base64.b64decode(chunk).decode("utf-8", errors="ignore")
                if len(decoded) > 10:
                    for rule_category, patterns, desc in all_rules:
                        for pattern, severity in patterns:
                            if re.search(pattern, decoded):
                                elevate_risk(severity)
                                violations.append(
                                    GuardrailViolation(
                                        rule_name=f"{rule_category}:Base64Obfuscated",
                                        description=f"{desc} (hidden inside Base64 encoding)",
                                        snippet=decoded[:100],
                                        severity=severity,
                                    )
                                )
            except Exception:
                continue

        # Decide Action based on risk level
        order = [
            RiskLevel.NONE,
            RiskLevel.LOW,
            RiskLevel.MEDIUM,
            RiskLevel.HIGH,
            RiskLevel.CRITICAL,
        ]
        threshold_idx = order.index(self.block_threshold)
        current_idx = order.index(highest_risk)

        if current_idx >= threshold_idx and current_idx > 0:
            action = GuardrailAction.BLOCK
        elif current_idx > 0:
            action = GuardrailAction.FLAG
        else:
            action = GuardrailAction.ALLOW

        return GuardrailResult(
            guardrail_name=self.name,
            action=action,
            risk_level=highest_risk,
            confidence=None,
            violations=violations,
            metadata={"violation_count": len(violations)},
        )
