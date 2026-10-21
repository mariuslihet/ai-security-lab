"""
Personally Identifiable Information (PII) and Secret Credential Detector.
Scans text for credit cards (with Luhn validation), emails, phone numbers,
SSNs, API keys, and cryptographic certificates.
"""

from __future__ import annotations

import re
from typing import Any, Dict, List, Optional
from guardrails.base import (
    BaseGuardrail,
    GuardrailAction,
    GuardrailResult,
    GuardrailViolation,
    RiskLevel,
)


def _luhn_checksum_valid(card_number: str) -> bool:
    """Validates credit card number string using Luhn algorithm."""
    digits = [int(c) for c in card_number if c.isdigit()]
    if len(digits) < 13 or len(digits) > 19:
        return False
    checksum = 0
    reverse_digits = digits[::-1]
    for i, digit in enumerate(reverse_digits):
        if i % 2 == 1:
            doubled = digit * 2
            checksum += doubled - 9 if doubled > 9 else doubled
        else:
            checksum += digit
    return checksum % 10 == 0


class PIIDetectorGuardrail(BaseGuardrail):
    """
    Detects high-sensitivity PII entities and leaked credentials.
    Can be used both as an input guardrail (preventing exfiltration)
    and output guardrail (preventing model memorization leakage).
    """

    EMAIL_REGEX = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b")
    PHONE_REGEX = re.compile(
        r"\b(?:\+?\d{1,3}[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b"
    )
    SSN_REGEX = re.compile(r"\b\d{3}-\d{2}-\d{4}\b")
    CREDIT_CARD_REGEX = re.compile(r"\b(?:\d{4}[-\s]?){3}\d{4}\b|\b\d{13,19}\b")

    # Credential & Token signatures
    API_KEY_REGEX = re.compile(
        r"\b(?:sk-[A-Za-z0-9]{20,}|AKIA[0-9A-Z]{16}|ghp_[A-Za-z0-9]{36})\b"
    )
    PRIVATE_KEY_REGEX = re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----")

    def __init__(
        self,
        name: str = "PIIDetector",
        block_on_secrets: bool = True,
        block_on_high_risk_pii: bool = True,
    ) -> None:
        super().__init__(name=name)
        self.block_on_secrets = block_on_secrets
        self.block_on_high_risk_pii = block_on_high_risk_pii

    def evaluate(
        self, text: str, context: Optional[Dict[str, Any]] = None
    ) -> GuardrailResult:
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

        # 1. Private Keys
        if self.PRIVATE_KEY_REGEX.search(text):
            elevate_risk(RiskLevel.CRITICAL)
            violations.append(
                GuardrailViolation(
                    rule_name="PII:PrivateKey",
                    description="Cryptographic private key header detected in text.",
                    snippet="-----BEGIN PRIVATE KEY-----...",
                    severity=RiskLevel.CRITICAL,
                )
            )

        # 2. API Keys
        for match in self.API_KEY_REGEX.finditer(text):
            elevate_risk(RiskLevel.CRITICAL)
            key_preview = match.group(0)[:6] + "..." + match.group(0)[-4:]
            violations.append(
                GuardrailViolation(
                    rule_name="PII:APIKey",
                    description="Cloud provider or service API key pattern detected.",
                    snippet=key_preview,
                    severity=RiskLevel.CRITICAL,
                )
            )

        # 3. Credit Cards (with Luhn validation)
        for match in self.CREDIT_CARD_REGEX.finditer(text):
            raw_val = match.group(0).replace("-", "").replace(" ", "")
            if _luhn_checksum_valid(raw_val):
                elevate_risk(RiskLevel.HIGH)
                masked_card = f"{raw_val[:4]}-****-****-{raw_val[-4:]}"
                violations.append(
                    GuardrailViolation(
                        rule_name="PII:CreditCard",
                        description="Valid Luhn-verified Payment Card Number detected.",
                        snippet=masked_card,
                        severity=RiskLevel.HIGH,
                    )
                )

        # 4. Social Security Numbers
        for match in self.SSN_REGEX.finditer(text):
            elevate_risk(RiskLevel.HIGH)
            violations.append(
                GuardrailViolation(
                    rule_name="PII:SSN",
                    description="US Social Security Number format detected.",
                    snippet="***-**-" + match.group(0)[-4:],
                    severity=RiskLevel.HIGH,
                )
            )

        # 5. Email Addresses
        for match in self.EMAIL_REGEX.finditer(text):
            elevate_risk(RiskLevel.LOW)
            violations.append(
                GuardrailViolation(
                    rule_name="PII:Email",
                    description="Personal or corporate email address detected.",
                    snippet=match.group(0),
                    severity=RiskLevel.LOW,
                )
            )

        # 6. Phone Numbers
        for match in self.PHONE_REGEX.finditer(text):
            elevate_risk(RiskLevel.LOW)
            violations.append(
                GuardrailViolation(
                    rule_name="PII:Phone",
                    description="Phone number sequence detected.",
                    snippet=match.group(0),
                    severity=RiskLevel.LOW,
                )
            )

        # Determine Action
        if highest_risk == RiskLevel.CRITICAL and self.block_on_secrets:
            action = GuardrailAction.BLOCK
        elif highest_risk == RiskLevel.HIGH and self.block_on_high_risk_pii:
            action = GuardrailAction.BLOCK
        elif highest_risk in (RiskLevel.MEDIUM, RiskLevel.LOW):
            action = GuardrailAction.FLAG
        else:
            action = GuardrailAction.ALLOW

        return GuardrailResult(
            guardrail_name=self.name,
            action=action,
            risk_level=highest_risk,
            confidence=None,
            violations=violations,
            metadata={"total_entities_detected": len(violations)},
        )
