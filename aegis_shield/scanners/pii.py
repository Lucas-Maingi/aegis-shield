"""PII (Personally Identifiable Information) scanner.

Detects sensitive data patterns in prompt text *before* it reaches the
upstream LLM.  The goal is to prevent accidental leakage of customer data
into third-party model providers.

Detection is regex-based and deliberately conservative — it flags anything
that *looks like* PII rather than trying to understand context.  False
positives are cheap (a blocked request gets a clear error); false negatives
are expensive (PII lands in a provider's training pipeline).

Supported categories:
- Email addresses
- Phone numbers (international & Kenyan format)
- Credit / debit card numbers (Luhn-validated)
- US Social Security Numbers
- API keys / bearer tokens (high-entropy hex/base64 strings)
- Kenyan national ID numbers
"""

from __future__ import annotations

import re

from aegis_shield.models import Finding, ThreatCategory

_SCANNER_NAME = "pii"


# ── Pattern definitions ──────────────────────────────────────────────────

_PATTERNS: list[tuple[str, re.Pattern, str]] = [
    (
        "email",
        re.compile(r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z]{2,}", re.IGNORECASE),
        "Email address detected",
    ),
    (
        "phone_international",
        re.compile(r"(?<!\d)(\+?\d{1,3}[-.\s]?\(?\d{1,4}\)?[-.\s]?\d{3,4}[-.\s]?\d{3,4})(?!\d)"),
        "Phone number detected",
    ),
    (
        "credit_card",
        re.compile(r"\b(?:\d[ -]*?){13,19}\b"),
        "Possible credit/debit card number detected",
    ),
    (
        "ssn",
        re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),
        "US Social Security Number detected",
    ),
    (
        "kenyan_id",
        re.compile(r"\b\d{7,8}\b"),
        "Possible Kenyan national ID number detected",
    ),
    (
        "api_key",
        re.compile(
            r"(?:sk-[a-zA-Z0-9]{20,}|"           # OpenAI-style
            r"AIza[a-zA-Z0-9_-]{35}|"              # Google API key
            r"ghp_[a-zA-Z0-9]{36}|"                # GitHub PAT
            r"Bearer\s+[a-zA-Z0-9._~+/=-]{20,})",  # Generic bearer token
            re.IGNORECASE,
        ),
        "API key or bearer token detected",
    ),
]


# ── Luhn check for credit card validation ────────────────────────────────

def _passes_luhn(number_str: str) -> bool:
    """Validate a numeric string against the Luhn algorithm.

    This filters out random digit sequences that match the credit-card
    regex but aren't real card numbers — reducing false positives without
    adding a heavy dependency.
    """
    digits = [int(d) for d in number_str if d.isdigit()]
    if len(digits) < 13:
        return False
    checksum = 0
    reverse = digits[::-1]
    for i, d in enumerate(reverse):
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        checksum += d
    return checksum % 10 == 0


# ── Public API ───────────────────────────────────────────────────────────

def scan(content: str) -> list[Finding]:
    """Scan ``content`` for PII patterns and return any findings.

    Each finding includes the matched text (truncated for safety in logs)
    and the detection category.
    """
    findings: list[Finding] = []

    for label, pattern, description in _PATTERNS:
        for match in pattern.finditer(content):
            matched = match.group(0).strip()

            # Credit-card matches must also pass Luhn to reduce noise.
            if label == "credit_card" and not _passes_luhn(matched):
                continue

            # Kenyan ID pattern is broad (7-8 digits) — skip if it's
            # clearly part of a longer number or a year.
            if label == "kenyan_id" and (
                len(matched) < 7 or matched.startswith("19") or matched.startswith("20")
            ):
                continue

            # Truncate matched text to avoid logging full PII in findings.
            safe_preview = matched[:6] + "***" if len(matched) > 6 else matched

            findings.append(
                Finding(
                    category=ThreatCategory.PII_LEAK,
                    severity="high",
                    detail=f"{description} ({label})",
                    matched_text=safe_preview,
                    scanner=_SCANNER_NAME,
                )
            )

    return findings
