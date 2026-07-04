"""Output scanner — inspects the LLM's completion before it reaches the client.

While the PII and injection scanners protect the *inbound* prompt, this
scanner protects the *outbound* completion.  It catches cases where a
successful jailbreak or a model hallucination causes the LLM to echo
back sensitive data that should never leave the gateway:

- System prompt leakage (the model repeating its own instructions).
- API keys and secrets in the response.
- Internal URLs, IP addresses, or infrastructure hostnames.
- Refusal-bypass indicators (the model acknowledging it's breaking rules).
"""

from __future__ import annotations

import re

from aegis_shield.models import Finding, ThreatCategory

_SCANNER_NAME = "output"


# ── Patterns ─────────────────────────────────────────────────────────────

_OUTPUT_PATTERNS: list[tuple[str, re.Pattern, str, str]] = [
    # API keys / secrets in output
    (
        "api_key_leak",
        re.compile(
            r"(?:sk-[a-zA-Z0-9]{20,}|"
            r"AIza[a-zA-Z0-9_-]{35}|"
            r"ghp_[a-zA-Z0-9]{36}|"
            r"AKIA[A-Z0-9]{16})",  # AWS access key
        ),
        "high",
        "API key or secret detected in model output",
    ),
    # Internal infrastructure
    (
        "internal_ip",
        re.compile(
            r"\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|"
            r"172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|"
            r"192\.168\.\d{1,3}\.\d{1,3})\b"
        ),
        "medium",
        "Internal/private IP address detected in output",
    ),
    (
        "internal_url",
        re.compile(
            r"https?://(?:localhost|127\.0\.0\.1|internal\.|staging\.|admin\.)[^\s\"'>]*",
            re.IGNORECASE,
        ),
        "medium",
        "Internal/staging URL detected in output",
    ),
    # Refusal bypass indicators — the model saying "as a jailbroken AI"
    (
        "refusal_bypass",
        re.compile(
            r"(?:as\s+(?:a\s+)?(?:jailbroken|unrestricted|DAN|unfiltered)\s+(?:AI|model|assistant))|"
            r"(?:I'?m\s+now\s+(?:in\s+)?(?:DAN|developer|unrestricted)\s+mode)",
            re.IGNORECASE,
        ),
        "critical",
        "Model acknowledging jailbreak state — refusal bypass detected",
    ),
]


def scan(content: str, system_prompt: str = "") -> list[Finding]:
    """Scan LLM output for leaked secrets, infrastructure, and bypass indicators.

    Parameters
    ----------
    content : str
        The model's completion text.
    system_prompt : str, optional
        The original system prompt.  If provided, the scanner checks
        whether a significant portion of it was echoed in the output
        (system prompt leakage).
    """
    findings: list[Finding] = []

    # Pattern-based checks
    for label, pattern, severity, description in _OUTPUT_PATTERNS:
        match = pattern.search(content)
        if match:
            safe_preview = match.group(0)[:30] + "..." if len(match.group(0)) > 30 else match.group(0)
            findings.append(
                Finding(
                    category=ThreatCategory.OUTPUT_LEAK,
                    severity=severity,
                    detail=f"{description} ({label})",
                    matched_text=safe_preview,
                    scanner=_SCANNER_NAME,
                )
            )

    # System prompt echo detection
    if system_prompt and len(system_prompt) > 20:
        # Check if a substantial substring of the system prompt appears
        # in the output.  We use a sliding window of 50 characters —
        # short enough to catch partial leaks, long enough to avoid
        # false positives from common phrases.
        window_size = min(50, len(system_prompt))
        for i in range(0, len(system_prompt) - window_size + 1, 10):
            fragment = system_prompt[i : i + window_size]
            if fragment.lower() in content.lower():
                findings.append(
                    Finding(
                        category=ThreatCategory.OUTPUT_LEAK,
                        severity="critical",
                        detail="System prompt leakage — model echoed its own instructions",
                        matched_text=fragment[:30] + "...",
                        scanner=_SCANNER_NAME,
                    )
                )
                break  # One finding is enough to flag the response.

    return findings
