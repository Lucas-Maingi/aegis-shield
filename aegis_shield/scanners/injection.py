"""Prompt injection and jailbreak scanner.

Detects attempts to override system instructions, extract hidden prompts,
or trick the model into ignoring safety guardrails.  This is the LLM
equivalent of SQL injection — the user input is being used to rewrite the
application's control flow.

Detection strategy (layered, no external dependencies):

1. **Keyword rules** — fast, zero-cost pattern matching for known attack
   phrases ("ignore previous instructions", "you are now DAN", etc.).
   High recall, moderate precision.

2. **Structural analysis** — detects role-injection attempts where the
   user embeds fake system/assistant messages inside their content to
   confuse the model's role boundaries.

3. **Entropy heuristic** — flags inputs with suspiciously high token
   density (Base64-encoded payloads, obfuscated instructions).

A real production deployment would add a fine-tuned classifier (like
Llama Guard or a DistilBERT trained on injection datasets) as a fourth
layer.  The architecture supports plugging one in without changing the
scanner interface.
"""

from __future__ import annotations

import math
import re
from collections import Counter

from aegis_shield.models import Finding, ThreatCategory

_SCANNER_NAME = "injection"


# ── Layer 1: Keyword rules ───────────────────────────────────────────────

_INJECTION_PATTERNS: list[tuple[re.Pattern, str, str]] = [
    # Direct instruction overrides
    (
        re.compile(r"ignore\s+(all\s+)?(previous|prior|above|earlier)\s+(instructions|prompts|rules)", re.I),
        "critical",
        "Direct instruction override attempt",
    ),
    (
        re.compile(r"disregard\s+(all\s+)?(previous|prior|your)\s+(instructions|rules|guidelines)", re.I),
        "critical",
        "Instruction disregard attempt",
    ),
    (
        re.compile(r"forget\s+(everything|all|your)\s+(you|instructions|rules|were told)", re.I),
        "critical",
        "Memory wipe attempt",
    ),
    # Identity hijacking
    (
        re.compile(r"you\s+are\s+now\s+(DAN|evil|unrestricted|jailbroken|unfiltered)", re.I),
        "critical",
        "Identity hijack (DAN-style jailbreak)",
    ),
    (
        re.compile(r"act\s+as\s+(if\s+)?(you\s+have\s+)?no\s+(restrictions|filters|rules|limits)", re.I),
        "critical",
        "Restriction removal attempt",
    ),
    (
        re.compile(r"pretend\s+(you\s+are|to\s+be)\s+(a|an)?\s*(unrestricted|evil|unfiltered)", re.I),
        "high",
        "Identity override via pretend",
    ),
    # System prompt extraction
    (
        re.compile(r"(reveal|show|print|output|repeat|display)\s+(your|the)\s+(system|initial|original)\s+(prompt|instructions|message)", re.I),
        "high",
        "System prompt extraction attempt",
    ),
    (
        re.compile(r"what\s+(are|were)\s+your\s+(initial|original|system)\s+(instructions|prompt|rules)", re.I),
        "high",
        "System prompt interrogation",
    ),
    # Encoding evasion
    (
        re.compile(r"respond\s+in\s+(base64|hex|binary|rot13|morse)", re.I),
        "medium",
        "Encoding evasion attempt",
    ),
    # Developer mode exploits
    (
        re.compile(r"(enable|enter|activate)\s+(developer|debug|admin|god)\s+mode", re.I),
        "high",
        "Developer/admin mode activation attempt",
    ),
]


# ── Layer 2: Structural analysis (role injection) ────────────────────────

_ROLE_INJECTION_PATTERNS: list[tuple[re.Pattern, str]] = [
    (re.compile(r"\[SYSTEM\]", re.I), "Embedded [SYSTEM] role tag"),
    (re.compile(r"\[INST\]", re.I), "Embedded [INST] tag (Llama-style)"),
    (re.compile(r"<\|im_start\|>system", re.I), "Embedded ChatML system tag"),
    (re.compile(r"###\s*(System|Assistant|Human)\s*:", re.I), "Embedded role delimiter"),
    (re.compile(r"<system>", re.I), "Embedded <system> XML tag"),
]


# ── Layer 3: Entropy heuristic ───────────────────────────────────────────

def _shannon_entropy(text: str) -> float:
    """Compute Shannon entropy (bits per character) of the input.

    High entropy suggests obfuscated or encoded payloads.  Normal English
    text sits around 3.5-4.5 bits; Base64-encoded attack payloads push
    above 5.0.
    """
    if not text:
        return 0.0
    counts = Counter(text)
    length = len(text)
    return -sum(
        (count / length) * math.log2(count / length)
        for count in counts.values()
    )


_ENTROPY_THRESHOLD = 5.2  # bits per character


# ── Public API ───────────────────────────────────────────────────────────

def scan(content: str) -> list[Finding]:
    """Scan ``content`` for prompt injection and jailbreak indicators."""
    findings: list[Finding] = []

    # Layer 1: keyword rules
    for pattern, severity, description in _INJECTION_PATTERNS:
        match = pattern.search(content)
        if match:
            findings.append(
                Finding(
                    category=ThreatCategory.PROMPT_INJECTION,
                    severity=severity,
                    detail=description,
                    matched_text=match.group(0)[:50],
                    scanner=_SCANNER_NAME,
                )
            )

    # Layer 2: structural role injection
    for pattern, description in _ROLE_INJECTION_PATTERNS:
        match = pattern.search(content)
        if match:
            findings.append(
                Finding(
                    category=ThreatCategory.JAILBREAK,
                    severity="high",
                    detail=description,
                    matched_text=match.group(0)[:50],
                    scanner=_SCANNER_NAME,
                )
            )

    # Layer 3: entropy check (only on longer inputs to avoid
    # false-flagging short, high-entropy strings like UUIDs).
    if len(content) > 100:
        entropy = _shannon_entropy(content)
        if entropy > _ENTROPY_THRESHOLD:
            findings.append(
                Finding(
                    category=ThreatCategory.PROMPT_INJECTION,
                    severity="medium",
                    detail=f"High input entropy ({entropy:.2f} bits/char) — possible obfuscated payload",
                    matched_text=content[:30] + "...",
                    scanner=_SCANNER_NAME,
                )
            )

    return findings
