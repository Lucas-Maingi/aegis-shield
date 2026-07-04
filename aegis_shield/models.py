"""Domain models shared across the gateway.

Every request that passes through Aegis Shield is represented as a ScanResult
before being forwarded (or blocked).  These models are the contract between
the scanners, the proxy middleware, and the persistence layer.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Optional

from pydantic import BaseModel, Field


# ── Enums ────────────────────────────────────────────────────────────────

class Verdict(str, Enum):
    """The gateway's final decision on a request."""
    ALLOW = "allow"
    BLOCK = "block"
    WARN = "warn"  # allowed through but flagged for review


class ThreatCategory(str, Enum):
    """Categories of threats the scanners can detect."""
    PII_LEAK = "pii_leak"
    PROMPT_INJECTION = "prompt_injection"
    JAILBREAK = "jailbreak"
    OUTPUT_LEAK = "output_leak"
    RATE_LIMIT = "rate_limit"
    NONE = "none"


# ── Scanner findings ─────────────────────────────────────────────────────

class Finding(BaseModel):
    """A single issue detected by a scanner."""
    category: ThreatCategory
    severity: str = "high"  # low / medium / high / critical
    detail: str = ""
    matched_text: str = ""
    scanner: str = ""  # which scanner produced this finding


# ── Request / Response wrappers ──────────────────────────────────────────

class ScanResult(BaseModel):
    """The aggregate result of all scanners running on one gateway transit."""
    request_id: str = Field(default_factory=lambda: uuid.uuid4().hex[:12])
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    # Inbound (prompt side)
    client_ip: str = ""
    api_key_hash: str = ""  # first 8 chars of sha256 — enough to identify, not to leak
    model_requested: str = ""
    prompt_tokens_est: int = 0

    # Scanner verdicts
    verdict: Verdict = Verdict.ALLOW
    findings: list[Finding] = Field(default_factory=list)

    # Outbound (completion side) — populated after the upstream responds
    completion_tokens_est: int = 0
    upstream_latency_ms: int = 0
    total_latency_ms: int = 0

    # Cost tracking (populated if token counts are available)
    estimated_cost_usd: float = 0.0

    @property
    def blocked(self) -> bool:
        return self.verdict == Verdict.BLOCK


class HealthResponse(BaseModel):
    """GET /health response."""
    status: str = "ok"
    version: str = ""
    scanners_active: list[str] = Field(default_factory=list)


# ── Proxy request schema ────────────────────────────────────────────────

class ProxyRequest(BaseModel):
    """The shape of the JSON body a client sends to the gateway.

    Mirrors the OpenAI chat-completions request shape so existing client
    SDKs work by just pointing their base_url at Aegis Shield.
    """
    model: str = "gpt-4o-mini"
    messages: list[dict] = Field(default_factory=list)
    temperature: Optional[float] = None
    max_tokens: Optional[int] = None
    stream: bool = False

    def system_prompt(self) -> str:
        """Extract the system message content, if any."""
        for msg in self.messages:
            if msg.get("role") == "system":
                return msg.get("content", "")
        return ""

    def user_messages(self) -> list[str]:
        """Extract all user-role message contents."""
        return [
            msg.get("content", "")
            for msg in self.messages
            if msg.get("role") == "user"
        ]

    def all_content(self) -> str:
        """Concatenate every message's content for full-text scanning."""
        return "\n".join(msg.get("content", "") for msg in self.messages)
