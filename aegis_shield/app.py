"""FastAPI application — the gateway's HTTP surface.

This module wires together config, scanners, and the audit store into a
running API.  The proxy endpoint is added in a later commit; this first
cut exposes health and readiness checks so the container can be deployed
and monitored immediately.
"""

from __future__ import annotations

from contextlib import asynccontextmanager

from fastapi import FastAPI

from aegis_shield import __version__
from aegis_shield.config import settings
from aegis_shield.models import HealthResponse
from aegis_shield.store import AuditStore

# ── Lifespan ─────────────────────────────────────────────────────────────

_store: AuditStore | None = None


def get_store() -> AuditStore:
    """Return the module-level audit store (created at startup)."""
    assert _store is not None, "Store not initialised — app lifespan not started."
    return _store


@asynccontextmanager
async def lifespan(app: FastAPI):
    global _store
    _store = AuditStore()
    yield
    # SQLite connection is lightweight; no explicit teardown needed.


# ── App ──────────────────────────────────────────────────────────────────

app = FastAPI(
    title=settings.app_name,
    version=__version__,
    description="LLM Security & Compliance Gateway",
    lifespan=lifespan,
)


# ── Routes ───────────────────────────────────────────────────────────────

@app.get("/health", response_model=HealthResponse, tags=["ops"])
async def health():
    """Liveness / readiness probe for container orchestrators."""
    active_scanners = []
    if settings.pii_scan_enabled:
        active_scanners.append("pii")
    if settings.injection_scan_enabled:
        active_scanners.append("injection")
    if settings.output_scan_enabled:
        active_scanners.append("output")

    return HealthResponse(
        status="ok",
        version=__version__,
        scanners_active=active_scanners,
    )
