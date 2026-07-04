"""FastAPI application — the gateway's HTTP surface and proxy logic.

This module acts as the core reverse proxy. It intercepts standard OpenAI-compatible
chat-completions requests, applies rate limits, runs inbound security scans,
checks the semantic cache, forwards requests to the upstream provider, and runs
outbound compliance scans before returning the completion.
"""

from __future__ import annotations

import hashlib
import time
from contextlib import asynccontextmanager

import httpx
from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse

from aegis_shield import __version__
from aegis_shield.cache import SemanticCache
from aegis_shield.config import settings
from aegis_shield.gateway import scan_completion, scan_prompt
from aegis_shield.limiter import RateLimiter
from aegis_shield.models import (
    Finding,
    HealthResponse,
    ProxyRequest,
    ScanResult,
    ThreatCategory,
    Verdict,
)
from aegis_shield.store import AuditStore

# ── Lifespan & Dependency Management ─────────────────────────────────────

_store: AuditStore | None = None
_limiter: RateLimiter | None = None
_cache: SemanticCache | None = None
_http_client: httpx.AsyncClient | None = None


def get_store() -> AuditStore:
    assert _store is not None, "Store not initialised"
    return _store


def get_limiter() -> RateLimiter:
    assert _limiter is not None, "Limiter not initialised"
    return _limiter


def get_cache() -> SemanticCache:
    assert _cache is not None, "Cache not initialised"
    return _cache


def get_http_client() -> httpx.AsyncClient:
    assert _http_client is not None, "HTTP client not initialised"
    return _http_client


@asynccontextmanager
async def lifespan(app: FastAPI):
    global _store, _limiter, _cache, _http_client
    _store = AuditStore()
    _limiter = RateLimiter()
    _cache = SemanticCache()

    # Connection pooling for high performance
    _http_client = httpx.AsyncClient(
        timeout=settings.upstream_timeout_seconds,
        limits=httpx.Limits(max_keepalive_connections=50, max_connections=100)
    )
    yield
    await _http_client.aclose()


# ── App Definition ───────────────────────────────────────────────────────

app = FastAPI(
    title=settings.app_name,
    version=__version__,
    description="LLM Security & Compliance Gateway",
    lifespan=lifespan,
)


# ── Helper functions ─────────────────────────────────────────────────────

def _hash_api_key(auth_header: str | None) -> str:
    """Safely hash the client's API key for identification without logging raw secrets."""
    if not auth_header:
        return "anonymous"
    # Extract token from "Bearer <token>"
    parts = auth_header.split()
    token = parts[1] if len(parts) > 1 else auth_header
    return hashlib.sha256(token.encode()).hexdigest()[:8]


# ── Endpoints ────────────────────────────────────────────────────────────

@app.get("/health", response_model=HealthResponse, tags=["ops"])
async def health():
    """Liveness / readiness probe."""
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


@app.post("/v1/chat/completions", tags=["proxy"])
async def chat_completions(
    proxy_req: ProxyRequest,
    request: Request,
    store: AuditStore = Depends(get_store),
    limiter: RateLimiter = Depends(get_limiter),
    cache: SemanticCache = Depends(get_cache),
    http_client: httpx.AsyncClient = Depends(get_http_client),
):
    """Proxy endpoint mimicking OpenAI's chat/completions API structure."""
    start_time = time.perf_counter()
    client_ip = request.client.host if request.client else "unknown"

    # Extract API Key from headers (if provided) to identify user/token bucket
    auth_header = request.headers.get("Authorization")
    api_key_hash = _hash_api_key(auth_header)

    # 1. Rate Limiting
    if not limiter.check_limit(api_key_hash):
        scan_result = ScanResult(
            client_ip=client_ip,
            api_key_hash=api_key_hash,
            model_requested=proxy_req.model,
            verdict=Verdict.BLOCK,
            findings=[
                Finding(
                    category=ThreatCategory.RATE_LIMIT,
                    severity="high",
                    detail="Rate limit exceeded",
                    scanner="gateway"
                )
            ]
        )
        scan_result.total_latency_ms = int((time.perf_counter() - start_time) * 1000)
        store.log(scan_result)
        return JSONResponse(
            status_code=429,
            content={"error": {"message": "Rate limit exceeded. Try again in a moment.", "type": "rate_limit_error"}}
        )

    # 2. Inbound Security Scan (PII & Injection)
    scan_result = scan_prompt(proxy_req, client_ip=client_ip, api_key_hash=api_key_hash)

    # If blocked by inbound scan, audit and reject
    if scan_result.blocked:
        scan_result.total_latency_ms = int((time.perf_counter() - start_time) * 1000)
        store.log(scan_result)
        return JSONResponse(
            status_code=400,
            content={
                "error": {
                    "message": f"Request blocked by Aegis Shield: {scan_result.findings[0].detail}",
                    "type": "security_policy_violation",
                    "request_id": scan_result.request_id
                }
            }
        )

    # 3. Cache lookup (exact match)
    user_prompt = proxy_req.all_content()
    cached_response = cache.get(user_prompt)
    if cached_response is not None:
        scan_result.total_latency_ms = int((time.perf_counter() - start_time) * 1000)
        # Log cache hits with zero upstream latency
        store.log(scan_result)
        return cached_response

    # 4. Proxy request to upstream LLM
    upstream_url = f"{settings.upstream_base_url.rstrip('/')}/chat/completions"

    headers = {}
    if auth_header:
        headers["Authorization"] = auth_header
    else:
        # Fallback to configured key if client did not supply one
        if settings.upstream_api_key:
            headers["Authorization"] = f"Bearer {settings.upstream_api_key}"

    headers["Content-Type"] = "application/json"

    # Forward identical parameters
    upstream_payload = proxy_req.model_dump(exclude_none=True)

    upstream_start = time.perf_counter()
    try:
        resp = await http_client.post(
            upstream_url,
            json=upstream_payload,
            headers=headers
        )
    except httpx.RequestError as e:
        raise HTTPException(
            status_code=502,
            detail=f"Failed to communicate with upstream LLM provider: {str(e)}"
        ) from e
    upstream_latency_ms = int((time.perf_counter() - upstream_start) * 1000)

    if resp.status_code != 200:
        return JSONResponse(
            status_code=resp.status_code,
            content=resp.json() if resp.headers.get("content-type") == "application/json" else {"error": resp.text}
        )

    response_json = resp.json()

    # Extract completion text to run outbound scan
    choices = response_json.get("choices", [])
    completion_text = choices[0].get("message", {}).get("content", "") if choices else ""

    # 5. Outbound Compliance Scan (Leaks & Refusal Bypasses)
    scan_result = scan_completion(
        scan_result,
        completion_text,
        system_prompt=proxy_req.system_prompt(),
        upstream_latency_ms=upstream_latency_ms,
        start_time=start_time
    )

    # Log the complete scan result to SQLite audit log
    store.log(scan_result)

    # If blocked by outbound scan, intercept and reject
    if scan_result.blocked:
        return JSONResponse(
            status_code=400,
            content={
                "error": {
                    "message": "Response blocked by Aegis Shield output validation guidelines.",
                    "type": "security_policy_violation",
                    "request_id": scan_result.request_id
                }
            }
        )

    # 6. Save clean response to cache
    cache.set(user_prompt, response_json)

    return response_json
