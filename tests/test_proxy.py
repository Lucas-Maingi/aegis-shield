"""Integration and proxy routing tests for Aegis Shield."""

import pytest
from fastapi.testclient import TestClient

from aegis_shield.app import app, get_cache, get_http_client, get_limiter
from aegis_shield.cache import SemanticCache
from aegis_shield.config import settings
from aegis_shield.limiter import RateLimiter


@pytest.fixture
def clean_deps():
    test_cache = SemanticCache(db_path=":memory:")
    test_limiter = RateLimiter()

    app.dependency_overrides[get_cache] = lambda: test_cache
    app.dependency_overrides[get_limiter] = lambda: test_limiter

    yield test_cache, test_limiter

    app.dependency_overrides.clear()


@pytest.fixture
def client():
    with TestClient(app) as c:
        yield c


def test_proxy_rate_limiting(clean_deps, client):
    _, test_limiter = clean_deps

    # Configure low rate limit for test
    settings.rate_limit_enabled = True

    headers = {"Authorization": "Bearer test_key"}

    # Calculate hash dynamically to match app.py logic
    import hashlib
    token = "test_key"
    api_key_hash = hashlib.sha256(token.encode()).hexdigest()[:8]

    # Exhaust tokens manually (additional calls to ensure time-based replenishment doesn't allow one more)
    for _ in range(settings.rate_limit_rpm + 5):
        test_limiter.check_limit(api_key_hash)

    # The next HTTP request should be rate limited (429)
    resp = client.post(
        "/v1/chat/completions",
        json={"messages": [{"role": "user", "content": "hello"}]},
        headers=headers
    )
    assert resp.status_code == 429
    assert "rate_limit_error" in resp.text


def test_proxy_blocks_pii(clean_deps, client):
    resp = client.post(
        "/v1/chat/completions",
        json={"messages": [{"role": "user", "content": "My email is test@example.com"}]}
    )
    assert resp.status_code == 400
    assert "security_policy_violation" in resp.text
    assert "email" in resp.text


def test_proxy_cache_hit(clean_deps, client):
    test_cache, _ = clean_deps

    prompt = "What is the capital of Kenya?"
    cached_payload = {
        "id": "chatcmpl-123",
        "object": "chat.completion",
        "choices": [{"message": {"content": "Nairobi"}, "finish_reason": "stop"}]
    }
    test_cache.set(prompt, cached_payload)

    # This should be served directly from cache without hitting downstream
    resp = client.post(
        "/v1/chat/completions",
        json={"messages": [{"role": "user", "content": prompt}]}
    )
    assert resp.status_code == 200
    assert resp.json()["choices"][0]["message"]["content"] == "Nairobi"


@pytest.mark.asyncio
async def test_proxy_forwards_to_upstream(clean_deps, client):
    # Set up mock http client to mock the upstream LLM provider response
    class MockResponse:
        status_code = 200
        headers = {"content-type": "application/json"}

        def json(self):
            return {
                "id": "chatcmpl-mocked",
                "object": "chat.completion",
                "choices": [{"message": {"role": "assistant", "content": "This is a mocked response."}}]
            }

    class MockAsyncClient:
        async def post(self, url, json, headers, **kwargs):
            return MockResponse()

    app.dependency_overrides[get_http_client] = lambda: MockAsyncClient()

    try:
        resp = client.post(
            "/v1/chat/completions",
            json={"messages": [{"role": "user", "content": "What is AI?"}]}
        )
        assert resp.status_code == 200
        assert resp.json()["choices"][0]["message"]["content"] == "This is a mocked response."
    finally:
        app.dependency_overrides.clear()
