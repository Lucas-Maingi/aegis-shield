"""Smoke tests for the FastAPI app scaffold."""

from fastapi.testclient import TestClient

from aegis_shield.app import app

client = TestClient(app)


def test_health_returns_ok():
    resp = client.get("/health")
    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == "ok"
    assert "version" in body


def test_health_lists_active_scanners():
    resp = client.get("/health")
    body = resp.json()
    # Default config enables all three scanners.
    assert "pii" in body["scanners_active"]
    assert "injection" in body["scanners_active"]
    assert "output" in body["scanners_active"]
