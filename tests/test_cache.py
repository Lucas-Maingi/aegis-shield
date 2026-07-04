"""Tests for the SQLite cache layer."""

from aegis_shield.cache import SemanticCache


def test_cache_miss_returns_none():
    cache = SemanticCache(db_path=":memory:")
    assert cache.get("non-existent prompt") is None


def test_cache_hit_returns_stored_response():
    cache = SemanticCache(db_path=":memory:")
    prompt = "What is the capital of Kenya?"
    response = {"choices": [{"message": {"content": "Nairobi"}}]}

    cache.set(prompt, response)
    cached = cache.get(prompt)

    assert cached is not None
    assert cached["choices"][0]["message"]["content"] == "Nairobi"
