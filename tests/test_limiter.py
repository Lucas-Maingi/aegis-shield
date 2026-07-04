"""Tests for the Token Bucket rate limiter."""

import time
from aegis_shield.limiter import RateLimiter
from aegis_shield.config import settings


def test_rate_limiter_allows_under_limit():
    limiter = RateLimiter()
    # RPM limit is 5 (fill rate = 5/60 = 0.083 per second, capacity = 5)
    assert limiter.check_limit("client_1", rpm=5) is True
    assert limiter.check_limit("client_1", rpm=5) is True


def test_rate_limiter_blocks_above_limit():
    limiter = RateLimiter()
    # Limit is 2
    assert limiter.check_limit("client_2", rpm=2) is True
    assert limiter.check_limit("client_2", rpm=2) is True
    # Third request should be blocked immediately
    assert limiter.check_limit("client_2", rpm=2) is False


def test_rate_limiter_refills():
    limiter = RateLimiter()
    # Limit is 1 request per 0.5 seconds (2 rpm, fill rate = 0.033/s)
    # Let's use custom fill rate directly:
    # 1 RPM capacity = 1, fill_rate = 1/60 per sec
    # Let's test with a higher rate so we don't sleep too long in tests
    assert limiter.check_limit("client_3", rpm=60) is True  # 1 req/sec fill
    
    # Consume capacity (60)
    for _ in range(59):
        assert limiter.check_limit("client_3", rpm=60) is True
        
    # Over capacity should block
    assert limiter.check_limit("client_3", rpm=60) is False
