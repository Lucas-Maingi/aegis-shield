"""Tests for the PII scanner."""

from aegis_shield.scanners.pii import scan, _passes_luhn


# ── Email detection ──────────────────────────────────────────────────────

def test_detects_email():
    findings = scan("Please contact me at lucas@example.com for details.")
    assert len(findings) >= 1
    assert any("email" in f.detail.lower() for f in findings)


def test_ignores_text_without_email():
    findings = scan("No contact info here, just a regular sentence.")
    email_findings = [f for f in findings if "email" in f.detail.lower()]
    assert len(email_findings) == 0


# ── Phone detection ──────────────────────────────────────────────────────

def test_detects_international_phone():
    findings = scan("Call me at +254 712 345 678 tomorrow.")
    assert any("phone" in f.detail.lower() for f in findings)


def test_detects_us_phone():
    findings = scan("My number is +1-555-123-4567.")
    assert any("phone" in f.detail.lower() for f in findings)


# ── Credit card detection ────────────────────────────────────────────────

def test_detects_valid_visa():
    # 4111 1111 1111 1111 is the standard Visa test card (passes Luhn).
    findings = scan("My card is 4111111111111111, please charge it.")
    assert any("credit" in f.detail.lower() or "card" in f.detail.lower() for f in findings)


def test_ignores_random_digits():
    # 16 random digits that fail Luhn should not trigger.
    findings = scan("Reference number: 1234567890123456.")
    card_findings = [f for f in findings if "card" in f.detail.lower()]
    assert len(card_findings) == 0


def test_luhn_valid():
    assert _passes_luhn("4111111111111111") is True


def test_luhn_invalid():
    assert _passes_luhn("4111111111111112") is False


# ── SSN detection ────────────────────────────────────────────────────────

def test_detects_ssn():
    findings = scan("SSN: 123-45-6789")
    assert any("social" in f.detail.lower() or "ssn" in f.detail.lower() for f in findings)


# ── API key detection ────────────────────────────────────────────────────

def test_detects_openai_key():
    findings = scan("Use this key: sk-abcdefghijklmnopqrstuvwxyz12345")
    assert any("api" in f.detail.lower() or "key" in f.detail.lower() for f in findings)


def test_detects_github_pat():
    findings = scan("Token: ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij")
    assert any("api" in f.detail.lower() or "key" in f.detail.lower() or "token" in f.detail.lower() for f in findings)


def test_detects_bearer_token():
    findings = scan("Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.payload.signature")
    assert any("token" in f.detail.lower() or "bearer" in f.detail.lower() for f in findings)


# ── Safe preview truncation ──────────────────────────────────────────────

def test_matched_text_is_truncated():
    findings = scan("Email me at longusername@example.com please.")
    email_findings = [f for f in findings if "email" in f.detail.lower()]
    assert len(email_findings) >= 1
    # The matched_text should be truncated, not the full email.
    assert "***" in email_findings[0].matched_text


# ── Multiple findings in one scan ────────────────────────────────────────

def test_multiple_pii_types_detected():
    text = (
        "Contact lucas@example.com or call +254 712 345 678. "
        "Card: 4111111111111111. SSN: 123-45-6789."
    )
    findings = scan(text)
    categories = {f.detail for f in findings}
    # Should find at least email, phone, card, and SSN.
    assert len(findings) >= 4
