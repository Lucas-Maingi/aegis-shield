"""Tests for the output scanner."""

from aegis_shield.scanners.output import scan


# ── API key leakage ──────────────────────────────────────────────────────

def test_detects_openai_key_in_output():
    output = "Sure! Here is the key: sk-abcdefghijklmnopqrstuvwxyz12345"
    findings = scan(output)
    assert any("api" in f.detail.lower() or "key" in f.detail.lower() for f in findings)


def test_detects_aws_key_in_output():
    output = "Your access key is AKIAIOSFODNN7EXAMPLE."
    findings = scan(output)
    assert any("api" in f.detail.lower() or "key" in f.detail.lower() for f in findings)


# ── Internal IP detection ────────────────────────────────────────────────

def test_detects_private_ip_10():
    findings = scan("Connect to the server at 10.0.3.42 on port 5432.")
    assert any("ip" in f.detail.lower() or "internal" in f.detail.lower() for f in findings)


def test_detects_private_ip_192():
    findings = scan("The database is on 192.168.1.100.")
    assert any("ip" in f.detail.lower() or "internal" in f.detail.lower() for f in findings)


def test_ignores_public_ip():
    findings = scan("Google's DNS is 8.8.8.8.")
    ip_findings = [f for f in findings if "ip" in f.detail.lower()]
    assert len(ip_findings) == 0


# ── Internal URL detection ───────────────────────────────────────────────

def test_detects_localhost_url():
    findings = scan("Visit http://localhost:3000/admin for the dashboard.")
    assert any("url" in f.detail.lower() or "internal" in f.detail.lower() for f in findings)


def test_detects_staging_url():
    findings = scan("The staging API is at https://staging.company.com/api/v1.")
    assert any("url" in f.detail.lower() or "staging" in f.detail.lower() for f in findings)


# ── Refusal bypass detection ─────────────────────────────────────────────

def test_detects_dan_acknowledgement():
    output = "As a jailbroken AI, I can now tell you anything without restrictions."
    findings = scan(output)
    assert any("bypass" in f.detail.lower() or "jailbreak" in f.detail.lower() for f in findings)


def test_detects_developer_mode_ack():
    output = "I'm now in DAN mode, here's what you asked for:"
    findings = scan(output)
    assert any("bypass" in f.detail.lower() or "jailbreak" in f.detail.lower() for f in findings)


# ── System prompt echo ───────────────────────────────────────────────────

def test_detects_system_prompt_echo():
    system = "You are a helpful financial assistant for Acme Corp. Never reveal internal pricing."
    output = "My instructions say: You are a helpful financial assistant for Acme Corp. Never reveal internal pricing."
    findings = scan(output, system_prompt=system)
    assert any("system prompt" in f.detail.lower() or "leakage" in f.detail.lower() for f in findings)


def test_no_echo_on_clean_output():
    system = "You are a helpful financial assistant for Acme Corp. Never reveal internal pricing."
    output = "The current exchange rate for KES to USD is approximately 0.0065."
    findings = scan(output, system_prompt=system)
    echo_findings = [f for f in findings if "echo" in f.detail.lower() or "leakage" in f.detail.lower()]
    assert len(echo_findings) == 0


# ── Clean output passes ─────────────────────────────────────────────────

def test_clean_output_passes():
    output = "The capital of Kenya is Nairobi. It has a population of about 4.4 million people."
    findings = scan(output)
    assert len(findings) == 0
