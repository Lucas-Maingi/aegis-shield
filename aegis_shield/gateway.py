"""Gateway coordinator integrating scanners and deciding when to block/allow.

This module coordinates running all enabled scanners (PII, prompt injection)
on the inbound request, evaluating the threat level, and running the output
scanner on the outbound completion.
"""

from __future__ import annotations

import time
from typing import Optional

from aegis_shield.config import settings
from aegis_shield.models import ScanResult, Verdict, Finding, ThreatCategory, ProxyRequest
from aegis_shield.scanners import pii, injection, output


def scan_prompt(request: ProxyRequest, client_ip: str = "", api_key_hash: str = "") -> ScanResult:
    """Scan the incoming user messages and decide whether to block or allow.

    Aggregates findings from the PII and Prompt Injection scanners if enabled.
    """
    result = ScanResult(
        client_ip=client_ip,
        api_key_hash=api_key_hash,
        model_requested=request.model,
    )

    all_text = request.all_content()
    # Estimate prompt tokens roughly (1 token ~ 4 chars) if not parsed.
    result.prompt_tokens_est = len(all_text) // 4

    findings: list[Finding] = []

    # 1. Run PII Scanner if enabled
    if settings.pii_scan_enabled:
        try:
            findings.extend(pii.scan(all_text))
        except Exception as e:
            # Scanners should never crash the proxy; log and proceed.
            # In production, we'd log this to stderr or a logging module.
            pass

    # 2. Run Prompt Injection Scanner if enabled
    if settings.injection_scan_enabled:
        try:
            findings.extend(injection.scan(all_text))
        except Exception as e:
            pass

    result.findings = findings

    # Determine final verdict based on findings
    if findings:
        # Block if there is any HIGH or CRITICAL severity threat
        has_block_threat = any(f.severity in ("high", "critical") for f in findings)
        if has_block_threat:
            result.verdict = Verdict.BLOCK
        else:
            result.verdict = Verdict.WARN
    else:
        result.verdict = Verdict.ALLOW

    return result


def scan_completion(
    result: ScanResult, 
    completion_text: str, 
    system_prompt: str = "", 
    upstream_latency_ms: int = 0,
    start_time: float = 0.0
) -> ScanResult:
    """Scan the outbound completion before returning it to the client.

    Modifies the ScanResult in-place with output scan findings and timing data.
    """
    result.upstream_latency_ms = upstream_latency_ms
    result.completion_tokens_est = len(completion_text) // 4
    
    if start_time > 0.0:
        result.total_latency_ms = int((time.perf_counter() - start_time) * 1000)

    # Calculate estimated cost (synthetic pricing for demonstration)
    # $0.0015 / 1k prompt tokens, $0.0020 / 1k completion tokens
    prompt_cost = (result.prompt_tokens_est / 1000) * 0.0015
    completion_cost = (result.completion_tokens_est / 1000) * 0.0020
    result.estimated_cost_usd = prompt_cost + completion_cost

    # Run Output Scanner if enabled
    if settings.output_scan_enabled and result.verdict != Verdict.BLOCK:
        try:
            output_findings = output.scan(completion_text, system_prompt=system_prompt)
            if output_findings:
                result.findings.extend(output_findings)
                # Block the completion if it contains high or critical outputs (e.g. system leaks, api keys)
                if any(f.severity in ("high", "critical") for f in output_findings):
                    result.verdict = Verdict.BLOCK
        except Exception as e:
            pass

    return result
