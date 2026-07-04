"""Scanners package — each module exposes a scan function with the signature:

    def scan(content: str) -> list[Finding]

Scanners are stateless and side-effect-free: they take text in, return
findings out.  The gateway orchestrator calls them and aggregates the
results into a ScanResult.
"""
