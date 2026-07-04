"""SQLite persistence for scan results and blocked-request audit log.

Every request that passes through the gateway — allowed or blocked — gets a
row in the ``scan_log`` table.  This is the data source for the Streamlit
dashboard and for compliance auditing ("prove that no PII left our network
in Q3").

SQLite is deliberate for v1: zero infrastructure, single-file backup, and
more than enough throughput for a gateway that's bottlenecked on upstream
LLM latency anyway.  Swap to Postgres via the same interface if needed.
"""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path

from aegis_shield.config import settings
from aegis_shield.models import ScanResult


class AuditStore:
    """Append-only audit log backed by SQLite."""

    def __init__(self, db_path: str | None = None):
        self._path = db_path or settings.db_path
        self._conn = sqlite3.connect(self._path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._migrate()

    def _migrate(self) -> None:
        self._conn.execute("""
            CREATE TABLE IF NOT EXISTS scan_log (
                request_id     TEXT PRIMARY KEY,
                timestamp      TEXT NOT NULL,
                client_ip      TEXT,
                api_key_hash   TEXT,
                model          TEXT,
                verdict        TEXT NOT NULL,
                findings_json  TEXT,
                prompt_tokens  INTEGER DEFAULT 0,
                completion_tokens INTEGER DEFAULT 0,
                upstream_latency_ms INTEGER DEFAULT 0,
                total_latency_ms    INTEGER DEFAULT 0,
                estimated_cost_usd  REAL DEFAULT 0.0
            )
        """)
        self._conn.commit()

    def log(self, result: ScanResult) -> None:
        """Persist a scan result."""
        self._conn.execute(
            """
            INSERT OR REPLACE INTO scan_log
                (request_id, timestamp, client_ip, api_key_hash, model,
                 verdict, findings_json, prompt_tokens, completion_tokens,
                 upstream_latency_ms, total_latency_ms, estimated_cost_usd)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                result.request_id,
                result.timestamp.isoformat(),
                result.client_ip,
                result.api_key_hash,
                result.model_requested,
                result.verdict.value,
                json.dumps([f.model_dump() for f in result.findings]),
                result.prompt_tokens_est,
                result.completion_tokens_est,
                result.upstream_latency_ms,
                result.total_latency_ms,
                result.estimated_cost_usd,
            ),
        )
        self._conn.commit()

    def recent(self, limit: int = 100) -> list[dict]:
        """Return the most recent scan log entries as dicts."""
        cursor = self._conn.execute(
            "SELECT * FROM scan_log ORDER BY timestamp DESC LIMIT ?",
            (limit,),
        )
        return [dict(row) for row in cursor.fetchall()]

    def count_by_verdict(self) -> dict[str, int]:
        """Aggregate counts grouped by verdict."""
        cursor = self._conn.execute(
            "SELECT verdict, COUNT(*) as cnt FROM scan_log GROUP BY verdict"
        )
        return {row["verdict"]: row["cnt"] for row in cursor.fetchall()}

    def total_cost(self) -> float:
        """Sum of estimated costs across all logged requests."""
        cursor = self._conn.execute(
            "SELECT COALESCE(SUM(estimated_cost_usd), 0.0) as total FROM scan_log"
        )
        return cursor.fetchone()["total"]
