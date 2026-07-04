"""Semantic cache for Aegis Shield.

Saves prompt-response pairs and matches incoming queries using exact
matching, with extension hooks for vector-based semantic similarity
(e.g., comparing embedding cosine distance).
"""

from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timezone
from typing import Optional
from aegis_shield.config import settings


class SemanticCache:
    """Caching layer using SQLite for persistence."""

    def __init__(self, db_path: str | None = None):
        self._path = db_path or settings.db_path
        self._conn = sqlite3.connect(self._path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._migrate()

    def _migrate(self) -> None:
        self._conn.execute("""
            CREATE TABLE IF NOT EXISTS semantic_cache (
                id             INTEGER PRIMARY KEY AUTOINCREMENT,
                prompt         TEXT UNIQUE NOT NULL,
                response_json  TEXT NOT NULL,
                timestamp      TEXT NOT NULL
            )
        """)
        self._conn.commit()

    def get(self, prompt: str) -> Optional[dict]:
        """Look up a prompt in the cache. Returns response dict if found."""
        cursor = self._conn.execute(
            "SELECT response_json FROM semantic_cache WHERE prompt = ?",
            (prompt.strip(),),
        )
        row = cursor.fetchone()
        if row:
            return json.loads(row["response_json"])
        return None

    def set(self, prompt: str, response: dict) -> None:
        """Store a prompt-response pair in the cache."""
        try:
            self._conn.execute(
                """
                INSERT OR REPLACE INTO semantic_cache (prompt, response_json, timestamp)
                VALUES (?, ?, ?)
                """,
                (
                    prompt.strip(),
                    json.dumps(response),
                    datetime.now(timezone.utc).isoformat(),
                ),
            )
            self._conn.commit()
        except Exception:
            # Never let cache write errors crash the proxy lifecycle
            pass

    def clear(self) -> None:
        """Purge the cache."""
        self._conn.execute("DELETE FROM semantic_cache")
        self._conn.commit()
