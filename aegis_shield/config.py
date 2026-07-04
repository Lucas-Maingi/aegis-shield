"""Application-wide settings loaded from environment variables.

Every knob lives here so the rest of the code never reads os.environ directly.
Pydantic Settings validates and coerces at startup — a missing required value
crashes early with a clear message rather than silently returning None at
request time.
"""

from __future__ import annotations

from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    """Central configuration for Aegis Shield.

    Values are read from environment variables (case-insensitive) or a `.env`
    file in the working directory.  Defaults are deliberately conservative so
    the gateway can start with *zero* configuration for local development.
    """

    # ── Gateway identity ────────────────────────────────────────────────
    app_name: str = "Aegis Shield"
    debug: bool = False

    # ── Upstream LLM provider ───────────────────────────────────────────
    #    The gateway forwards clean requests here after scanning.
    upstream_base_url: str = "https://api.openai.com/v1"
    upstream_api_key: str = ""
    upstream_timeout_seconds: float = 60.0

    # ── Rate limiting ───────────────────────────────────────────────────
    rate_limit_rpm: int = 60  # requests per minute per API key
    rate_limit_enabled: bool = True

    # ── Scanner thresholds ──────────────────────────────────────────────
    pii_scan_enabled: bool = True
    injection_scan_enabled: bool = True
    output_scan_enabled: bool = True

    # Injection classifier confidence threshold (0-1).  Prompts scoring
    # above this are blocked.
    injection_threshold: float = 0.80

    # ── Persistence ─────────────────────────────────────────────────────
    db_path: str = "aegis_shield.db"

    # ── Server ──────────────────────────────────────────────────────────
    host: str = "0.0.0.0"
    port: int = 8000

    model_config = {"env_prefix": "AEGIS_", "env_file": ".env", "extra": "ignore"}


# Module-level singleton — import this wherever you need config.
settings = Settings()
