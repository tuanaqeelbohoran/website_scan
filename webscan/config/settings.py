"""config/settings.py — All runtime configuration drawn from environment variables.

Never hardcode secrets or host targets in this file.
Copy .env.example → .env, fill in values, never commit .env.
"""
from pydantic_settings import BaseSettings
from config.defaults import (
    MAX_CONCURRENT_CHECKS,
    REQUEST_TIMEOUT_SEC,
    MAX_REDIRECTS,
    MAX_REQUESTS_PER_SCAN,
    DELAY_BETWEEN_REQS_SEC,
)


class Settings(BaseSettings):
    # ── Safety guards ──────────────────────────────────────────────────────
    MAX_CONCURRENT_CHECKS: int = MAX_CONCURRENT_CHECKS
    REQUEST_TIMEOUT_SEC: float = REQUEST_TIMEOUT_SEC
    MAX_REDIRECTS: int = MAX_REDIRECTS
    MAX_REQUESTS_PER_SCAN: int = MAX_REQUESTS_PER_SCAN
    DELAY_BETWEEN_REQS_SEC: float = DELAY_BETWEEN_REQS_SEC
    # Regex applied to target_url before scanning.  Empty string = no allowlist enforced.
    ALLOWED_TARGETS_REGEX: str = ""

    # ── Server ─────────────────────────────────────────────────────────────
    HOST: str = "127.0.0.1"   # DO NOT change to 0.0.0.0 without firewall rules
    PORT: int = 8080
    LOG_LEVEL: str = "INFO"
    AUDIT_LOG_PATH: str = "audit.jsonl"

    # ── SLM agents (optional) ──────────────────────────────────────────────
    ENABLE_SLM_AGENTS: bool = False
    SLM_MODEL: str = "phi3:mini"
    SLM_BASE_URL: str = "http://localhost:11434"   # Ollama default

    # ── Reports ────────────────────────────────────────────────────────────
    REPORT_STORE_DIR: str = "webscan_reports"

    model_config = {
        "env_file": ".env",
        "env_file_encoding": "utf-8",
    }


# Module-level singleton — import and use this everywhere.
settings = Settings()
