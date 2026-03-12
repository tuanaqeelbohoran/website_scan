"""checks/base.py — Shared helpers for all Check implementations."""
from __future__ import annotations

from core.interfaces import Check


class BaseCheck(Check):
    """Provides utility methods; does NOT implement run()."""

    def _truncate(self, value: str, max_len: int = 256) -> str:
        if len(value) > max_len:
            return value[:max_len] + "…"
        return value

    def _redact_sensitive_headers(self, headers: dict) -> dict:
        """Return a copy of headers with credential values replaced."""
        _SENSITIVE = {"authorization", "cookie", "set-cookie", "x-api-key", "x-auth-token"}
        return {
            k: ("***REDACTED***" if k.lower() in _SENSITIVE else v)
            for k, v in headers.items()
        }
