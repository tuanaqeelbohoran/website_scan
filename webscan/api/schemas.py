"""api/schemas.py — Pydantic request/response models for the API."""
from __future__ import annotations

from typing import Any
from pydantic import BaseModel, HttpUrl, field_validator


class ScanRequest(BaseModel):
    target_url: str
    scan_type: str = "website"
    # The caller MUST set this to True; used to enforce the consent gate.
    i_own_or_have_written_permission: bool = False
    config: dict[str, Any] = {}

    @field_validator("scan_type")
    @classmethod
    def validate_scan_type(cls, v: str) -> str:
        if v not in ("website", "ai_endpoint"):
            raise ValueError("scan_type must be 'website' or 'ai_endpoint'")
        return v

    @field_validator("target_url")
    @classmethod
    def validate_url_scheme(cls, v: str) -> str:
        from urllib.parse import urlparse
        parsed = urlparse(v)
        if parsed.scheme not in ("http", "https"):
            raise ValueError("target_url must start with http:// or https://")
        if not parsed.hostname:
            raise ValueError("target_url must include a hostname")
        return v


class ScanAccepted(BaseModel):
    scan_id: str
    message: str = "Scan started"


class ScanStatus(BaseModel):
    scan_id: str
    status: str          # "running" | "completed" | "error"
    total_findings: int
    errors: list[str]
    finished_at: str | None = None


class ScheduleRequest(BaseModel):
    target_url: str
    scan_type: str = "website"
    cron_expression: str           # e.g. "0 3 * * *"
    notify_webhook: str = ""
    i_own_or_have_written_permission: bool = False

    @field_validator("scan_type")
    @classmethod
    def validate_scan_type(cls, v: str) -> str:
        if v not in ("website", "ai_endpoint"):
            raise ValueError("scan_type must be 'website' or 'ai_endpoint'")
        return v
