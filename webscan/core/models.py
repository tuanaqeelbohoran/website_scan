"""core/models.py — Pure data classes. No I/O, no network, no side effects."""
from __future__ import annotations

import datetime
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"
    PASS = "pass"


class ScanType(str, Enum):
    WEBSITE = "website"
    AI_ENDPOINT = "ai_endpoint"


@dataclass
class Evidence:
    """Raw proof attached to a finding."""

    label: str
    value: str                  # truncated header value, cert field, etc.
    source_url: str = ""
    http_method: str = "GET"
    redacted: bool = False      # True if the value was sanitised before storage


@dataclass
class Finding:
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    check_id: str = ""
    title: str = ""
    description: str = ""
    severity: Severity = Severity.INFO
    affected_url: str = ""
    evidence: list[Evidence] = field(default_factory=list)
    remediation: str = ""
    references: list[str] = field(default_factory=list)
    cwe: str = ""
    cvss_score: float | None = None
    tags: list[str] = field(default_factory=list)
    # Optional mappings to security frameworks (OWASP LLM Top 10, MITRE ATLAS)
    framework_refs: dict[str, str] = field(default_factory=dict)


@dataclass
class ScanResult:
    scan_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    target_url: str = ""
    scan_type: ScanType = ScanType.WEBSITE
    started_at: datetime.datetime = field(default_factory=datetime.datetime.utcnow)
    finished_at: datetime.datetime | None = None
    findings: list[Finding] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)
    errors: list[str] = field(default_factory=list)
    checks_total: int = 0
    checks_done: int = 0
    last_check_name: str = ""

    @property
    def by_severity(self) -> dict[Severity, list[Finding]]:
        out: dict[Severity, list[Finding]] = {s: [] for s in Severity}
        for f in self.findings:
            out[f.severity].append(f)
        return out

    @property
    def risk_score(self) -> float:
        """Weighted 0-100 risk score. PASS findings do not contribute."""
        weights = {
            Severity.CRITICAL: 40,
            Severity.HIGH: 20,
            Severity.MEDIUM: 10,
            Severity.LOW: 3,
            Severity.INFO: 1,
            Severity.PASS: 0,
        }
        raw = sum(weights[f.severity] for f in self.findings)
        return min(round(raw, 1), 100.0)
