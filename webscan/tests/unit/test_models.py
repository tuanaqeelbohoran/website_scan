"""tests/unit/test_models.py — unit tests for core.models dataclasses."""
from __future__ import annotations

import pytest

from core.models import Evidence, Finding, ScanResult, ScanType, Severity


# ---------------------------------------------------------------------------
# Severity ordering
# ---------------------------------------------------------------------------

def test_severity_values_exist() -> None:
    for sev in ("critical", "high", "medium", "low", "info", "pass"):
        assert Severity(sev) is not None


# ---------------------------------------------------------------------------
# Finding construction
# ---------------------------------------------------------------------------

def test_finding_minimal() -> None:
    f = Finding(check_id="test.check", title="T", severity=Severity.LOW, description="d")
    assert f.check_id == "test.check"
    assert f.evidence == []
    assert f.references == []
    assert f.framework_refs == {}


def test_finding_with_evidence() -> None:
    e = Evidence(label="header", value="x-powered-by: Express")
    f = Finding(
        check_id    = "banner.leakage",
        title       = "Server version disclosed",
        severity    = Severity.LOW,
        description = "Framework version exposed in header.",
        evidence    = [e],
    )
    assert len(f.evidence) == 1
    assert f.evidence[0].label == "header"


# ---------------------------------------------------------------------------
# ScanResult.risk_score
# ---------------------------------------------------------------------------

def _make_result(findings: list[Finding]) -> ScanResult:
    import datetime, uuid
    return ScanResult(
        scan_id    = str(uuid.uuid4()),
        target_url = "https://example.com",
        scan_type  = ScanType.WEBSITE,
        started_at = datetime.datetime.utcnow(),
        findings   = findings,
    )


def test_risk_score_all_pass() -> None:
    findings = [
        Finding(check_id="c1", title="C1", severity=Severity.PASS, description="ok")
    ]
    result = _make_result(findings)
    assert result.risk_score == 0


def test_risk_score_one_critical() -> None:
    findings = [
        Finding(check_id="c1", title="C1", severity=Severity.CRITICAL, description="bad")
    ]
    result = _make_result(findings)
    assert result.risk_score > 0


def test_risk_score_capped_at_100() -> None:
    findings = [
        Finding(check_id=f"c{i}", title=f"C{i}", severity=Severity.CRITICAL, description="x")
        for i in range(20)
    ]
    result = _make_result(findings)
    assert result.risk_score <= 100


# ---------------------------------------------------------------------------
# ScanResult.by_severity
# ---------------------------------------------------------------------------

def test_by_severity_grouping() -> None:
    findings = [
        Finding(check_id="a", title="A", severity=Severity.HIGH, description="h"),
        Finding(check_id="b", title="B", severity=Severity.HIGH, description="h2"),
        Finding(check_id="c", title="C", severity=Severity.LOW,  description="l"),
    ]
    result = _make_result(findings)
    groups = result.by_severity
    assert len(groups[Severity.HIGH]) == 2
    assert len(groups[Severity.LOW])  == 1
    assert groups.get(Severity.CRITICAL, []) == []
