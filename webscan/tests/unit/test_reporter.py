"""tests/unit/test_reporter.py — unit tests for all three reporters."""
from __future__ import annotations

import datetime
import json
import uuid

import pytest

from core.models import Evidence, Finding, ScanResult, ScanType, Severity


def _make_result(sev: Severity = Severity.HIGH) -> ScanResult:
    return ScanResult(
        scan_id    = str(uuid.uuid4()),
        target_url = "https://example.com",
        scan_type  = ScanType.WEBSITE,
        started_at = datetime.datetime.utcnow(),
        findings   = [
            Finding(
                check_id    = "test.check",
                title       = "Test finding",
                severity    = sev,
                description = "A test finding for reporter tests.",
                affected_url= "https://example.com/test",
                remediation = "Fix it.",
                references  = ["https://owasp.org"],
                evidence    = [Evidence(label="header", value="x-powered-by: Test/1.0")],
                cwe         = "CWE-16",
                cvss_score  = 5.5,
                framework_refs={"OWASP": "A05:2021"},
            )
        ],
    )


# ---------------------------------------------------------------------------
# JSONReporter
# ---------------------------------------------------------------------------

def test_json_reporter_returns_bytes() -> None:
    from reporter.json_reporter import JSONReporter

    result   = _make_result()
    reporter = JSONReporter()
    output   = reporter.render(result)
    assert isinstance(output, bytes)
    assert len(output) > 10


def test_json_reporter_valid_json() -> None:
    from reporter.json_reporter import JSONReporter

    result = _make_result()
    data   = json.loads(JSONReporter().render(result))
    assert "findings" in data
    assert len(data["findings"]) == 1
    assert data["findings"][0]["check_id"] == "test.check"


def test_json_reporter_risk_score_present() -> None:
    from reporter.json_reporter import JSONReporter

    result = _make_result()
    data   = json.loads(JSONReporter().render(result))
    assert "risk_score" in data.get("metadata", {})


# ---------------------------------------------------------------------------
# PDFReporter
# ---------------------------------------------------------------------------

def test_pdf_reporter_returns_bytes() -> None:
    from reporter.pdf_reporter import PDFReporter

    result = _make_result()
    output = PDFReporter().render(result)
    assert isinstance(output, bytes)
    # PDF magic bytes
    assert output[:4] == b"%PDF"


def test_pdf_reporter_non_empty_for_empty_findings() -> None:
    """PDF should still be generated even with zero findings."""
    from reporter.pdf_reporter import PDFReporter

    result = ScanResult(
        scan_id    = str(uuid.uuid4()),
        target_url = "https://example.com",
        scan_type  = ScanType.WEBSITE,
        started_at = datetime.datetime.utcnow(),
        findings   = [],
    )
    output = PDFReporter().render(result)
    assert output[:4] == b"%PDF"


# ---------------------------------------------------------------------------
# SARIFReporter
# ---------------------------------------------------------------------------

def test_sarif_reporter_returns_bytes() -> None:
    from reporter.sarif_reporter import SARIFReporter

    output = SARIFReporter().render(_make_result())
    assert isinstance(output, bytes)
    assert len(output) > 10


def test_sarif_reporter_valid_json_schema() -> None:
    from reporter.sarif_reporter import SARIFReporter

    data = json.loads(SARIFReporter().render(_make_result()))
    assert data["version"] == "2.1.0"
    assert "runs" in data
    assert len(data["runs"]) == 1
    assert data["runs"][0]["results"][0]["ruleId"] == "test.check"


def test_sarif_reporter_severity_mapping() -> None:
    from reporter.sarif_reporter import SARIFReporter

    for sev, expected_level in [
        (Severity.CRITICAL, "error"),
        (Severity.HIGH,     "error"),
        (Severity.MEDIUM,   "warning"),
        (Severity.LOW,      "note"),
        (Severity.INFO,     "note"),
    ]:
        data = json.loads(SARIFReporter().render(_make_result(sev=sev)))
        assert data["runs"][0]["results"][0]["level"] == expected_level
