"""reporter/json_reporter.py — Converts ScanResult to a validated JSON report."""
from __future__ import annotations

import dataclasses
import datetime
import json

from core.interfaces import Reporter
from core.models import Severity, ScanResult


class JSONReporter(Reporter):
    def render(self, result: ScanResult) -> bytes:
        by_sev = result.by_severity
        doc = {
            "scan_id":    result.scan_id,
            "target_url": result.target_url,
            "scan_type":  result.scan_type.value,
            "started_at":  result.started_at.isoformat() + "Z",
            "finished_at": (
                (result.finished_at.isoformat() + "Z") if result.finished_at
                else (datetime.datetime.utcnow().isoformat() + "Z")
            ),
            "summary": {
                "total_findings": len(result.findings),
                "by_severity": {s.value: len(by_sev[s]) for s in Severity},
                "risk_score": result.risk_score,
                "executive_summary": result.metadata.get("executive_summary", ""),
            },
            "methodology": (
                "Passive and low-impact checks only. All requests used HEAD or GET "
                "(POST for user-consented AI probes). No exploit payloads, brute force, "
                "or credential stuffing was performed."
            ),
            "scope": {
                "target_url": result.target_url,
                "scan_type":  result.scan_type.value,
                "checks_performed": sorted({f.check_id for f in result.findings}),
            },
            "findings": [self._finding_to_dict(f) for f in result.findings],
            "errors":   result.errors,
        }
        return json.dumps(doc, default=str, indent=2).encode("utf-8")

    @staticmethod
    def _finding_to_dict(f) -> dict:
        d = dataclasses.asdict(f)
        # Enum values → strings
        d["severity"] = f.severity.value
        return d
