"""reporter/sarif_reporter.py — SARIF 2.1.0 export for CI/CD integration.

SARIF is understood natively by GitHub Advanced Security, VS Code Problems panel,
and most CI platforms.  Spec: https://sarifweb.azurewebsites.net/
"""
from __future__ import annotations

import datetime
import json

from core.interfaces import Reporter
from core.models import Finding, Severity, ScanResult

_SARIF_LEVEL = {
    Severity.CRITICAL: "error",
    Severity.HIGH:     "error",
    Severity.MEDIUM:   "warning",
    Severity.LOW:      "note",
    Severity.INFO:     "note",
    Severity.PASS:     "none",
}


class SARIFReporter(Reporter):
    TOOL_NAME    = "WebScan"
    TOOL_VERSION = "1.0.0"
    TOOL_URI     = "https://github.com/your-org/webscan"

    def render(self, result: ScanResult) -> bytes:
        # Build rules from unique check_ids
        rules_by_id: dict[str, dict] = {}
        for f in result.findings:
            if f.check_id not in rules_by_id:
                rules_by_id[f.check_id] = self._make_rule(f)

        sarif = {
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": self.TOOL_NAME,
                            "version": self.TOOL_VERSION,
                            "informationUri": self.TOOL_URI,
                            "rules": list(rules_by_id.values()),
                        }
                    },
                    "invocations": [
                        {
                            "executionSuccessful": not bool(result.errors),
                            "startTimeUtc": result.started_at.isoformat() + "Z",
                            "endTimeUtc": (
                                (result.finished_at.isoformat() + "Z")
                                if result.finished_at
                                else (datetime.datetime.utcnow().isoformat() + "Z")
                            ),
                        }
                    ],
                    "results": [self._make_result(f) for f in result.findings],
                    "properties": {
                        "scan_id":    result.scan_id,
                        "target_url": result.target_url,
                        "risk_score": result.risk_score,
                    },
                }
            ],
        }
        return json.dumps(sarif, indent=2, ensure_ascii=True).encode("utf-8")

    def _make_rule(self, f: Finding) -> dict:
        rule: dict = {
            "id":   f.check_id,
            "name": f.check_id.replace(".", "_").replace("-", "_"),
            "shortDescription": {"text": f.title or f.check_id},
            "fullDescription":  {"text": f.description or f.title or f.check_id},
            "defaultConfiguration": {"level": _SARIF_LEVEL[f.severity]},
            "properties": {},
        }
        if f.cwe:
            rule["properties"]["cwe"] = f.cwe
        if f.remediation:
            rule["help"] = {"text": f.remediation}
        if f.references:
            rule["helpUri"] = f.references[0]
        if f.cvss_score is not None:
            rule["properties"]["cvss_score"] = f.cvss_score
        if f.framework_refs:
            rule["properties"]["framework_refs"] = f.framework_refs
        return rule

    def _make_result(self, f: Finding) -> dict:
        res: dict = {
            "ruleId":  f.check_id,
            "level":   _SARIF_LEVEL[f.severity],
            "message": {"text": f.description or f.title},
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {"uri": f.affected_url or "unknown"},
                    }
                }
            ],
            "partialFingerprints": {"check_id/v1": f.check_id},
        }
        if f.evidence:
            res["attachments"] = [
                {"description": {"text": f"{e.label}: {e.value}"}}
                for e in f.evidence
            ]
        return res
