"""checks/ai_endpoint/data_retention_policy.py — Data retention policy signal check."""
from __future__ import annotations

from checks.base import BaseCheck
from core.models import Evidence, Finding, Severity, ScanType

_RETENTION_HEADERS = (
    "x-data-retention",
    "x-log-policy",
    "x-training-data-opt-out",
    "x-privacy-policy",
)


class DataRetentionPolicyCheck(BaseCheck):
    check_id = "ai.data_retention"
    scan_type = ScanType.AI_ENDPOINT
    description = (
        "Looks for data-retention policy signals in HTTP headers (passive). "
        "Captures presence/absence — does not assert policy correctness."
    )

    async def run(self, target_url: str, session, config: dict) -> list[Finding]:
        findings: list[Finding] = []
        try:
            resp = await session.head(target_url, follow_redirects=True)
        except Exception:
            return findings

        lower = {k.lower(): v for k, v in resp.headers.items()}
        found: list[str] = []

        for header in _RETENTION_HEADERS:
            if header in lower:
                found.append(header)
                findings.append(Finding(
                    check_id=f"ai.data_retention.header_present.{header.replace('-', '_')}",
                    title=f"Data policy header present: {header} ✓",
                    severity=Severity.PASS,
                    affected_url=str(resp.url),
                    evidence=[Evidence(label=header, value=self._truncate(lower[header]))],
                ))

        if not found:
            findings.append(Finding(
                check_id="ai.data_retention.no_policy_headers",
                title="No data retention/privacy policy headers found",
                description=(
                    "Response headers contain no signals about how request/response data "
                    "is logged, retained, or used for model training."
                ),
                severity=Severity.LOW,
                affected_url=str(resp.url),
                remediation=(
                    "Publish clear data retention, logging, and training-opt-out policies. "
                    "Consider adding custom headers (X-Data-Retention, X-Training-Data-Opt-Out) "
                    "and link to your privacy policy in OpenAPI info.x-privacy-policy."
                ),
                framework_refs={
                    "owasp_llm": "LLM06 — Sensitive Information Disclosure",
                },
            ))

        return findings
