"""checks/ai_endpoint/content_type.py — Content-Type correctness for AI APIs."""
from __future__ import annotations

from checks.base import BaseCheck
from core.models import Evidence, Finding, Severity, ScanType


class ContentTypeCheck(BaseCheck):
    check_id = "ai.content_type"
    scan_type = ScanType.AI_ENDPOINT
    description = "Verifies AI endpoint responses declare application/json Content-Type."

    async def run(self, target_url: str, session, config: dict) -> list[Finding]:
        findings: list[Finding] = []
        try:
            resp = await session.head(target_url, follow_redirects=True)
        except Exception:
            return findings

        ct = resp.headers.get("content-type", "")

        if not ct:
            findings.append(Finding(
                check_id="ai.content_type.missing",
                title="AI endpoint response missing Content-Type header",
                description="Absence of Content-Type can cause client-side MIME sniffing.",
                severity=Severity.LOW,
                affected_url=str(resp.url),
                remediation="Always return Content-Type: application/json for AI API responses.",
                cwe="CWE-16",
            ))
        elif "text/html" in ct:
            findings.append(Finding(
                check_id="ai.content_type.html_response",
                title="AI endpoint returned text/html (likely an error page)",
                description=(
                    f"Expected application/json but got '{ct}'. "
                    "This may indicate the endpoint is returning an HTML error/login page."
                ),
                severity=Severity.MEDIUM,
                affected_url=str(resp.url),
                evidence=[Evidence(label="Content-Type", value=self._truncate(ct))],
                remediation=(
                    "Ensure the endpoint returns JSON for all responses (including errors). "
                    "Verify authentication is not redirecting to an HTML login page."
                ),
                cwe="CWE-16",
            ))
        elif "application/json" in ct:
            findings.append(Finding(
                check_id="ai.content_type.json_pass",
                title="Content-Type is application/json ✓",
                severity=Severity.PASS,
                affected_url=str(resp.url),
                evidence=[Evidence(label="Content-Type", value=self._truncate(ct))],
            ))

        return findings
