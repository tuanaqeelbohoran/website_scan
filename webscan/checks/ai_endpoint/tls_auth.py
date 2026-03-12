"""checks/ai_endpoint/tls_auth.py — TLS enforcement + authentication presence."""
from __future__ import annotations

from urllib.parse import urlparse

from checks.base import BaseCheck
from core.models import Evidence, Finding, Severity, ScanType


class TLSAuthCheck(BaseCheck):
    check_id = "ai.tls_auth"
    scan_type = ScanType.AI_ENDPOINT
    description = "Checks HTTPS enforcement and authentication requirements on AI endpoints."

    async def run(self, target_url: str, session, config: dict) -> list[Finding]:
        findings: list[Finding] = []
        parsed = urlparse(target_url)

        if parsed.scheme != "https":
            findings.append(Finding(
                check_id="ai.tls_auth.no_https",
                title="AI endpoint served over plain HTTP",
                description="All request/response data — including prompts and API keys — is unencrypted.",
                severity=Severity.CRITICAL,
                affected_url=target_url,
                remediation="Enforce HTTPS with a valid TLS certificate. AI APIs must never use plain HTTP.",
                cwe="CWE-319",
            ))
            return findings

        try:
            resp = await session.head(target_url, follow_redirects=True)
        except Exception:
            return findings

        if resp.status_code == 200:
            findings.append(Finding(
                check_id="ai.tls_auth.no_auth_required",
                title="AI endpoint accessible without authentication (HTTP 200 on HEAD)",
                description=(
                    f"HEAD {target_url} returned HTTP 200 without any Authorization header. "
                    "Unauthenticated access to an AI API may enable abuse, data leakage, or cost exploitation."
                ),
                severity=Severity.CRITICAL,
                affected_url=target_url,
                evidence=[Evidence(label="HTTP Status", value="200")],
                remediation=(
                    "Require an API key or OAuth2 Bearer token. "
                    "Return HTTP 401 for unauthenticated requests."
                ),
                cwe="CWE-306",
                framework_refs={
                    "owasp_llm": "LLM08 — Excessive Agency",
                    "mitre_atlas": "AML.T0051 — LLM Jailbreak",
                },
            ))
        elif resp.status_code in (401, 403):
            findings.append(Finding(
                check_id="ai.tls_auth.auth_required_pass",
                title="Authentication requirement confirmed ✓",
                description=f"Unauthenticated HEAD returned HTTP {resp.status_code}.",
                severity=Severity.PASS,
                affected_url=target_url,
                evidence=[Evidence(label="HTTP Status", value=str(resp.status_code))],
            ))

        return findings
