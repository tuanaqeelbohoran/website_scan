"""checks/website/cors_posture.py — CORS configuration audit."""
from __future__ import annotations

from checks.base import BaseCheck
from core.models import Evidence, Finding, Severity, ScanType


class CORSPostureCheck(BaseCheck):
    check_id = "cors_posture"
    scan_type = ScanType.WEBSITE
    description = "Checks CORS headers for wildcard origins and credentialed-request misconfig."

    async def run(self, target_url: str, session, config: dict) -> list[Finding]:
        findings: list[Finding] = []

        # Test 1: wildcard ACAO
        try:
            resp = await session.head(
                target_url,
                headers={"Origin": "https://evil.example.com"},
                follow_redirects=True,
            )
        except Exception:
            return findings

        acao = resp.headers.get("access-control-allow-origin", "")
        acac = resp.headers.get("access-control-allow-credentials", "").lower()

        if acao == "*":
            sev = Severity.HIGH if acac == "true" else Severity.MEDIUM
            findings.append(Finding(
                check_id="cors_posture.wildcard_origin",
                title="CORS allows all origins (Access-Control-Allow-Origin: *)",
                description=(
                    "Any website can read responses from this origin. "
                    + ("Combined with Allow-Credentials: true this is critical." if acac == "true" else "")
                ),
                severity=sev,
                affected_url=str(resp.url),
                evidence=[
                    Evidence(label="Access-Control-Allow-Origin", value=acao),
                    Evidence(label="Access-Control-Allow-Credentials", value=acac or "not set"),
                ],
                remediation=(
                    "Restrict ACAO to an explicit list of trusted origins. "
                    "Never combine ACAO: * with Allow-Credentials: true."
                ),
                cwe="CWE-942",
                references=["https://portswigger.net/web-security/cors"],
            ))
        elif acao == "https://evil.example.com":
            # Endpoint reflects arbitrary Origin — almost as bad as wildcard
            findings.append(Finding(
                check_id="cors_posture.reflects_origin",
                title="CORS reflects arbitrary Origin header",
                description="The server echoes back any supplied Origin, allowing cross-origin reads.",
                severity=Severity.HIGH,
                affected_url=str(resp.url),
                evidence=[Evidence(label="Access-Control-Allow-Origin", value=acao)],
                remediation="Validate the Origin against a static allowlist before echoing it.",
                cwe="CWE-942",
            ))

        return findings
