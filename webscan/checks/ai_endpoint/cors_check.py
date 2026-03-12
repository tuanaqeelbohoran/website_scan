"""checks/ai_endpoint/cors_check.py — CORS posture for AI API endpoints."""
from __future__ import annotations

from checks.base import BaseCheck
from core.models import Evidence, Finding, Severity, ScanType


class AICORSCheck(BaseCheck):
    check_id = "ai.cors"
    scan_type = ScanType.AI_ENDPOINT
    description = "Checks CORS configuration on AI API endpoints."

    async def run(self, target_url: str, session, config: dict) -> list[Finding]:
        findings: list[Finding] = []
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
            sev = Severity.CRITICAL if acac == "true" else Severity.HIGH
            findings.append(Finding(
                check_id="ai.cors.wildcard_origin",
                title="AI endpoint CORS allows all origins (*)",
                description=(
                    "Any website can send credentialed requests to this AI API. "
                    + ("ACAO: * combined with Allow-Credentials: true is dangerous." if acac == "true" else "")
                ),
                severity=sev,
                affected_url=str(resp.url),
                evidence=[
                    Evidence(label="Access-Control-Allow-Origin", value=acao),
                    Evidence(label="Access-Control-Allow-Credentials", value=acac or "not set"),
                ],
                remediation=(
                    "Restrict ACAO to specific trusted frontend origins. "
                    "Never combine ACAO: * with Allow-Credentials: true."
                ),
                cwe="CWE-942",
                framework_refs={"owasp_llm": "LLM06 — Sensitive Information Disclosure"},
            ))
        elif acao == "https://evil.example.com":
            findings.append(Finding(
                check_id="ai.cors.reflects_origin",
                title="AI endpoint CORS reflects arbitrary Origin header",
                severity=Severity.HIGH,
                affected_url=str(resp.url),
                evidence=[Evidence(label="Reflected ACAO", value=acao)],
                remediation="Validate Origin against a static allowlist before echoing it.",
                cwe="CWE-942",
            ))

        return findings
