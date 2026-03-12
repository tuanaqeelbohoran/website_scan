"""checks/ai_endpoint/openapi_discovery.py — OpenAPI/Swagger schema discovery."""
from __future__ import annotations

from urllib.parse import urljoin, urlparse

from checks.base import BaseCheck
from core.models import Evidence, Finding, Severity, ScanType

_PROBE_PATHS = (
    "/openapi.json",
    "/openapi.yaml",
    "/swagger.json",
    "/swagger.yaml",
    "/api/docs",
    "/docs",
    "/api/swagger",
    "/.well-known/openapi",
    "/v1/openapi.json",
    "/v2/openapi.json",
)


class OpenAPIDiscoveryCheck(BaseCheck):
    check_id = "ai.openapi_discovery"
    scan_type = ScanType.AI_ENDPOINT
    description = "Probes common paths for OpenAPI/Swagger schema exposure (HEAD only)."

    async def run(self, target_url: str, session, config: dict) -> list[Finding]:
        findings: list[Finding] = []
        parsed   = urlparse(target_url)
        base     = f"{parsed.scheme}://{parsed.netloc}"

        for path in _PROBE_PATHS:
            url = urljoin(base, path)
            try:
                resp = await session.head(url, follow_redirects=False)
            except Exception:
                continue

            if resp.status_code == 200:
                findings.append(Finding(
                    check_id=f"ai.openapi_discovery.{path.strip('/').replace('/', '_').replace('.', '_')}",
                    title=f"OpenAPI/Swagger schema accessible at {path}",
                    description=(
                        f"HEAD {url} returned HTTP 200. "
                        "Publicly accessible API schemas can reveal endpoint names, parameters, "
                        "and authentication requirements to attackers."
                    ),
                    severity=Severity.MEDIUM,
                    affected_url=url,
                    evidence=[Evidence(label="HTTP Status", value="200"), Evidence(label="Path", value=path)],
                    remediation=(
                        "Restrict schema access to authenticated users or internal networks. "
                        "Consider removing verbose schemas from production."
                    ),
                    cwe="CWE-200",
                    framework_refs={"owasp_llm": "LLM09 — Overreliance"},
                ))

        return findings
