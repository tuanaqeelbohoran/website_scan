"""checks/website/sensitive_paths.py — Static sensitive-path probe (HEAD only)."""
from __future__ import annotations

from urllib.parse import urljoin

from checks.base import BaseCheck
from core.models import Evidence, Finding, Severity, ScanType

# Short, static list — NOT a wordlist fuzzer. HEAD requests only.
_SENSITIVE_PATHS: list[dict] = [
    {"path": "/swagger.json",      "title": "Swagger/OpenAPI spec exposed"},
    {"path": "/openapi.json",      "title": "OpenAPI spec exposed"},
    {"path": "/openapi.yaml",      "title": "OpenAPI YAML spec exposed"},
    {"path": "/api/docs",          "title": "API documentation accessible"},
    {"path": "/api/swagger",       "title": "Swagger UI accessible at /api/swagger"},
    {"path": "/graphql",           "title": "GraphQL endpoint detected"},
    {"path": "/graphiql",          "title": "GraphiQL IDE accessible"},
    {"path": "/__debug__/",        "title": "Django debug interface accessible"},
    {"path": "/trace",             "title": "HTTP TRACE method endpoint"},
    {"path": "/.DS_Store",         "title": ".DS_Store file exposed (macOS metadata)"},
    {"path": "/package.json",      "title": "package.json exposed"},
    {"path": "/composer.json",     "title": "composer.json exposed"},
    {"path": "/Dockerfile",        "title": "Dockerfile exposed"},
]


class SensitivePathsCheck(BaseCheck):
    check_id = "sensitive_paths"
    scan_type = ScanType.WEBSITE
    description = (
        "Probes a short static allowlist of sensitive paths using HEAD requests only. "
        "No content is read. No wordlist fuzzing."
    )

    async def run(self, target_url: str, session, config: dict) -> list[Finding]:
        findings: list[Finding] = []
        base = self._base_url(target_url)

        for probe in _SENSITIVE_PATHS:
            url = urljoin(base, probe["path"])
            try:
                resp = await session.head(url, follow_redirects=False)
            except Exception:
                continue

            if resp.status_code == 200:
                findings.append(Finding(
                    check_id=f"sensitive_paths.{probe['path'].strip('/').replace('/', '_').replace('.', '_')}",
                    title=probe["title"],
                    description=(
                        f"HEAD {url} returned HTTP 200. "
                        "This resource may expose sensitive information."
                    ),
                    severity=Severity.MEDIUM,
                    affected_url=url,
                    evidence=[Evidence(label="HTTP Status", value="200")],
                    remediation=(
                        "Remove the resource from the public web root or restrict access "
                        "with authentication / firewall rules."
                    ),
                    cwe="CWE-200",
                ))

        return findings

    @staticmethod
    def _base_url(url: str) -> str:
        from urllib.parse import urlparse
        p = urlparse(url)
        return f"{p.scheme}://{p.netloc}"
