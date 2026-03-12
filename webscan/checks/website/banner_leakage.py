"""checks/website/banner_leakage.py — Server banner / version disclosure."""
from __future__ import annotations

import re

from checks.base import BaseCheck
from core.models import Evidence, Finding, Severity, ScanType

# Headers that commonly reveal server technology and version
_BANNER_HEADERS = (
    "server",
    "x-powered-by",
    "x-aspnet-version",
    "x-aspnetmvc-version",
    "x-generator",
    "via",
)

# Regex patterns indicating version numbers in header values
_VERSION_RE = re.compile(r"[\d]+\.[\d]+", re.IGNORECASE)


class BannerLeakageCheck(BaseCheck):
    check_id = "banner_leakage"
    scan_type = ScanType.WEBSITE
    description = "Detects server technology and version strings in HTTP response headers."

    async def run(self, target_url: str, session, config: dict) -> list[Finding]:
        findings: list[Finding] = []
        try:
            resp = await session.head(target_url, follow_redirects=True)
        except Exception:
            return findings

        lower = {k.lower(): v for k, v in resp.headers.items()}

        for header in _BANNER_HEADERS:
            value = lower.get(header, "")
            if not value:
                continue
            # Only report when an actual version number is present.
            # Generic technology names (e.g. "cloudflare", "nginx" without
            # a version) are already covered by tech_fingerprint and
            # http_headers.disclosure — emitting them here creates duplicates.
            version_match = _VERSION_RE.search(value)
            if not version_match:
                continue
            findings.append(Finding(
                check_id=f"banner_leakage.{header.replace('-', '_')}",
                title=f"Version number disclosed in '{header}' header (v{version_match.group()})",
                description=(
                    f"The '{header}' header value '{self._truncate(value)}' "
                    "contains a version string that helps attackers identify known CVEs."
                ),
                severity=Severity.LOW,
                affected_url=str(resp.url),
                evidence=[Evidence(label=header, value=self._truncate(value))],
                remediation=f"Remove or suppress the '{header}' header in your web server configuration.",
                cwe="CWE-200",
            ))

        return findings
