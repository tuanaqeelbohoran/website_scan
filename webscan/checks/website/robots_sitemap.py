"""checks/website/robots_sitemap.py — robots.txt and sitemap.xml exposure check."""
from __future__ import annotations

import re

from checks.base import BaseCheck
from core.models import Evidence, Finding, Severity, ScanType
from urllib.parse import urljoin


class RobotsSitemapCheck(BaseCheck):
    check_id = "robots_sitemap"
    scan_type = ScanType.WEBSITE
    description = "Checks for robots.txt/sitemap.xml exposure and disallowed-path hints."

    async def run(self, target_url: str, session, config: dict) -> list[Finding]:
        findings: list[Finding] = []

        base = self._base_url(target_url)

        # ── robots.txt ────────────────────────────────────────────────────
        robots_url = urljoin(base, "/robots.txt")
        robots_findings = await self._probe(
            session, robots_url,
            check_prefix="robots_txt",
            label="robots.txt",
            analyze_fn=self._analyze_robots,
        )
        findings.extend(robots_findings)

        # ── security.txt (RFC 9116) ───────────────────────────────────────
        sec_url = urljoin(base, "/.well-known/security.txt")
        sec_resp_code = await self._get_status(session, sec_url)
        if sec_resp_code == 200:
            findings.append(Finding(
                check_id="robots_sitemap.security_txt_present",
                title="security.txt is present (RFC 9116) ✓",
                severity=Severity.PASS,
                affected_url=sec_url,
                evidence=[Evidence(label="URL", value=sec_url)],
            ))
        else:
            findings.append(Finding(
                check_id="robots_sitemap.security_txt_missing",
                title="security.txt not found (RFC 9116)",
                description=(
                    "A /.well-known/security.txt file documents your vulnerability "
                    "disclosure policy and contacts."
                ),
                severity=Severity.INFO,
                affected_url=sec_url,
                remediation="Publish a security.txt file per RFC 9116: https://www.rfc-editor.org/rfc/rfc9116",
                references=["https://www.rfc-editor.org/rfc/rfc9116"],
            ))

        return findings

    # ── Helpers ───────────────────────────────────────────────────────────

    async def _probe(self, session, url, check_prefix, label, analyze_fn):
        findings: list[Finding] = []
        try:
            resp = await session.get(url, follow_redirects=True)
        except Exception:
            return findings

        if resp.status_code == 200:
            body = resp.text[:4096]        # read a safe preview only
            findings.append(Finding(
                check_id=f"{check_prefix}.present",
                title=f"{label} is publicly accessible",
                severity=Severity.INFO,
                affected_url=url,
                evidence=[Evidence(label="Preview (first 200 chars)", value=body[:200])],
            ))
            findings.extend(analyze_fn(url, body))
        return findings

    async def _get_status(self, session, url) -> int:
        try:
            resp = await session.head(url, follow_redirects=True)
            return resp.status_code
        except Exception:
            return 0

    def _analyze_robots(self, url: str, body: str) -> list[Finding]:
        """Look for Disallow: paths that hint at sensitive admin areas."""
        findings: list[Finding] = []
        sensitive_patterns = re.compile(
            r"Disallow:\s*(/admin|/login|/wp-admin|/api|/private|/backup|/config)",
            re.IGNORECASE,
        )
        for match in sensitive_patterns.finditer(body):
            findings.append(Finding(
                check_id="robots_txt.sensitive_disallow",
                title=f"robots.txt Disallow hints at sensitive path: {match.group(1)}",
                description=(
                    "Disallow entries in robots.txt are publicly visible and may "
                    "advertise the existence of sensitive endpoints to attackers."
                ),
                severity=Severity.LOW,
                affected_url=url,
                evidence=[Evidence(label="Disallow", value=match.group(0).strip())],
                remediation=(
                    "Remove sensitive paths from robots.txt. Protect them with "
                    "authentication instead of relying on search engine exclusion."
                ),
                cwe="CWE-200",
            ))
        return findings

    @staticmethod
    def _base_url(url: str) -> str:
        from urllib.parse import urlparse
        p = urlparse(url)
        return f"{p.scheme}://{p.netloc}"
