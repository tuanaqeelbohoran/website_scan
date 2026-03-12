"""checks/website/tech_fingerprint.py — Passive technology fingerprinting."""
from __future__ import annotations

import re

from checks.base import BaseCheck
from core.models import Evidence, Finding, Severity, ScanType

# (header_name, value_pattern, technology_label)
_HEADER_SIGS: list[tuple[str, str, str]] = [
    ("server",          r"nginx",             "nginx"),
    ("server",          r"apache",            "Apache"),
    ("server",          r"iis",               "Microsoft IIS"),
    ("server",          r"cloudflare",        "Cloudflare"),
    ("server",          r"lighttpd",          "Lighttpd"),
    ("x-powered-by",    r"php",               "PHP"),
    ("x-powered-by",    r"asp\.net",          "ASP.NET"),
    ("x-powered-by",    r"express",           "Express.js"),
    ("x-generator",     r"wordpress",         "WordPress"),
    ("x-drupal-cache",  r".*",                "Drupal"),
    ("set-cookie",      r"PHPSESSID",         "PHP session"),
    ("set-cookie",      r"JSESSIONID",        "Java/Tomcat"),
    ("set-cookie",      r"ASP\.NET_SessionId","ASP.NET session"),
    ("set-cookie",      r"laravel_session",   "Laravel"),
    ("set-cookie",      r"django",            "Django"),
]


class TechFingerprintCheck(BaseCheck):
    check_id = "tech_fingerprint"
    scan_type = ScanType.WEBSITE
    description = (
        "Passively identifies server-side technologies from response headers and cookies. "
        "No active probing — informational only."
    )

    async def run(self, target_url: str, session, config: dict) -> list[Finding]:
        findings: list[Finding] = []
        try:
            resp = await session.get(target_url, follow_redirects=True)
        except Exception:
            return findings

        lower = {k.lower(): v for k, v in resp.headers.items()}
        detected: set[str] = set()

        for header, pattern, tech in _HEADER_SIGS:
            value = lower.get(header, "")
            if value and re.search(pattern, value, re.IGNORECASE):
                if tech not in detected:
                    detected.add(tech)
                    findings.append(Finding(
                        check_id=f"tech_fingerprint.{tech.replace(' ', '_').replace('.', '').lower()}",
                        title=f"Technology detected: {tech}",
                        description=(
                            f"Identified via '{header}' header. "
                            "Knowledge of the technology stack helps attackers target known CVEs."
                        ),
                        severity=Severity.INFO,
                        affected_url=str(resp.url),
                        evidence=[Evidence(label=header, value=self._truncate(value))],
                        remediation=(
                            "Suppress version-identifying headers. "
                            "Keep all dependencies up to date to reduce the CVE attack surface."
                        ),
                        cwe="CWE-200",
                    ))

        return findings
