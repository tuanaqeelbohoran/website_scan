"""checks/website/misconfig_hints.py — Common misconfiguration probes (HEAD-only)."""
from __future__ import annotations

from urllib.parse import urljoin

from checks.base import BaseCheck
from core.models import Evidence, Finding, Severity, ScanType

# Static allowlist — HEAD requests only, no content retrieval, no fuzzing.
_PROBES: list[dict] = [
    {"path": "/.env",              "title": ".env file exposed",             "severity": Severity.CRITICAL, "cwe": "CWE-538"},
    {"path": "/.env.local",        "title": ".env.local file exposed",       "severity": Severity.CRITICAL, "cwe": "CWE-538"},
    {"path": "/.git/HEAD",         "title": ".git directory exposed",        "severity": Severity.CRITICAL, "cwe": "CWE-538"},
    {"path": "/phpinfo.php",       "title": "phpinfo() page exposed",        "severity": Severity.HIGH,     "cwe": "CWE-200"},
    {"path": "/server-status",     "title": "Apache server-status exposed",  "severity": Severity.MEDIUM,   "cwe": "CWE-200"},
    {"path": "/server-info",       "title": "Apache server-info exposed",    "severity": Severity.MEDIUM,   "cwe": "CWE-200"},
    {"path": "/admin/",            "title": "Admin panel accessible (200)",  "severity": Severity.MEDIUM,   "cwe": "CWE-284"},
    {"path": "/wp-login.php",      "title": "WordPress login page detected", "severity": Severity.INFO,     "cwe": "CWE-200"},
    {"path": "/actuator/health",   "title": "Spring Actuator endpoint exposed","severity": Severity.LOW,    "cwe": "CWE-200"},
    {"path": "/actuator/env",      "title": "Spring Actuator /env exposed",  "severity": Severity.HIGH,    "cwe": "CWE-200"},
    {"path": "/config.json",       "title": "config.json accessible",        "severity": Severity.HIGH,    "cwe": "CWE-538"},
    {"path": "/backup.zip",        "title": "backup.zip exposed",            "severity": Severity.HIGH,    "cwe": "CWE-538"},
    {"path": "/web.config",        "title": "web.config accessible",         "severity": Severity.HIGH,    "cwe": "CWE-538"},
    {"path": "/crossdomain.xml",   "title": "crossdomain.xml present",       "severity": Severity.LOW,     "cwe": "CWE-942"},
]


class MisconfigHintsCheck(BaseCheck):
    check_id = "misconfig_hints"
    scan_type = ScanType.WEBSITE
    description = (
        "Probes a static allowlist of paths for common misconfigurations. "
        "HEAD requests only — no content is retrieved."
    )

    async def run(self, target_url: str, session, config: dict) -> list[Finding]:
        findings: list[Finding] = []
        base = self._base_url(target_url)

        for probe in _PROBES:
            url = urljoin(base, probe["path"])
            try:
                resp = await session.head(url, follow_redirects=False)
            except Exception:
                continue

            if resp.status_code == 200:
                findings.append(Finding(
                    check_id=f"misconfig_hints.{probe['path'].strip('/').replace('/', '_').replace('.', '_')}",
                    title=probe["title"],
                    description=(
                        f"HEAD {url} returned HTTP 200. "
                        "The resource appears to be publicly accessible."
                    ),
                    severity=probe["severity"],
                    affected_url=url,
                    evidence=[Evidence(label="HTTP Status", value="200")],
                    remediation=(
                        "Remove or protect this resource with authentication. "
                        "Verify it is intentionally public."
                    ),
                    cwe=probe["cwe"],
                ))
            elif resp.status_code in (401, 403):
                # Distinguish a WAF/CDN block from a real server 403.
                # Cloudflare (and similar CDNs) return 403 for every blocked
                # probe regardless of whether the path exists on the origin.
                # A real server 403 means the resource exists but is guarded.
                resp_hdrs = {k.lower(): v.lower() for k, v in resp.headers.items()}
                is_cdn_block = (
                    "cf-ray" in resp_hdrs
                    or resp_hdrs.get("server", "").startswith("cloudflare")
                    or "x-amzn-requestid" in resp_hdrs  # AWS WAF
                    or resp_hdrs.get("server", "").startswith("awselb")
                )
                if is_cdn_block:
                    # CDN/WAF intercepted — path existence unknown, skip
                    continue

                # Real origin 403 — resource likely exists but is protected
                findings.append(Finding(
                    check_id=f"misconfig_hints.{probe['path'].strip('/').replace('/', '_').replace('.', '_')}_protected",
                    title=f"{probe['title']} — protected ({resp.status_code})",
                    description=(
                        f"Origin server returned {resp.status_code} for this path, "
                        "suggesting the resource exists but access is restricted."
                    ),
                    severity=Severity.INFO,
                    affected_url=url,
                    evidence=[Evidence(label="HTTP Status", value=str(resp.status_code))],
                    remediation=(
                        "Confirm the path is intentionally access-controlled. "
                        "Consider returning 404 instead of 403 to avoid confirming path existence."
                    ),
                ))

        return findings

    @staticmethod
    def _base_url(url: str) -> str:
        from urllib.parse import urlparse
        p = urlparse(url)
        return f"{p.scheme}://{p.netloc}"
