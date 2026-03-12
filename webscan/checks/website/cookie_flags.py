"""checks/website/cookie_flags.py — Cookie security flag analysis."""
from __future__ import annotations

from checks.base import BaseCheck
from core.models import Evidence, Finding, Severity, ScanType


class CookieFlagsCheck(BaseCheck):
    check_id = "cookie_flags"
    scan_type = ScanType.WEBSITE
    description = "Checks Set-Cookie headers for Secure, HttpOnly, and SameSite flags."

    async def run(self, target_url: str, session, config: dict) -> list[Finding]:
        findings: list[Finding] = []
        try:
            resp = await session.get(target_url, follow_redirects=True)
        except Exception:
            return findings

        raw_cookies = resp.headers.get_list("set-cookie")
        if not raw_cookies:
            return findings

        for raw in raw_cookies:
            # Extract cookie name — first token before '='
            name = raw.split("=")[0].strip()
            lower = raw.lower()
            # Redact the cookie value in evidence
            safe_raw = f"{name}=***; {raw.split(';', 1)[1].strip() if ';' in raw else ''}"

            if "secure" not in lower:
                findings.append(Finding(
                    check_id="cookie_flags.no_secure",
                    title=f"Cookie '{name}' missing Secure flag",
                    description="Cookie may be transmitted over unencrypted HTTP connections.",
                    severity=Severity.MEDIUM,
                    affected_url=str(resp.url),
                    evidence=[Evidence(label="Set-Cookie", value=self._truncate(safe_raw), redacted=True)],
                    remediation="Add the Secure attribute to prevent transmission over HTTP.",
                    cwe="CWE-614",
                    references=["https://owasp.org/www-community/controls/SecureCookieAttribute"],
                ))
            if "httponly" not in lower:
                findings.append(Finding(
                    check_id="cookie_flags.no_httponly",
                    title=f"Cookie '{name}' missing HttpOnly flag",
                    description="Cookie is accessible via JavaScript — increases XSS risk.",
                    severity=Severity.MEDIUM,
                    affected_url=str(resp.url),
                    evidence=[Evidence(label="Set-Cookie", value=self._truncate(safe_raw), redacted=True)],
                    remediation="Add HttpOnly attribute to prevent JavaScript access.",
                    cwe="CWE-1004",
                ))
            samesite_missing = "samesite" not in lower
            samesite_none    = "samesite=none" in lower
            if samesite_missing:
                findings.append(Finding(
                    check_id="cookie_flags.no_samesite",
                    title=f"Cookie '{name}' missing SameSite attribute",
                    description="Absence of SameSite can enable CSRF attacks in some browsers.",
                    severity=Severity.LOW,
                    affected_url=str(resp.url),
                    evidence=[Evidence(label="Set-Cookie", value=self._truncate(safe_raw), redacted=True)],
                    remediation="Add SameSite=Strict or SameSite=Lax.",
                    cwe="CWE-352",
                ))
            elif samesite_none and "secure" not in lower:
                findings.append(Finding(
                    check_id="cookie_flags.samesite_none_without_secure",
                    title=f"Cookie '{name}' has SameSite=None without Secure",
                    description="SameSite=None requires the Secure flag per modern browser policy.",
                    severity=Severity.MEDIUM,
                    affected_url=str(resp.url),
                    evidence=[Evidence(label="Set-Cookie", value=self._truncate(safe_raw), redacted=True)],
                    remediation="Add the Secure flag when using SameSite=None.",
                    cwe="CWE-614",
                ))

        return findings
