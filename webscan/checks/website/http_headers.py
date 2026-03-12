"""checks/website/http_headers.py — HTTP security header audit."""
from __future__ import annotations

from checks.base import BaseCheck
from core.models import Evidence, Finding, Severity, ScanType

REQUIRED_HEADERS: dict[str, dict] = {
    "strict-transport-security": {
        "severity": Severity.HIGH,
        "cwe": "CWE-319",
        "remediation": (
            "Add: Strict-Transport-Security: max-age=63072000; includeSubDomains; preload"
        ),
    },
    "content-security-policy": {
        "severity": Severity.HIGH,
        "cwe": "CWE-693",
        "remediation": (
            "Define a strict CSP. Start with default-src 'self' and tighten iteratively. "
            "Use a nonce or hash for inline scripts."
        ),
    },
    "x-content-type-options": {
        "severity": Severity.MEDIUM,
        "cwe": "CWE-693",
        "remediation": "Add: X-Content-Type-Options: nosniff",
    },
    "x-frame-options": {
        "severity": Severity.MEDIUM,
        "cwe": "CWE-1021",
        "remediation": "Add: X-Frame-Options: DENY  (or use CSP frame-ancestors directive).",
    },
    "referrer-policy": {
        "severity": Severity.LOW,
        "cwe": "CWE-200",
        "remediation": "Add: Referrer-Policy: strict-origin-when-cross-origin",
    },
    "permissions-policy": {
        "severity": Severity.LOW,
        "cwe": "CWE-693",
        "remediation": "Add a Permissions-Policy header restricting unused browser features.",
    },
}

DISCLOSING_HEADERS = frozenset({
    "server", "x-powered-by", "x-aspnet-version",
    "x-aspnetmvc-version", "x-generator", "x-drupal-cache",
})

WEAK_CSP_PATTERNS = ("unsafe-inline", "unsafe-eval", "* ", "http:")


class HTTPHeadersCheck(BaseCheck):
    check_id = "http_headers"
    scan_type = ScanType.WEBSITE
    description = "Audits presence and correctness of HTTP security response headers."

    async def run(self, target_url: str, session, config: dict) -> list[Finding]:
        findings: list[Finding] = []
        try:
            resp = await session.head(target_url, follow_redirects=True)
        except Exception as exc:
            findings.append(Finding(
                check_id="http_headers.connect_error",
                title="Could not fetch response headers",
                description=str(exc),
                severity=Severity.INFO,
                affected_url=target_url,
            ))
            return findings

        lower = {k.lower(): v for k, v in resp.headers.items()}

        # Missing required headers
        for header, meta in REQUIRED_HEADERS.items():
            if header not in lower:
                findings.append(Finding(
                    check_id=f"http_headers.missing.{header.replace('-', '_')}",
                    title=f"Missing security header: {header}",
                    description=f"The response does not include the '{header}' header.",
                    severity=meta["severity"],
                    affected_url=str(resp.url),
                    remediation=meta["remediation"],
                    cwe=meta["cwe"],
                    references=["https://owasp.org/www-project-secure-headers/"],
                ))

        # Weak CSP
        csp_value = lower.get("content-security-policy", "")
        for pattern in WEAK_CSP_PATTERNS:
            if pattern in csp_value:
                findings.append(Finding(
                    check_id="http_headers.weak_csp",
                    title=f"Weak CSP directive detected: '{pattern}'",
                    description=f"CSP contains '{pattern}' which weakens script execution guards.",
                    severity=Severity.MEDIUM,
                    affected_url=str(resp.url),
                    evidence=[Evidence(label="Content-Security-Policy", value=self._truncate(csp_value))],
                    remediation="Remove or tighten the weak CSP directive.",
                    cwe="CWE-693",
                ))
                break  # one finding per header is enough

        # Disclosing headers
        for header in DISCLOSING_HEADERS:
            if header in lower:
                findings.append(Finding(
                    check_id=f"http_headers.disclosure.{header.replace('-', '_')}",
                    title=f"Server technology disclosed via '{header}' header",
                    description=f"Header value: {self._truncate(lower[header])}",
                    severity=Severity.LOW,
                    affected_url=str(resp.url),
                    evidence=[Evidence(label=header, value=self._truncate(lower[header]))],
                    remediation=f"Remove or suppress the '{header}' response header.",
                    cwe="CWE-200",
                ))

        return findings
