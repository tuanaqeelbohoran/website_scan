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

        # Weak CSP — per-directive analysis
        csp_value = lower.get("content-security-policy", "")
        if csp_value:
            findings.extend(self._audit_csp(csp_value, str(resp.url)))

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

    # ── CSP helpers ────────────────────────────────────────────────────────

    def _audit_csp(self, csp: str, url: str) -> list[Finding]:
        """
        Parse each CSP directive individually and return a finding per
        problematic directive with the appropriate severity.

        Severity mapping:
          HIGH   — 'unsafe-inline' or 'unsafe-eval' in script-src / default-src
          MEDIUM — 'unsafe-inline' in script-src-attr
          LOW    — 'unsafe-inline' in style-src
          MEDIUM — wildcard (*) host in script-src / default-src
          LOW    — http: scheme in any directive
        """
        import re as _re
        results: list[Finding] = []

        # Parse directives into a dict: name -> value string
        directives: dict[str, str] = {}
        for part in csp.split(";"):
            part = part.strip()
            if not part:
                continue
            tokens = part.split(None, 1)
            directives[tokens[0].lower()] = tokens[1] if len(tokens) > 1 else ""

        def _script_effective() -> str:
            return directives.get("script-src", directives.get("default-src", ""))

        script_val = _script_effective()

        # 1. unsafe-inline in script-src / default-src (HIGH)
        if "'unsafe-inline'" in script_val:
            results.append(Finding(
                check_id="http_headers.weak_csp.script_unsafe_inline",
                title="CSP: 'unsafe-inline' in script-src allows arbitrary inline JavaScript",
                description=(
                    "The script-src (or default-src fallback) permits 'unsafe-inline', "
                    "which lets attackers inject and execute inline <script> tags. "
                    "This largely negates XSS protection."
                ),
                severity=Severity.HIGH,
                affected_url=url,
                evidence=[Evidence(label="script-src", value=self._truncate(script_val))],
                remediation=(
                    "Remove 'unsafe-inline' from script-src. "
                    "Use a per-request nonce or sha256 hash for inline blocks instead."
                ),
                cwe="CWE-693",
                references=["https://csp.withgoogle.com/docs/strict-csp.html"],
            ))

        # 2. unsafe-eval in script-src / default-src (HIGH)
        if "'unsafe-eval'" in script_val:
            results.append(Finding(
                check_id="http_headers.weak_csp.script_unsafe_eval",
                title="CSP: 'unsafe-eval' in script-src allows eval() and similar sinks",
                description=(
                    "Permitting 'unsafe-eval' allows eval(), Function(), "
                    "and setTimeout(string). Exploitable if user-controlled data reaches those sinks."
                ),
                severity=Severity.HIGH,
                affected_url=url,
                evidence=[Evidence(label="script-src", value=self._truncate(script_val))],
                remediation="Remove 'unsafe-eval'. Refactor code to avoid eval() patterns.",
                cwe="CWE-693",
            ))

        # 3. unsafe-inline in script-src-attr (MEDIUM — inline event handlers)
        attr_val = directives.get("script-src-attr", "")
        if "'unsafe-inline'" in attr_val:
            results.append(Finding(
                check_id="http_headers.weak_csp.script_src_attr_unsafe_inline",
                title="CSP: 'unsafe-inline' in script-src-attr allows inline event handlers",
                description=(
                    "script-src-attr controls inline event handlers (onclick, onerror, etc.). "
                    "'unsafe-inline' here allows attackers to inject handlers via HTML injection."
                ),
                severity=Severity.MEDIUM,
                affected_url=url,
                evidence=[Evidence(label="script-src-attr", value=self._truncate(attr_val))],
                remediation=(
                    "Remove 'unsafe-inline' from script-src-attr. "
                    "Use addEventListener() in external scripts instead of inline handlers."
                ),
                cwe="CWE-693",
            ))

        # 4. unsafe-inline in style-src (LOW — CSS injection)
        style_val = directives.get("style-src", directives.get("default-src", ""))
        if "'unsafe-inline'" in style_val:
            results.append(Finding(
                check_id="http_headers.weak_csp.style_unsafe_inline",
                title="CSP: 'unsafe-inline' in style-src allows inline styles",
                description=(
                    "Inline styles can be used for CSS-based data exfiltration and "
                    "UI-redressing attacks. Prefer external stylesheets or nonce/hash."
                ),
                severity=Severity.LOW,
                affected_url=url,
                evidence=[Evidence(label="style-src", value=self._truncate(style_val))],
                remediation=(
                    "Remove 'unsafe-inline' from style-src. "
                    "Use a nonce or hash for any necessary inline <style> blocks."
                ),
                cwe="CWE-693",
            ))

        # 5. Wildcard host in script-src (MEDIUM)
        if _re.search(r"(?:^|\s)\*(?:\s|$)", script_val):
            results.append(Finding(
                check_id="http_headers.weak_csp.script_wildcard",
                title="CSP: wildcard (*) in script-src trusts any origin",
                description="A bare wildcard in script-src allows scripts from any host.",
                severity=Severity.MEDIUM,
                affected_url=url,
                evidence=[Evidence(label="script-src", value=self._truncate(script_val))],
                remediation="Replace * with explicit trusted host names.",
                cwe="CWE-693",
            ))

        # 6. http: scheme in any directive (LOW — mixed content)
        for name, val in directives.items():
            if "http:" in val.split():
                results.append(Finding(
                    check_id=f"http_headers.weak_csp.http_scheme.{name.replace('-', '_')}",
                    title=f"CSP: http: scheme allowed in {name}",
                    description=(
                        f"The {name} directive permits http: sources, "
                        "allowing resources over unencrypted connections (MITM injection risk)."
                    ),
                    severity=Severity.LOW,
                    affected_url=url,
                    evidence=[Evidence(label=name, value=self._truncate(val))],
                    remediation=f"Replace http: with https: in the {name} directive.",
                    cwe="CWE-319",
                ))
                break

        return results
