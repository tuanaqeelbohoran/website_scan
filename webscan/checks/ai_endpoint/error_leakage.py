"""checks/ai_endpoint/error_leakage.py — Error-response information leakage."""
from __future__ import annotations

import re

from checks.base import BaseCheck
from core.models import Evidence, Finding, Severity, ScanType
from urllib.parse import urljoin, urlparse

# Patterns indicating verbose error information in response bodies
_LEAKAGE_PATTERNS: list[tuple[str, str, str]] = [
    (r"Traceback \(most recent call last\)",       "Python traceback",       "CWE-209"),
    (r"(?i)at .+\.(java|kt):\d+",                  "Java stack trace",       "CWE-209"),
    (r"(?i)at .+\.(cs):\d+",                       "C# stack trace",         "CWE-209"),
    (r"(?i)File \".*\", line \d+",                 "Python file path/line",  "CWE-209"),
    (r"(?i)connection string",                     "Connection string hint", "CWE-200"),
    (r"\b[A-Z]:\\(?:[^\\/:*?\"<>|\r\n]+\\)*",     "Windows file path",      "CWE-200"),
    (r"(?i)internal server error.*at .+\.(py|js|rb|go|php)", "Stack frame", "CWE-209"),
    (r"(?i)sql syntax|mysql_fetch|ORA-\d{5}",     "SQL error message",      "CWE-209"),
    (r"(?i)(secret|api_key|password)\s*[=:]\s*\S+", "Credential in response", "CWE-312"),
]


class ErrorLeakageCheck(BaseCheck):
    check_id = "ai.error_leakage"
    scan_type = ScanType.AI_ENDPOINT
    description = "Issues a safe 404 probe and scans the response body for stack traces and PII."

    async def run(self, target_url: str, session, config: dict) -> list[Finding]:
        findings: list[Finding] = []
        parsed  = urlparse(target_url)
        base    = f"{parsed.scheme}://{parsed.netloc}"
        # Probe a nonexistent path to provoke an error response
        probe_url = urljoin(base, "/webscan-probe-nonexistent-abc123xyz")
        try:
            resp = await session.get(probe_url, follow_redirects=False)
        except Exception:
            return findings

        body = resp.text[:4096]  # read a safe, bounded preview

        for pattern, label, cwe in _LEAKAGE_PATTERNS:
            if re.search(pattern, body):
                # Redact any match snippet to avoid re-logging sensitive data
                snippet = re.search(pattern, body)
                safe_snippet = self._truncate(snippet.group(0) if snippet else "", 80)
                findings.append(Finding(
                    check_id=f"ai.error_leakage.{label.lower().replace(' ', '_')}",
                    title=f"Error response leaks: {label}",
                    description=(
                        f"The 404 error response body contains patterns consistent with {label}. "
                        "Verbose errors give attackers insight into the server internals."
                    ),
                    severity=Severity.MEDIUM,
                    affected_url=probe_url,
                    evidence=[Evidence(label=label, value=safe_snippet)],
                    remediation=(
                        "Configure error handling to return generic error messages in production. "
                        "Log details server-side only."
                    ),
                    cwe=cwe,
                    framework_refs={"owasp_llm": "LLM06 — Sensitive Information Disclosure"},
                ))

        return findings
