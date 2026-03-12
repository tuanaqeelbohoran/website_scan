"""checks/ai_endpoint/rate_limit_headers.py — Rate-limit signal header check."""
from __future__ import annotations

from checks.base import BaseCheck
from core.models import Evidence, Finding, Severity, ScanType

_RATELIMIT_HEADERS = (
    "x-ratelimit-limit",
    "x-ratelimit-remaining",
    "x-ratelimit-reset",
    "ratelimit-limit",
    "ratelimit-remaining",
    "ratelimit-reset",
    "retry-after",
)


class RateLimitHeadersCheck(BaseCheck):
    check_id = "ai.rate_limit_headers"
    scan_type = ScanType.AI_ENDPOINT
    description = "Checks for the presence of rate-limit signal headers in AI endpoint responses."

    async def run(self, target_url: str, session, config: dict) -> list[Finding]:
        findings: list[Finding] = []
        try:
            resp = await session.head(target_url, follow_redirects=True)
        except Exception:
            return findings

        lower = {k.lower(): v for k, v in resp.headers.items()}
        present = [h for h in _RATELIMIT_HEADERS if h in lower]

        if not present:
            findings.append(Finding(
                check_id="ai.rate_limit_headers.missing",
                title="No rate-limit signal headers in AI endpoint response",
                description=(
                    "Without rate-limit headers (X-RateLimit-Limit, Retry-After, etc.) "
                    "callers cannot detect throttling programmatically, risking runaway costs."
                ),
                severity=Severity.MEDIUM,
                affected_url=target_url,
                remediation=(
                    "Return X-RateLimit-Limit, X-RateLimit-Remaining, X-RateLimit-Reset, "
                    "and Retry-After headers on all responses."
                ),
                references=["https://datatracker.ietf.org/doc/html/draft-ietf-httpapi-ratelimit-headers"],
                framework_refs={"owasp_llm": "LLM04 — Model Denial of Service"},
            ))
        else:
            for h in present:
                findings.append(Finding(
                    check_id=f"ai.rate_limit_headers.present.{h.replace('-', '_')}",
                    title=f"Rate-limit header present: {h} ✓",
                    severity=Severity.PASS,
                    affected_url=target_url,
                    evidence=[Evidence(label=h, value=self._truncate(lower[h]))],
                ))

        return findings
