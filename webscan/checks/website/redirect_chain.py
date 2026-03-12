"""checks/website/redirect_chain.py — Redirect chain analysis."""
from __future__ import annotations

from checks.base import BaseCheck
from config.defaults import MAX_REDIRECTS
from core.models import Evidence, Finding, Severity, ScanType


class RedirectChainCheck(BaseCheck):
    check_id = "redirect_chain"
    scan_type = ScanType.WEBSITE
    description = "Follows and audits redirect hops for HTTPS downgrades and long chains."

    async def run(self, target_url: str, session, config: dict) -> list[Finding]:
        findings: list[Finding] = []
        current_url = target_url
        hops: list[str] = [target_url]
        max_hops = min(config.get("max_redirects", MAX_REDIRECTS), MAX_REDIRECTS)

        for _ in range(max_hops):
            try:
                resp = await session.head(current_url, follow_redirects=False)
            except Exception:
                break

            if resp.status_code not in (301, 302, 303, 307, 308):
                break

            location = resp.headers.get("location", "").strip()
            if not location:
                break

            # Detect HTTPS → HTTP downgrade
            if current_url.lower().startswith("https://") and location.lower().startswith("http://"):
                findings.append(Finding(
                    check_id="redirect_chain.https_downgrade",
                    title="Redirect downgrades HTTPS to HTTP",
                    description=(
                        f"A redirect from '{current_url}' leads to the insecure "
                        f"URL '{location}'."
                    ),
                    severity=Severity.HIGH,
                    affected_url=current_url,
                    evidence=[
                        Evidence(label="From", value=current_url),
                        Evidence(label="To",   value=location),
                    ],
                    remediation="Ensure all redirects preserve the https:// scheme.",
                    cwe="CWE-319",
                ))

            hops.append(location)
            current_url = location

        if len(hops) > 4:
            findings.append(Finding(
                check_id="redirect_chain.long_chain",
                title=f"Redirect chain contains {len(hops) - 1} hops",
                description="Long redirect chains add latency and complicate debugging.",
                severity=Severity.LOW,
                affected_url=target_url,
                evidence=[Evidence(label="Chain", value=" → ".join(hops))],
                remediation="Consolidate redirects to a single hop where possible.",
            ))

        # Confirm plain HTTP redirects to HTTPS (positive check)
        if (
            target_url.lower().startswith("http://")
            and len(hops) > 1
            and hops[1].lower().startswith("https://")
            and not any("https_downgrade" in f.check_id for f in findings)
        ):
            findings.append(Finding(
                check_id="redirect_chain.http_to_https_pass",
                title="HTTP correctly redirects to HTTPS",
                severity=Severity.PASS,
                affected_url=target_url,
                evidence=[Evidence(label="Chain", value=" → ".join(hops[:2]))],
            ))

        return findings
