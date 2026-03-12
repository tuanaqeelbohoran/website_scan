"""agents/reporter_agent.py — LLM-drafted executive summary.

Drafts a short executive-summary paragraph for the PDF report.

Safety rules enforced:
- The prompt explicitly forbids inventing CVEs, version numbers, or CWE IDs.
- The LLM is given ONLY the deduplicated, structured finding list — no raw
  HTTP responses that might contain prompt-injection payloads.
- Output is capped at MAX_TOKENS_OUT=512 characters by the base class.
- The draft is prefixed with a disclaimer before being inserted into reports.
"""
from __future__ import annotations

import logging

from agents.base_agent import BaseAgent
from core.models import ScanResult, Severity

log = logging.getLogger("webscan.agents")

_DISCLAIMER = (
    "[AI-ASSISTED SUMMARY — review before relying on this text.  "
    "All findings are sourced from automated checks only.]\n\n"
)


class ReporterAgent(BaseAgent):
    """Draft an executive summary paragraph from a completed ScanResult."""

    async def run(self, result: ScanResult) -> str:
        """Return a plain-text executive summary string (empty string if disabled)."""
        if not self._enabled:
            return ""

        # Build a safe, compact description for the prompt
        by_sev = result.by_severity
        lines  = []
        for sev in Severity:
            fs = by_sev.get(sev, [])
            if fs:
                titles = ", ".join(f.title or f.check_id for f in fs[:5])
                if len(fs) > 5:
                    titles += f" … and {len(fs) - 5} more"
                lines.append(f"  {sev.value.upper()}: {titles}")

        if not lines:
            return ""

        finding_summary = "\n".join(lines)
        user_msg = (
            f"Target: {result.target_url}\n"
            f"Scan type: {result.scan_type.value if result.scan_type else 'website'}\n"
            f"Risk score: {result.risk_score}/100\n\n"
            f"Finding summary:\n{finding_summary}\n\n"
            "Write a 3–5 sentence executive summary suitable for a non-technical "
            "stakeholder.  Focus on business impact.  "
            "DO NOT invent CVE IDs, CWE IDs, version numbers, or specific exploits."
        )

        draft = await self._prompt(
            system=(
                "You are a professional security report writer. "
                "Write clear, factual, businessfocused executive summaries. "
                "Never invent technical details beyond what is provided. "
                "Never suggest offensive actions."
            ),
            user=user_msg,
        )

        if not draft:
            return ""

        return _DISCLAIMER + draft
