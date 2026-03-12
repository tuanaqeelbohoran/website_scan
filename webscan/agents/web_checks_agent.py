"""agents/web_checks_agent.py — re-scores website findings in tech-stack context.

After all website checks have run, this agent asks the LLM to adjust severity
ratings in light of the detected technology stack (from tech_fingerprint.py).
It then returns a list of updated Finding objects.

Safety note: the LLM output is parsed very conservatively — only lowercase
severity strings matching the Severity enum are accepted.  Any unexpected
output leaves the original severity unchanged.
"""
from __future__ import annotations

import json
import logging

from agents.base_agent import BaseAgent
from core.models import Evidence, Finding, Severity

log = logging.getLogger("webscan.agents")

_VALID_SEVERITIES = {s.value for s in Severity}


class WebChecksAgent(BaseAgent):
    """Contextually re-score website findings using the detected tech stack."""

    async def run(
        self,
        findings: list[Finding],
        tech_stack: list[str],
    ) -> list[Finding]:
        """Return a (possibly updated) copy of findings.

        Only re-scores non-PASS findings.  Severity can only be raised, not
        lowered, to avoid the LLM suppressing real issues.
        """
        if not findings or not self._enabled:
            return findings

        actionable = [f for f in findings if f.severity not in (Severity.PASS, Severity.INFO)]
        if not actionable:
            return findings

        # Build a compact description of findings for the prompt
        finding_descs = "\n".join(
            f"  {i}. [{f.severity.value}] {f.check_id}: {f.title}"
            for i, f in enumerate(actionable)
        )

        user_msg = (
            f"Technology stack detected: {', '.join(tech_stack) or 'unknown'}\n\n"
            f"Findings:\n{finding_descs}\n\n"
            "For each finding, decide whether the severity should be RAISED "
            "(e.g. missing HSTS is critical on a banking site).  "
            "Reply ONLY with valid JSON: a list of objects like "
            '{"index": 0, "new_severity": "high"} for each finding you want to RAISE. '
            "Omit findings that should stay the same.  "
            "Valid severities: critical, high, medium, low.  "
            "DO NOT lower any severity."
        )
        raw = await self._prompt(
            system=(
                "You are a defensive security analyst. "
                "Re-evaluate findings based on the detected technology stack. "
                "Only raise severities when the tech stack makes the issue more critical. "
                "Reply with compact JSON only — no prose."
            ),
            user=user_msg,
        )

        if not raw:
            return findings

        # Parse LLM output safely
        try:
            # Extract first JSON array or object from the response
            start = raw.find("[")
            end   = raw.rfind("]") + 1
            if start == -1 or end == 0:
                return findings
            adjustments: list[dict] = json.loads(raw[start:end])
        except json.JSONDecodeError:
            log.debug("WebChecksAgent: could not parse LLM JSON: %s", raw[:200])
            return findings

        # Apply adjustments (only raises)
        updated = list(findings)
        for adj in adjustments:
            idx      = adj.get("index")
            new_sev  = str(adj.get("new_severity", "")).lower()
            if not isinstance(idx, int) or new_sev not in _VALID_SEVERITIES:
                continue
            if idx < 0 or idx >= len(actionable):
                continue
            target_finding = actionable[idx]
            new_severity   = Severity(new_sev)
            # Only raise
            sev_order = list(Severity)
            if sev_order.index(new_severity) < sev_order.index(target_finding.severity):
                # Find this finding in the full list and update
                for i, f in enumerate(updated):
                    if f is target_finding:
                        updated[i] = Finding(
                            check_id      = f.check_id,
                            title         = f.title,
                            severity      = new_severity,
                            description   = f.description,
                            affected_url  = f.affected_url,
                            remediation   = f.remediation,
                            references    = f.references,
                            evidence      = list(f.evidence) + [Evidence(
                                label="Agent re-score",
                                value=f"Raised from {f.severity.value} by web_checks_agent (tech stack: {', '.join(tech_stack)})",
                            )],
                            cwe           = f.cwe,
                            cvss_score    = f.cvss_score,
                            framework_refs= f.framework_refs,
                        )
                        break

        return updated
