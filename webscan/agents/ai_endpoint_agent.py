"""agents/ai_endpoint_agent.py — maps AI endpoint findings to OWASP LLM Top 10 / MITRE ATLAS.

After all AI endpoint checks have run, this agent:
1. Calls the LLM to suggest OWASP LLM Top 10 and MITRE ATLAS mappings for each finding.
2. Merges the mappings into finding.framework_refs (additive only).

Safety: LLM output is parsed conservatively — only known OWASP-LLM and ATLAS tags
are accepted.  Arbitrary strings are rejected.
"""
from __future__ import annotations

import json
import logging
import re

from agents.base_agent import BaseAgent
from core.models import Finding

log = logging.getLogger("webscan.agents")

# Known OWASP LLM Top 10 identifiers (2023 v1.1)
_OWASP_LLM_TAGS = frozenset({
    "LLM01", "LLM02", "LLM03", "LLM04", "LLM05",
    "LLM06", "LLM07", "LLM08", "LLM09", "LLM10",
})

# MITRE ATLAS technique prefix pattern  (AML.T followed by 4 digits)
_ATLAS_PATTERN = re.compile(r"^AML\.T\d{4}(\.000)?$")


def _valid_tag(tag: str) -> bool:
    tag = tag.strip()
    return tag in _OWASP_LLM_TAGS or bool(_ATLAS_PATTERN.match(tag))


class AIEndpointAgent(BaseAgent):
    """Enrich AI endpoint findings with OWASP LLM + MITRE ATLAS tags."""

    async def run(self, findings: list[Finding]) -> list[Finding]:
        if not findings or not self._enabled:
            return findings

        summaries = "\n".join(
            f"  {i}. {f.check_id}: {f.title} (severity={f.severity.value})"
            for i, f in enumerate(findings)
        )

        user_msg = (
            f"AI endpoint findings:\n{summaries}\n\n"
            "For each finding, suggest relevant OWASP LLM Top 10 (e.g. LLM01) "
            "and MITRE ATLAS (e.g. AML.T0040) identifiers. "
            "Reply ONLY with valid JSON — a list of objects: "
            '{"index": 0, "owasp_llm": ["LLM01"], "atlas": ["AML.T0040"]}. '
            "Only include well-known identifiers.  Omit findings with no mapping."
        )

        raw = await self._prompt(
            system=(
                "You are an AI security expert specialising in OWASP LLM Top 10 "
                "and MITRE ATLAS framework mappings.  Reply only with compact JSON."
            ),
            user=user_msg,
        )

        if not raw:
            return findings

        try:
            start = raw.find("[")
            end   = raw.rfind("]") + 1
            if start == -1 or end == 0:
                return findings
            mappings: list[dict] = json.loads(raw[start:end])
        except json.JSONDecodeError:
            log.debug("AIEndpointAgent: could not parse LLM JSON: %s", raw[:200])
            return findings

        updated = list(findings)
        for mapping in mappings:
            idx = mapping.get("index")
            if not isinstance(idx, int) or idx < 0 or idx >= len(updated):
                continue
            f   = updated[idx]
            new_refs = dict(f.framework_refs) if f.framework_refs else {}
            for tag in mapping.get("owasp_llm", []):
                if _valid_tag(str(tag).strip()):
                    new_refs.setdefault("OWASP-LLM", str(tag).strip())
            for tag in mapping.get("atlas", []):
                if _valid_tag(str(tag).strip()):
                    new_refs.setdefault("MITRE-ATLAS", str(tag).strip())
            if new_refs != (f.framework_refs or {}):
                updated[idx] = Finding(
                    check_id      = f.check_id,
                    title         = f.title,
                    severity      = f.severity,
                    description   = f.description,
                    affected_url  = f.affected_url,
                    remediation   = f.remediation,
                    references    = f.references,
                    evidence      = f.evidence,
                    cwe           = f.cwe,
                    cvss_score    = f.cvss_score,
                    framework_refs= new_refs,
                )

        return updated
