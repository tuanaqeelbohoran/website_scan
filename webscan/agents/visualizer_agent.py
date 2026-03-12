"""agents/visualizer_agent.py — builds graph_data dict for UI Plotly components.

This agent post-processes the ScanResult to produce a serialisable dictionary
that the UI can consume directly.  No LLM call is needed here — the heavy
lifting is pure Python aggregation.

Returned dict shape (all keys present even when empty):
{
  "severity_counts":  {severity_value: int, …},
  "check_scores":     [{check_id, count, max_severity, weight}, …],
  "timeline":         [{timestamp, check_id, severity}, …],   # if timestamps available
  "top_findings":     [serialised Finding dicts, …]           # top 5 by weight
}
"""
from __future__ import annotations

from collections import defaultdict

from agents.base_agent import BaseAgent
from core.models import Finding, Severity, ScanResult

_WEIGHT = {
    Severity.CRITICAL: 16,
    Severity.HIGH:     8,
    Severity.MEDIUM:   4,
    Severity.LOW:      2,
    Severity.INFO:     1,
    Severity.PASS:     0,
}


class VisualizerAgent(BaseAgent):
    """Build graph_data from a ScanResult (no LLM call required)."""

    async def run(self, result: ScanResult) -> dict:
        findings = result.findings

        # ── Severity counts ──────────────────────────────────────────────────
        sev_counts: dict[str, int] = {s.value: 0 for s in Severity}
        for f in findings:
            sev_counts[f.severity.value] += 1

        # ── Per-check aggregation ────────────────────────────────────────────
        check_agg: dict[str, dict] = defaultdict(
            lambda: {"count": 0, "weight": 0, "max_sev": Severity.PASS}
        )
        for f in findings:
            agg = check_agg[f.check_id]
            agg["count"]  += 1
            agg["weight"] += _WEIGHT[f.severity]
            if _WEIGHT[f.severity] > _WEIGHT[agg["max_sev"]]:
                agg["max_sev"] = f.severity

        check_scores = [
            {
                "check_id":    cid,
                "count":       d["count"],
                "max_severity": d["max_sev"].value,
                "weight":      d["weight"],
            }
            for cid, d in sorted(check_agg.items(), key=lambda x: -x[1]["weight"])
        ]

        # ── Top-5 findings ───────────────────────────────────────────────────
        top_5 = sorted(findings, key=lambda f: -_WEIGHT[f.severity])[:5]
        top_findings = [
            {
                "check_id":    f.check_id,
                "title":       f.title,
                "severity":    f.severity.value,
                "affected_url": f.affected_url,
            }
            for f in top_5
        ]

        return {
            "severity_counts": sev_counts,
            "check_scores":    check_scores,
            "top_findings":    top_findings,
            "risk_score":      result.risk_score,
        }
