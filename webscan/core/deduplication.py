"""core/deduplication.py — Remove duplicate findings and apply suppressions."""
from __future__ import annotations

import re
from pathlib import Path

import yaml

from core.models import Finding, Severity


def deduplicate(findings: list[Finding]) -> list[Finding]:
    """
    Collapse findings that share the same (check_id, affected_url).
    When duplicates exist, keep the one with the highest severity.
    """
    _order = list(Severity)

    def sev_rank(s: Severity) -> int:
        return _order.index(s)

    seen: dict[tuple[str, str], Finding] = {}
    for f in findings:
        key = (f.check_id, f.affected_url)
        if key not in seen or sev_rank(f.severity) < sev_rank(seen[key].severity):
            seen[key] = f
    return list(seen.values())


def load_suppressions(suppression_file: str = "suppression.yaml") -> list[dict]:
    """Load suppression rules from a YAML file if it exists."""
    path = Path(suppression_file)
    if not path.exists():
        return []
    with path.open(encoding="utf-8") as fh:
        data = yaml.safe_load(fh) or {}
    return data.get("suppressions", [])


def apply_suppressions(findings: list[Finding], suppressions: list[dict]) -> list[Finding]:
    """
    Remove findings that match a suppression rule.

    Suppression rule fields (all optional, AND-combined):
      check_id_pattern: regex matched against finding.check_id
      url_pattern:      regex matched against finding.affected_url
      reason:           human-readable string (for audit trail)
    """
    if not suppressions:
        return findings

    def is_suppressed(f: Finding) -> bool:
        for rule in suppressions:
            cid_pat = rule.get("check_id_pattern", "")
            url_pat = rule.get("url_pattern", "")
            if cid_pat and not re.search(cid_pat, f.check_id):
                continue
            if url_pat and not re.search(url_pat, f.affected_url):
                continue
            return True
        return False

    return [f for f in findings if not is_suppressed(f)]
