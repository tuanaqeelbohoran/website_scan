"""ui/components/severity_heatmap.py — Plotly heatmap: check × severity."""
from __future__ import annotations

from collections import defaultdict

from nicegui import ui

from core.models import Finding, Severity

_SEVERITY_ORDER = [
    Severity.CRITICAL,
    Severity.HIGH,
    Severity.MEDIUM,
    Severity.LOW,
    Severity.INFO,
    Severity.PASS,
]


def severity_heatmap(findings: list[Finding]) -> None:
    """Render a Plotly heatmap showing how many findings each check produced per severity."""
    # Gather unique check ids
    check_ids = sorted({f.check_id for f in findings})
    if not check_ids:
        ui.label("No findings to display.").classes("text-grey-5")
        return

    sev_labels = [s.value for s in _SEVERITY_ORDER]

    # Build matrix: rows=severity, cols=check
    matrix: dict[str, dict[str, int]] = defaultdict(lambda: defaultdict(int))
    for f in findings:
        matrix[f.severity.value][f.check_id] += 1

    z: list[list[int]] = []
    for sev in sev_labels:
        row = [matrix[sev].get(cid, 0) for cid in check_ids]
        z.append(row)

    fig = {
        "data": [
            {
                "type":       "heatmap",
                "z":          z,
                "x":          check_ids,
                "y":          sev_labels,
                "colorscale": [
                    [0.0,  "#ffffff"],
                    [0.01, "#ffe0e0"],
                    [0.5,  "#ff8080"],
                    [1.0,  "#cc0000"],
                ],
                "hoverongaps": False,
                "showscale": True,
            }
        ],
        "layout": {
            "title":   "Findings heatmap — check × severity",
            "xaxis":   {"tickangle": -30},
            "yaxis":   {"autorange": "reversed"},
            "margin":  {"l": 100, "r": 20, "t": 50, "b": 120},
            "height":  320,
        },
    }
    ui.plotly(fig).classes("w-full")
