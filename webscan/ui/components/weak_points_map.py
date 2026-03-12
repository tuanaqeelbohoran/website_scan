"""ui/components/weak_points_map.py — Plotly treemap showing risk by check category."""
from __future__ import annotations

from collections import defaultdict

from nicegui import ui

from core.models import Finding, Severity

# Numeric weight used to size the treemap tiles
_WEIGHT = {
    Severity.CRITICAL: 16,
    Severity.HIGH:     8,
    Severity.MEDIUM:   4,
    Severity.LOW:      2,
    Severity.INFO:     1,
    Severity.PASS:     0,
}
_COLOUR = {
    Severity.CRITICAL: "#c0392b",
    Severity.HIGH:     "#e67e22",
    Severity.MEDIUM:   "#f1c40f",
    Severity.LOW:      "#2ecc71",
    Severity.INFO:     "#3498db",
    Severity.PASS:     "#95a5a6",
}


def weak_points_map(findings: list[Finding]) -> None:
    """Render a Plotly treemap of risk.

    Root → check_category (first segment of check_id, e.g. 'website', 'ai_endpoint')
         → check_id
    Tile size  ∝ sum of severity weights.
    Tile colour = worst severity in that tile.
    """
    if not findings:
        ui.label("No findings to display.").classes("text-grey-5")
        return

    # Aggregate per check_id
    per_check: dict[str, dict] = defaultdict(lambda: {"weight": 0, "worst": Severity.PASS})
    for f in findings:
        d = per_check[f.check_id]
        d["weight"] += _WEIGHT[f.severity]
        if _WEIGHT[f.severity] > _WEIGHT[d["worst"]]:
            d["worst"] = f.severity

    labels:  list[str] = ["All Findings"]
    parents: list[str] = [""]
    values:  list[int] = [0]
    colours: list[str] = ["#2c3e50"]

    categories: set[str] = set()
    for check_id in per_check:
        cat = check_id.split(".")[0] if "." in check_id else "general"
        categories.add(cat)

    for cat in sorted(categories):
        labels.append(cat)
        parents.append("All Findings")
        w = sum(
            v["weight"] for cid, v in per_check.items()
            if (cid.split(".")[0] if "." in cid else "general") == cat
        )
        values.append(w)
        colours.append("#34495e")

    for check_id, d in sorted(per_check.items(), key=lambda x: -x[1]["weight"]):
        cat = check_id.split(".")[0] if "." in check_id else "general"
        labels.append(check_id)
        parents.append(cat)
        values.append(d["weight"])
        colours.append(_COLOUR[d["worst"]])

    fig = {
        "data": [
            {
                "type":    "treemap",
                "labels":  labels,
                "parents": parents,
                "values":  values,
                "marker":  {"colors": colours},
                "hovertemplate": "<b>%{label}</b><br>Risk weight: %{value}<extra></extra>",
            }
        ],
        "layout": {
            "title":  "Weak-points map — risk by check",
            "margin": {"l": 10, "r": 10, "t": 50, "b": 10},
            "height": 400,
        },
    }
    ui.plotly(fig).classes("w-full")
