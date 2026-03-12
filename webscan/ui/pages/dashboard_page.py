"""ui/pages/dashboard_page.py — findings dashboard after scan completion."""
from __future__ import annotations

import httpx
from nicegui import ui

from core.models import Finding, Severity
from ui.components.finding_card import finding_card
from ui.components.severity_heatmap import severity_heatmap
from ui.components.weak_points_map import weak_points_map

_SEV_COLOUR = {
    "critical": "red-14",
    "high":     "deep-orange-9",
    "medium":   "orange-9",
    "low":      "yellow-9",
    "info":     "blue-7",
    "pass":     "green-7",
}


def _parse_finding(raw: dict) -> Finding:
    from core.models import Evidence, Severity
    return Finding(
        check_id      = raw.get("check_id", ""),
        title         = raw.get("title") or raw.get("check_id", ""),
        severity      = Severity(raw.get("severity", "info")),
        description   = raw.get("description", ""),
        affected_url  = raw.get("affected_url") or "",
        remediation   = raw.get("remediation") or "",
        references    = raw.get("references") or [],
        evidence      = [
            Evidence(label=e.get("label", ""), value=e.get("value", ""))
            for e in (raw.get("evidence") or [])
        ],
        cwe           = raw.get("cwe") or "",
        cvss_score    = raw.get("cvss_score"),
        framework_refs= raw.get("framework_refs") or {},
    )


async def _fetch_report(scan_id: str) -> dict | None:
    try:
        async with httpx.AsyncClient(timeout=15) as client:
            resp = await client.get(f"http://127.0.0.1:8080/api/report/{scan_id}/report.json")
        if resp.status_code == 200:
            return resp.json()
    except Exception:
        pass
    return None


def dashboard_page(scan_id: str) -> None:
    """Render the findings dashboard for a completed scan."""

    container = ui.column().classes("w-full q-pa-md")

    async def load_data() -> None:
        with container:
            ui.label("Loading results…").classes("text-grey-5")

        data = await _fetch_report(scan_id)
        container.clear()

        with container:
            if data is None:
                ui.label("Could not load results.").classes("text-negative")
                ui.button("Back", on_click=lambda: ui.navigate.to("/")).props("flat")
                return

            meta      = data.get("metadata", {})
            raw_finds = data.get("findings", [])
            findings  = [_parse_finding(f) for f in raw_finds]

            # ── Header ──────────────────────────────────────────────────────
            with ui.row().classes("items-center justify-between w-full q-mb-md"):
                ui.label("Scan Results").classes("text-h5 text-weight-bold")
                ui.button("New scan", on_click=lambda: ui.navigate.to("/"), icon="add").props("flat")

            # ── Summary chips ────────────────────────────────────────────────
            sev_counts: dict[str, int] = {s.value: 0 for s in Severity}
            for f in findings:
                sev_counts[f.severity.value] += 1

            with ui.row().classes("gap-2 q-mb-sm flex-wrap"):
                ui.label(f"Target: {meta.get('target_url', scan_id)}").classes("text-caption")
                ui.label(f"Risk score: {meta.get('risk_score', '?')}/100").classes(
                    "text-caption font-bold"
                )
                for sev, cnt in sev_counts.items():
                    if cnt:
                        ui.chip(f"{sev.upper()}: {cnt}", color=_SEV_COLOUR.get(sev, "grey")).props(
                            "dense"
                        )

            # ── Visuals ──────────────────────────────────────────────────────
            if findings:
                with ui.tabs().classes("w-full") as tabs:
                    tab_heat = ui.tab("Heatmap",   icon="grid_on")
                    tab_tree = ui.tab("Risk map",  icon="account_tree")
                    tab_list = ui.tab("Findings",  icon="list")

                with ui.tab_panels(tabs, value=tab_heat).classes("w-full"):
                    with ui.tab_panel(tab_heat):
                        severity_heatmap(findings)
                    with ui.tab_panel(tab_tree):
                        weak_points_map(findings)
                    with ui.tab_panel(tab_list):
                        for f in sorted(
                            findings,
                            key=lambda x: list(Severity).index(x.severity),
                        ):
                            finding_card(f)
            else:
                ui.label("No findings — target looks clean!").classes("text-positive text-h6 q-mt-lg")

            # ── Download buttons ──────────────────────────────────────────────
            ui.separator().classes("q-my-md")
            with ui.row().classes("gap-2"):
                ui.button(
                    "Download JSON",
                    icon="download",
                    on_click=lambda: ui.download(
                        f"http://127.0.0.1:8080/api/report/{scan_id}/report.json"
                    ),
                ).props("outline")
                ui.button(
                    "Download PDF",
                    icon="picture_as_pdf",
                    on_click=lambda: ui.download(
                        f"http://127.0.0.1:8080/api/report/{scan_id}/report.pdf"
                    ),
                ).props("outline")
                ui.button(
                    "Download SARIF",
                    icon="code",
                    on_click=lambda: ui.download(
                        f"http://127.0.0.1:8080/api/report/{scan_id}/report.sarif"
                    ),
                ).props("outline")

    ui.timer(0.05, load_data, once=True)
