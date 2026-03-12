"""ui/components/finding_card.py — reusable finding detail component."""
from __future__ import annotations

from nicegui import ui

from core.models import Finding, Severity

_SEVERITY_COLOUR = {
    Severity.CRITICAL: "red-14",
    Severity.HIGH:     "deep-orange-9",
    Severity.MEDIUM:   "orange-9",
    Severity.LOW:      "yellow-9",
    Severity.INFO:     "blue-7",
    Severity.PASS:     "green-7",
}

_SEVERITY_TEXT = {
    Severity.CRITICAL: "text-white",
    Severity.HIGH:     "text-white",
    Severity.MEDIUM:   "text-white",
    Severity.LOW:      "text-black",
    Severity.INFO:     "text-white",
    Severity.PASS:     "text-white",
}


def finding_card(f: Finding) -> None:
    """Render a single finding as a NiceGUI card with collapsible evidence."""
    colour  = _SEVERITY_COLOUR.get(f.severity, "grey-7")
    txt_cls = _SEVERITY_TEXT.get(f.severity, "text-white")

    with ui.card().classes("w-full q-mb-sm"):
        with ui.row().classes("items-center justify-between w-full"):
            with ui.row().classes("items-center gap-2"):
                ui.badge(f.severity.value.upper(), color=colour).classes(txt_cls)
                ui.label(f.title or f.check_id).classes("text-subtitle1 font-bold")
            ui.label(f.check_id).classes("text-caption text-grey-6")

        if f.affected_url:
            ui.label(f"Target: {f.affected_url}").classes("text-caption text-grey-7")

        if f.description:
            ui.label(f.description).classes("text-body2 q-mt-xs")

        if f.remediation:
            with ui.expansion("Remediation", icon="build").classes("w-full q-mt-xs"):
                ui.label(f.remediation).classes("text-body2")

        if f.evidence:
            with ui.expansion(f"Evidence ({len(f.evidence)})", icon="info").classes("w-full"):
                for e in f.evidence:
                    with ui.row().classes("gap-2 items-start"):
                        ui.label(e.label).classes("text-caption text-weight-bold")
                        ui.label(str(e.value)).classes("text-caption font-mono text-grey-8")

        if f.references:
            with ui.expansion("References", icon="open_in_new").classes("w-full"):
                for ref in f.references:
                    ui.link(ref, ref, new_tab=True).classes("text-caption")

        if f.framework_refs:
            with ui.row().classes("gap-1 q-mt-xs flex-wrap"):
                for tag, val in f.framework_refs.items():
                    ui.chip(f"{tag}: {val}", icon="label").props("dense outline")
