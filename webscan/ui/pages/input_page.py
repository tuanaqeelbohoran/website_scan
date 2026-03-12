"""ui/pages/input_page.py — URL input, scan type selector, consent gate."""
from __future__ import annotations

import httpx
from nicegui import ui


def input_page() -> None:
    """Render the landing / scan submission page."""

    with ui.column().classes("items-center w-full q-pa-md"):
        ui.label("WebScan — Defensive Vulnerability Checker").classes(
            "text-h4 text-weight-bold q-mb-md"
        )
        ui.label(
            "Analyse a web target or AI endpoint for common security misconfigurations."
        ).classes("text-subtitle1 text-grey-7 q-mb-lg")

        with ui.card().classes("w-full max-w-2xl"):
            url_input = ui.input(
                label="Target URL",
                placeholder="https://example.com",
                validation={"Must start with https:// or http://": lambda v: v.startswith(("https://", "http://"))},
            ).classes("w-full")

            scan_type = ui.select(
                {"website": "Website scan", "ai_endpoint": "AI endpoint scan"},
                label="Scan type",
                value="website",
            ).classes("w-full q-mt-sm")

            with ui.expansion("Advanced options", icon="settings").classes("w-full q-mt-sm"):
                follow_redir = ui.checkbox("Follow redirects", value=False)
                timeout = ui.number("Request timeout (seconds)", value=8, min=2, max=30).classes("w-full")

            ui.separator().classes("q-my-md")

            ui.label(
                "By checking the box below you confirm you own or have explicit written "
                "permission to scan the target.  Scanning without permission may violate "
                "the Computer Fraud and Abuse Act (CFAA) and equivalent laws in your "
                "jurisdiction."
            ).classes("text-caption text-grey-7")

            consent = ui.checkbox(
                "I own or have explicit written permission to scan this target"
            ).classes("q-mt-xs")

            async def start_scan() -> None:
                if not consent.value:
                    ui.notify("You must confirm permission before scanning.", type="negative")
                    return
                if not url_input.value or not url_input.value.startswith(("https://", "http://")):
                    ui.notify("Please enter a valid URL starting with http(s)://", type="negative")
                    return

                payload = {
                    "target_url":                        url_input.value.strip(),
                    "scan_type":                         scan_type.value,
                    "i_own_or_have_written_permission":  consent.value,
                    "follow_redirects":                  follow_redir.value,
                    "timeout_override":                  float(timeout.value),
                }
                try:
                    async with httpx.AsyncClient(timeout=15) as client:
                        resp = await client.post("http://127.0.0.1:8080/api/scan", json=payload)
                    if resp.status_code == 202:
                        scan_id = resp.json()["scan_id"]
                        ui.navigate.to(f"/progress/{scan_id}")
                    elif resp.status_code == 422:
                        detail = resp.json().get("detail", "Validation error")
                        ui.notify(f"Validation error: {detail}", type="negative")
                    elif resp.status_code == 403:
                        detail = resp.json().get("detail", "Forbidden")
                        ui.notify(f"Forbidden: {detail}", type="negative")
                    elif resp.status_code == 429:
                        ui.notify("Rate limit exceeded — please wait and try again.", type="warning")
                    else:
                        ui.notify(f"Server error {resp.status_code}", type="negative")
                except Exception as exc:
                    ui.notify(f"Could not reach API: {exc}", type="negative")

            ui.button("Start scan", on_click=start_scan, icon="search").props(
                "color=primary size=lg"
            ).classes("w-full q-mt-md")
