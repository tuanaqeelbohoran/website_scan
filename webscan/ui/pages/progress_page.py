"""ui/pages/progress_page.py — real-time scan progress via SSE."""
from __future__ import annotations

import asyncio
import json

import httpx
from nicegui import ui


def progress_page(scan_id: str) -> None:
    """Render the live progress view for a running scan."""

    with ui.row().classes("items-center gap-3 q-mb-sm"):
        spinner = ui.spinner("dots", size="lg", color="primary")
        status_label = ui.label("Connecting…").classes("text-subtitle1")

    progress_bar = ui.linear_progress(value=0, size="20px", color="primary").classes("w-full")

    with ui.row().classes("items-center justify-between w-full text-caption text-grey-7 q-mt-xs"):
        check_label = ui.label("").classes("font-mono")
        pct_label   = ui.label("0 %")

    with ui.row().classes("items-center gap-2 q-mt-sm"):
        ui.icon("bug_report", color="orange").classes("text-sm")
        findings_label = ui.label("0 findings detected so far").classes("text-caption")

    log_area = ui.log(max_lines=200).classes("w-full h-56 font-mono text-xs q-mt-md")

    async def poll() -> None:
        """Stream SSE events from the API and update the UI."""
        try:
            async with httpx.AsyncClient(timeout=None) as client:
                async with client.stream(
                    "GET",
                    f"http://127.0.0.1:8080/api/scan/{scan_id}/stream",
                    headers={"Accept": "text/event-stream"},
                ) as resp:
                    if resp.status_code != 200:
                        spinner.set_visibility(False)
                        status_label.set_text(f"Error {resp.status_code} from API.")
                        return

                    buffer = ""
                    async for chunk in resp.aiter_text():
                        buffer += chunk
                        while "\n\n" in buffer:
                            event_block, buffer = buffer.split("\n\n", 1)
                            for line in event_block.splitlines():
                                if not line.startswith("data:"):
                                    continue
                                data_str = line[5:].strip()
                                if not data_str:
                                    continue
                                try:
                                    data = json.loads(data_str)
                                except json.JSONDecodeError:
                                    continue

                                event_type = data.get("event", "update")

                                if event_type == "progress":
                                    done  = data.get("checks_done", 0)
                                    total = data.get("checks_total", 1) or 1
                                    msg   = data.get("message", "")
                                    found = data.get("findings_so_far", 0)
                                    frac  = done / total
                                    progress_bar.set_value(frac)
                                    pct_label.set_text(f"{int(frac * 100)} %")
                                    status_label.set_text(f"Running — {done} / {total} checks")
                                    check_label.set_text(msg)
                                    findings_label.set_text(
                                        f"{found} finding{'s' if found != 1 else ''} detected so far"
                                    )
                                    if msg:
                                        log_area.push(f"✓ {msg}")

                                elif event_type == "complete":
                                    spinner.set_visibility(False)
                                    progress_bar.set_value(1.0)
                                    pct_label.set_text("100 %")
                                    total_f = data.get("total_findings", 0)
                                    status_label.set_text("Scan complete!")
                                    findings_label.set_text(
                                        f"{total_f} finding{'s' if total_f != 1 else ''} found"
                                    )
                                    log_area.push(
                                        f"[done] {total_f} findings — redirecting to dashboard…"
                                    )
                                    await asyncio.sleep(1.5)
                                    ui.navigate.to(f"/dashboard/{scan_id}")
                                    return

                                elif event_type == "error":
                                    spinner.set_visibility(False)
                                    msg = data.get("message", "Unknown error")
                                    status_label.set_text(f"Error: {msg}")
                                    log_area.push(f"[error] {msg}")
                                    return

        except Exception as exc:
            spinner.set_visibility(False)
            status_label.set_text(f"Connection lost: {exc}")

    ui.timer(0.1, poll, once=True)

    with ui.row().classes("q-mt-md"):
        ui.label("Scan ID:").classes("text-caption text-grey-6")
        ui.label(scan_id).classes("text-caption font-mono")
