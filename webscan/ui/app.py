"""ui/app.py — NiceGUI application entry point.

Mounts all NiceGUI pages onto the FastAPI app created by api/main.py,
then runs a single combined Uvicorn server.

Usage:
    python -m ui.app
or via pyproject.toml script:
    webscan-ui
"""
from __future__ import annotations

from nicegui import app as niceapp
from nicegui import ui

from api.main import create_app
from ui.pages.input_page import input_page
from ui.pages.progress_page import progress_page
from ui.pages.dashboard_page import dashboard_page

# ---------------------------------------------------------------------------
# Build the FastAPI application
# ---------------------------------------------------------------------------
fastapi_app = create_app()

# ---------------------------------------------------------------------------
# Register NiceGUI pages
# ---------------------------------------------------------------------------

@ui.page("/")
def _home() -> None:
    _apply_global_style()
    input_page()


@ui.page("/progress/{scan_id}")
def _progress(scan_id: str) -> None:
    _apply_global_style()
    with ui.column().classes("w-full max-w-3xl mx-auto q-pa-md"):
        ui.label("Scan in progress").classes("text-h5 q-mb-md")
        progress_page(scan_id)


@ui.page("/dashboard/{scan_id}")
def _dashboard(scan_id: str) -> None:
    _apply_global_style()
    with ui.column().classes("w-full max-w-5xl mx-auto"):
        dashboard_page(scan_id)


def _apply_global_style() -> None:
    ui.add_head_html(
        "<style>"
        "body { background: #f8f9fa; font-family: 'Segoe UI', sans-serif; }"
        ".max-w-2xl { max-width: 42rem; }"
        ".max-w-3xl { max-width: 48rem; }"
        ".max-w-5xl { max-width: 64rem; }"
        ".mx-auto   { margin-left: auto; margin-right: auto; }"
        ".font-mono  { font-family: 'Courier New', monospace; }"
        "</style>"
    )


# ---------------------------------------------------------------------------
# Run
# ---------------------------------------------------------------------------
if __name__ in {"__main__", "__mp_main__"}:
    import uvicorn
    ui.run_with(fastapi_app, title="WebScan", favicon="🔍", dark=False)
    uvicorn.run(fastapi_app, host="127.0.0.1", port=8080)
