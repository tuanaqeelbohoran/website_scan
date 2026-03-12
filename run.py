"""Root-level launcher — run from the workspace root:
    python run.py
"""
import os
import sys

# Add the webscan package directory to sys.path so all internal imports work.
ROOT = os.path.dirname(__file__)
WEBSCAN = os.path.join(ROOT, "webscan")
if WEBSCAN not in sys.path:
    sys.path.insert(0, WEBSCAN)

from webscan.ui.app import fastapi_app, ui  # noqa: E402

if __name__ == "__main__":
    import uvicorn
    ui.run_with(fastapi_app, title="WebScan", favicon="🔍", dark=False)
    uvicorn.run(fastapi_app, host="127.0.0.1", port=8080)
