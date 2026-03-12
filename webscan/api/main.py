"""api/main.py — FastAPI application factory."""
from __future__ import annotations

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from api.middleware.rate_limiter import RateLimitMiddleware
from api.routers import scan, report
from config.logging_config import configure_logging
from config.settings import settings


def create_app() -> FastAPI:
    configure_logging()

    app = FastAPI(
        title="WebScan — Defensive Vulnerability Checker",
        description=(
            "Passive, low-impact security scanning for targets you own "
            "or have explicit written permission to test."
        ),
        version="1.0.0",
        docs_url="/api/docs",
        redoc_url="/api/redoc",
    )

    # ── Middlewares (order matters — first added = outermost) ─────────────
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["http://127.0.0.1:8080", "http://localhost:8080"],
        allow_methods=["GET", "POST"],
        allow_headers=["Content-Type"],
    )
    app.add_middleware(RateLimitMiddleware)

    # ── Routers ───────────────────────────────────────────────────────────
    app.include_router(scan.router)
    app.include_router(report.router)

    @app.get("/api/healthz", tags=["meta"])
    async def healthz():
        return {"status": "ok"}

    return app


# Expose for uvicorn: `uvicorn api.main:app`
app = create_app()
