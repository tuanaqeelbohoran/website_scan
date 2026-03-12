"""api/routers/report.py — Report download endpoints (JSON, PDF, SARIF)."""
from __future__ import annotations

import re
import logging

from fastapi import APIRouter, HTTPException
from fastapi.responses import Response

from core.finding_store import store
from reporter.json_reporter import JSONReporter
from reporter.pdf_reporter import PDFReporter
from reporter.sarif_reporter import SARIFReporter

logger = logging.getLogger("webscan.api.report")
router = APIRouter(prefix="/api/report", tags=["report"])

_json_reporter = JSONReporter()
_pdf_reporter  = PDFReporter()
_sarif_reporter = SARIFReporter()

_UUID_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$",
    re.IGNORECASE,
)


def _get_result(scan_id: str):
    if not _UUID_RE.match(scan_id):
        raise HTTPException(status_code=400, detail="Invalid scan_id format")
    result = store.get(scan_id)
    if result is None:
        raise HTTPException(status_code=404, detail="Scan not found")
    return result


@router.get("/{scan_id}/report.json")
async def download_json(scan_id: str):
    result = _get_result(scan_id)
    data = _json_reporter.render(result)
    return Response(
        content=data,
        media_type="application/json",
        headers={"Content-Disposition": f'attachment; filename="webscan-{scan_id}.json"'},
    )


@router.get("/{scan_id}/report.pdf")
async def download_pdf(scan_id: str):
    result = _get_result(scan_id)
    data = _pdf_reporter.render(result)
    return Response(
        content=data,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="webscan-{scan_id}.pdf"'},
    )


@router.get("/{scan_id}/report.sarif")
async def download_sarif(scan_id: str):
    result = _get_result(scan_id)
    data = _sarif_reporter.render(result)
    return Response(
        content=data,
        media_type="application/json",
        headers={"Content-Disposition": f'attachment; filename="webscan-{scan_id}.sarif"'},
    )
