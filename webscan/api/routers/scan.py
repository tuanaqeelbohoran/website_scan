"""api/routers/scan.py — /api/scan endpoints + SSE progress stream."""
from __future__ import annotations

import asyncio
import json
import logging

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import StreamingResponse

from api.schemas import ScanAccepted, ScanRequest, ScanStatus
from config.settings import settings
from core.audit_log import AuditLog
from core.finding_store import store
from core.models import ScanType
from core.orchestrator import AllowlistError, ConsentError, ScanOrchestrator
from core.ssrf_guard import SSRFError

logger = logging.getLogger("webscan.api.scan")
router = APIRouter(prefix="/api/scan", tags=["scan"])

_audit_log = AuditLog(settings.AUDIT_LOG_PATH)
_orchestrator = ScanOrchestrator(settings=settings, audit_log=_audit_log)


@router.post("", response_model=ScanAccepted, status_code=202)
async def start_scan(req: ScanRequest, request: Request):
    """Validate and enqueue a scan. Returns scan_id immediately."""
    operator_ip = request.client.host if request.client else "unknown"

    scan_type = ScanType(req.scan_type)

    # Kick off scan in background; store partial results for SSE endpoint.
    async def _background():
        try:
            async for _ in _orchestrator.run(
                target_url=req.target_url,
                scan_type=scan_type,
                config=req.config,
                operator_ip=operator_ip,
                permission_asserted=req.i_own_or_have_written_permission,
            ):
                pass  # store updates happen inside orchestrator
        except (ConsentError, AllowlistError, SSRFError) as exc:
            logger.warning("Scan blocked: %s", exc)
        except Exception as exc:
            logger.error("Scan error: %s", exc, exc_info=True)

    # We need the scan_id before the background task starts.
    # Orchestrator generates it internally, so we run it synchronously just
    # long enough to get past the gates and obtain the scan_id.
    gen = _orchestrator.run(
        target_url=req.target_url,
        scan_type=scan_type,
        config=req.config,
        operator_ip=operator_ip,
        permission_asserted=req.i_own_or_have_written_permission,
    )

    try:
        # Exhaust the generator in a background task; let the first yield
        # place the initial ScanResult in the store so we can read its scan_id.
        result_holder: list = []

        async def _run_and_collect():
            try:
                async for partial in _orchestrator.run(
                    target_url=req.target_url,
                    scan_type=scan_type,
                    config=req.config,
                    operator_ip=operator_ip,
                    permission_asserted=req.i_own_or_have_written_permission,
                ):
                    result_holder.append(partial)
            except (ConsentError, AllowlistError, SSRFError) as exc:
                result_holder.append(exc)

        task = asyncio.create_task(_run_and_collect())
        # Give the task a moment to initialise and create the first result entry.
        await asyncio.sleep(0)

        # If we already have an error, surface it.
        if result_holder and isinstance(result_holder[0], ConsentError):
            raise HTTPException(status_code=403, detail=str(result_holder[0]))
        if result_holder and isinstance(result_holder[0], (AllowlistError, SSRFError)):
            raise HTTPException(status_code=403, detail=str(result_holder[0]))

        # Retrieve scan_id from the store (most recently added entry).
        ids = store.all_ids()
        if not ids:
            await asyncio.sleep(0.2)
            ids = store.all_ids()

        scan_id = ids[-1] if ids else "pending"
        return ScanAccepted(scan_id=scan_id)

    except HTTPException:
        raise
    except (ConsentError, AllowlistError) as exc:
        raise HTTPException(status_code=403, detail=str(exc))
    except SSRFError as exc:
        raise HTTPException(status_code=403, detail=str(exc))
    except Exception as exc:
        logger.error("Unexpected error starting scan: %s", exc, exc_info=True)
        raise HTTPException(status_code=500, detail="Internal error starting scan")


@router.get("/{scan_id}/status", response_model=ScanStatus)
async def get_status(scan_id: str):
    """Poll-based status endpoint (complement to SSE stream)."""
    _validate_scan_id(scan_id)
    result = store.get(scan_id)
    if result is None:
        raise HTTPException(status_code=404, detail="Scan not found")
    status = "completed" if result.finished_at else "running"
    return ScanStatus(
        scan_id=scan_id,
        status=status,
        total_findings=len(result.findings),
        errors=result.errors,
        finished_at=result.finished_at.isoformat() + "Z" if result.finished_at else None,
    )


@router.get("/{scan_id}/stream")
async def stream_progress(scan_id: str):
    """Server-Sent Events progress stream for a running or completed scan."""
    _validate_scan_id(scan_id)

    async def _event_generator():
        last_done = -1
        timeout_ticks = 0
        while True:
            result = store.get(scan_id)
            if result is None:
                yield _sse({"event": "error", "message": "Scan not found."})
                return

            current_done = result.checks_done
            total = result.checks_total

            if current_done != last_done:
                yield _sse({
                    "event": "progress",
                    "checks_done": current_done,
                    "checks_total": total,
                    "message": result.last_check_name or f"Check {current_done}/{total}",
                    "findings_so_far": len(result.findings),
                })
                last_done = current_done
                timeout_ticks = 0

            if result.finished_at:
                yield _sse({
                    "event": "complete",
                    "scan_id": scan_id,
                    "total_findings": len(result.findings),
                })
                return

            await asyncio.sleep(0.5)
            timeout_ticks += 1
            if timeout_ticks > 240:   # 2-minute hard timeout on stream
                yield _sse({"event": "error", "message": "Stream timed out."})
                return

    return StreamingResponse(_event_generator(), media_type="text/event-stream")


def _sse(data: dict) -> str:
    return f"data: {json.dumps(data)}\n\n"


def _validate_scan_id(scan_id: str) -> None:
    """Prevent path traversal: scan_id must be a UUID."""
    import re
    _UUID_RE = re.compile(
        r"^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$",
        re.IGNORECASE,
    )
    if not _UUID_RE.match(scan_id):
        raise HTTPException(status_code=400, detail="Invalid scan_id format")
