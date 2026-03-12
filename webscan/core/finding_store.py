"""core/finding_store.py — In-memory store keyed by scan_id, with disk persistence.

Completed scans are written to scan_cache/{scan_id}.json so they survive
server restarts.  Cache misses fall back to disk automatically.
"""
from __future__ import annotations

import datetime
import json
import logging
import threading
from collections import OrderedDict
from pathlib import Path

from core.models import Evidence, Finding, ScanResult, ScanType, Severity

logger = logging.getLogger("webscan.finding_store")

_MAX_STORE_SIZE = 100   # evict oldest scans after this many entries

# Persist inside the workspace root (next to run.py).
_CACHE_DIR = Path(__file__).resolve().parent.parent.parent / "scan_cache"


def _scan_result_from_dict(data: dict) -> ScanResult:
    """Reconstruct a ScanResult from the JSON reporter's output format."""
    def _dt(s: str | None) -> datetime.datetime | None:
        if not s:
            return None
        return datetime.datetime.fromisoformat(s.rstrip("Z"))

    findings: list[Finding] = []
    for fd in data.get("findings", []):
        evidence = [
            Evidence(
                label      = e.get("label", ""),
                value      = e.get("value", ""),
                source_url = e.get("source_url", ""),
                http_method= e.get("http_method", "GET"),
                redacted   = e.get("redacted", False),
            )
            for e in (fd.get("evidence") or [])
        ]
        findings.append(Finding(
            id           = fd.get("id", ""),
            check_id     = fd.get("check_id", ""),
            title        = fd.get("title", ""),
            description  = fd.get("description", ""),
            severity     = Severity(fd.get("severity", "info")),
            affected_url = fd.get("affected_url", ""),
            evidence     = evidence,
            remediation  = fd.get("remediation", ""),
            references   = fd.get("references") or [],
            cwe          = fd.get("cwe", ""),
            cvss_score   = fd.get("cvss_score"),
            tags         = fd.get("tags") or [],
            framework_refs = fd.get("framework_refs") or {},
        ))

    started = _dt(data.get("started_at")) or datetime.datetime.utcnow()
    finished = _dt(data.get("finished_at"))
    return ScanResult(
        scan_id    = data["scan_id"],
        target_url = data.get("target_url", ""),
        scan_type  = ScanType(data.get("scan_type", "website")),
        started_at = started,
        finished_at= finished,
        findings   = findings,
        errors     = data.get("errors") or [],
    )


class FindingStore:
    """Thread-safe in-memory scan result store with LRU eviction and disk persistence."""

    def __init__(self) -> None:
        self._store: OrderedDict[str, ScanResult] = OrderedDict()
        self._lock = threading.Lock()

    def put(self, result: ScanResult) -> None:
        with self._lock:
            if result.scan_id in self._store:
                self._store.move_to_end(result.scan_id)
            else:
                if len(self._store) >= _MAX_STORE_SIZE:
                    self._store.popitem(last=False)  # evict oldest
            self._store[result.scan_id] = result
        # Persist to disk once the scan is complete.
        if result.finished_at is not None:
            self._persist(result)

    def get(self, scan_id: str) -> ScanResult | None:
        with self._lock:
            result = self._store.get(scan_id)
        if result is not None:
            return result
        # Fall back to disk cache (handles server restarts).
        return self._load(scan_id)

    def all_ids(self) -> list[str]:
        with self._lock:
            return list(self._store.keys())

    # ── Persistence helpers ────────────────────────────────────────────────

    def _persist(self, result: ScanResult) -> None:
        try:
            # Import inside method to avoid circular imports.
            from reporter.json_reporter import JSONReporter
            _CACHE_DIR.mkdir(parents=True, exist_ok=True)
            path = _CACHE_DIR / f"{result.scan_id}.json"
            path.write_bytes(JSONReporter().render(result))
        except Exception as exc:
            logger.warning("Could not persist scan %s: %s", result.scan_id, exc)

    def _load(self, scan_id: str) -> ScanResult | None:
        path = _CACHE_DIR / f"{scan_id}.json"
        if not path.exists():
            return None
        try:
            data = json.loads(path.read_bytes())
            result = _scan_result_from_dict(data)
            # Warm the memory cache.
            with self._lock:
                self._store[scan_id] = result
            return result
        except Exception as exc:
            logger.warning("Could not load cached scan %s: %s", scan_id, exc)
            return None


# Module-level singleton used by API routers and orchestrator.
store = FindingStore()
