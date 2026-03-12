"""core/audit_log.py — Append-only, structured audit logger.

Every scan attempt (permitted or blocked) is recorded here.
The file is never truncated — only appended to.
"""
from __future__ import annotations

import datetime
import json
import logging
import os
import threading
from pathlib import Path

logger = logging.getLogger("webscan.audit")


class AuditLog:
    """Thread-safe, append-only JSONL audit log."""

    def __init__(self, log_path: str) -> None:
        self._path = Path(log_path)
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()

    def record(
        self,
        *,
        scan_id: str,
        target_url: str,
        operator_ip: str = "unknown",
        consent_checked: bool = True,
        permission_asserted: bool = True,
        scan_type: str = "unknown",
        outcome: str,
    ) -> None:
        entry = {
            "ts": datetime.datetime.utcnow().isoformat() + "Z",
            "scan_id": scan_id,
            "operator_ip": operator_ip,
            "target_url": target_url,
            "consent_checked": consent_checked,
            "permission_asserted": permission_asserted,
            "scan_type": scan_type,
            "outcome": outcome,
        }
        line = json.dumps(entry, ensure_ascii=True)
        with self._lock:
            with self._path.open("a", encoding="utf-8") as fh:
                fh.write(line + "\n")
                fh.flush()
                os.fsync(fh.fileno())
        logger.info("audit", extra=entry)
