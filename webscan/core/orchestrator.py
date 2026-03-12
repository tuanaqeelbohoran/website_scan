"""core/orchestrator.py — Coordinates checks, enforces safety limits, emits progress."""
from __future__ import annotations

import asyncio
import datetime
import logging
import re
import uuid
from typing import AsyncIterator

import httpx

from config.settings import Settings
from core.audit_log import AuditLog
from core.deduplication import apply_suppressions, deduplicate, load_suppressions
from core.finding_store import store
from core.models import Finding, ScanResult, ScanType, Severity
from core.ssrf_guard import SSRFError, assert_safe_target

logger = logging.getLogger("webscan.orchestrator")


class ConsentError(PermissionError):
    """Raised when the authorization assertion is missing or false."""


class AllowlistError(PermissionError):
    """Raised when the target URL is not on the configured allowlist."""


class ScanOrchestrator:
    def __init__(
        self,
        settings: Settings | None = None,
        audit_log: AuditLog | None = None,
    ) -> None:
        from config.settings import settings as _default_settings
        self._settings = settings if settings is not None else _default_settings
        if audit_log is not None:
            self._audit_log = audit_log
        else:
            self._audit_log = AuditLog(self._settings.AUDIT_LOG_PATH)

    # ── Public entry point ─────────────────────────────────────────────────

    async def run(
        self,
        *,
        target_url: str,
        scan_type: ScanType,
        config: dict,
        operator_ip: str = "unknown",
        permission_asserted: bool = False,
    ) -> AsyncIterator[ScanResult]:
        """
        Async generator: yields partial ScanResult on each check completion,
        then the final deduplicated result.

        Raises ConsentError, AllowlistError, or SSRFError before any network I/O.
        """
        scan_id = str(uuid.uuid4())

        # ── Gate 1: authorization assertion ───────────────────────────────
        if not permission_asserted:
            self._audit_log.record(
                scan_id=scan_id,
                target_url=target_url,
                operator_ip=operator_ip,
                consent_checked=False,
                permission_asserted=False,
                scan_type=scan_type.value,
                outcome="blocked",
            )
            raise ConsentError(
                "Authorization assertion missing. "
                "You must assert ownership or explicit written permission."
            )

        # ── Gate 2: optional allowlist ────────────────────────────────────
        if self._settings.ALLOWED_TARGETS_REGEX:
            if not re.search(self._settings.ALLOWED_TARGETS_REGEX, target_url):
                self._audit_log.record(
                    scan_id=scan_id,
                    target_url=target_url,
                    operator_ip=operator_ip,
                    permission_asserted=True,
                    scan_type=scan_type.value,
                    outcome="blocked",
                )
                raise AllowlistError(f"Target '{target_url}' is not on the configured allowlist.")

        # ── Gate 3: SSRF guard ────────────────────────────────────────────
        try:
            assert_safe_target(target_url)
        except SSRFError:
            self._audit_log.record(
                scan_id=scan_id,
                target_url=target_url,
                operator_ip=operator_ip,
                permission_asserted=True,
                scan_type=scan_type.value,
                outcome="blocked",
            )
            raise

        # ── Gate 4: audit log — scan starting ─────────────────────────────
        self._audit_log.record(
            scan_id=scan_id,
            target_url=target_url,
            operator_ip=operator_ip,
            permission_asserted=True,
            scan_type=scan_type.value,
            outcome="started",
        )

        result = ScanResult(
            scan_id=scan_id,
            target_url=target_url,
            scan_type=scan_type,
            started_at=datetime.datetime.utcnow(),
        )
        store.put(result)

        # ── Load checks lazily to avoid circular imports ──────────────────
        if scan_type == ScanType.WEBSITE:
            from checks.website import WEBSITE_CHECKS as check_list
        else:
            from checks.ai_endpoint import AI_CHECKS as check_list

        result.checks_total = len(check_list)
        store.put(result)

        sem = asyncio.Semaphore(self._settings.MAX_CONCURRENT_CHECKS)
        timeout = httpx.Timeout(self._settings.REQUEST_TIMEOUT_SEC)
        limits = httpx.Limits(max_connections=5, max_keepalive_connections=2)

        request_count = 0

        async with httpx.AsyncClient(
            timeout=timeout,
            limits=limits,
            follow_redirects=False,  # redirect chain check handles hops manually
            http2=True,
            verify=True,
        ) as session:

            async def _run_one(check) -> None:
                nonlocal request_count
                async with sem:
                    await asyncio.sleep(self._settings.DELAY_BETWEEN_REQS_SEC)
                    if request_count >= self._settings.MAX_REQUESTS_PER_SCAN:
                        result.errors.append(
                            f"{check.check_id}: skipped — request budget exhausted"
                        )
                        return
                    try:
                        findings = await check.run(target_url, session, config)
                        request_count += 1
                        result.findings.extend(findings)
                    except Exception as exc:
                        logger.warning("Check %s failed: %s", check.check_id, exc)
                        result.errors.append(f"{check.check_id}: {exc}")
                    result.checks_done += 1
                    result.last_check_name = check.check_id
                    store.put(result)

            tasks = [asyncio.create_task(_run_one(c)) for c in check_list]
            for task in asyncio.as_completed(tasks):
                await task
                yield result   # stream partial results to SSE consumers

        # ── Post-processing ───────────────────────────────────────────────
        suppressions = load_suppressions()
        result.findings = deduplicate(result.findings)
        result.findings = apply_suppressions(result.findings, suppressions)
        result.finished_at = datetime.datetime.utcnow()
        store.put(result)

        self._audit_log.record(
            scan_id=scan_id,
            target_url=target_url,
            operator_ip=operator_ip,
            permission_asserted=True,
            scan_type=scan_type.value,
            outcome="completed",
        )
        yield result
