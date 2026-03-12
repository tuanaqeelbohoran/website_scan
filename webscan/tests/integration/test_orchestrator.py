"""tests/integration/test_orchestrator.py — orchestrator gate tests."""
from __future__ import annotations

import pytest

from core.models import ScanType
from core.orchestrator import ScanOrchestrator
from core.orchestrator import ConsentError, AllowlistError
from core.ssrf_guard import SSRFError


# ---------------------------------------------------------------------------
# Consent gate
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_no_consent_raises() -> None:
    orch = ScanOrchestrator()
    with pytest.raises(ConsentError):
        async for _ in orch.run(
            target_url          = "https://example.com",
            scan_type           = ScanType.WEBSITE,
            config              = {},
            permission_asserted = False,
            operator_ip         = "127.0.0.1",
        ):
            pass


# ---------------------------------------------------------------------------
# SSRF guard — loopback
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_ssrf_loopback_blocked() -> None:
    orch = ScanOrchestrator()
    with pytest.raises(SSRFError):
        async for _ in orch.run(
            target_url          = "https://127.0.0.1/",
            scan_type           = ScanType.WEBSITE,
            config              = {},
            permission_asserted = True,
            operator_ip         = "127.0.0.1",
        ):
            pass


@pytest.mark.asyncio
async def test_ssrf_rfc1918_blocked() -> None:
    orch = ScanOrchestrator()
    with pytest.raises(SSRFError):
        async for _ in orch.run(
            target_url          = "https://10.0.0.1/",
            scan_type           = ScanType.WEBSITE,
            config              = {},
            permission_asserted = True,
            operator_ip         = "127.0.0.1",
        ):
            pass


@pytest.mark.asyncio
async def test_ssrf_cloud_metadata_blocked() -> None:
    orch = ScanOrchestrator()
    with pytest.raises(SSRFError):
        async for _ in orch.run(
            target_url          = "https://169.254.169.254/latest/meta-data/",
            scan_type           = ScanType.WEBSITE,
            config              = {},
            permission_asserted = True,
            operator_ip         = "127.0.0.1",
        ):
            pass


# ---------------------------------------------------------------------------
# Allowlist gate — if ALLOWED_TARGETS_REGEX is set
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_allowlist_blocks_non_matching(monkeypatch: pytest.MonkeyPatch) -> None:
    import config.settings as settings_module

    monkeypatch.setattr(settings_module.settings, "ALLOWED_TARGETS_REGEX", "^https://allowed\\.example\\.com")
    orch = ScanOrchestrator()
    with pytest.raises(AllowlistError):
        async for _ in orch.run(
            target_url          = "https://notallowed.example.com",
            scan_type           = ScanType.WEBSITE,
            config              = {},
            permission_asserted = True,
            operator_ip         = "127.0.0.1",
        ):
            pass
