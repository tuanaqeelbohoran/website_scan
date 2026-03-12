"""tests/unit/test_checks_website.py — mocked tests for website checks.

Uses respx to intercept httpx calls — no real network I/O.
"""
from __future__ import annotations

import re
import ssl

import httpx
import pytest
import respx

from core.models import Severity


# ---------------------------------------------------------------------------
# http_headers check
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
@respx.mock
async def test_missing_hsts_is_high() -> None:
    respx.head("https://example.com").mock(
        return_value=httpx.Response(
            200,
            headers={
                "content-type":       "text/html",
                # deliberately no Strict-Transport-Security
                "content-length":     "100",
            },
        )
    )
    from checks.website.http_headers import HTTPHeadersCheck

    check = HTTPHeadersCheck()
    async with httpx.AsyncClient() as session:
        findings = await check.run("https://example.com", session, {})

    missing_hsts = [
        f for f in findings
        if "hsts" in f.check_id.lower() or "strict-transport" in (f.title or "").lower()
        or "strict-transport" in (f.description or "").lower()
    ]
    assert missing_hsts, "Expected a finding for missing HSTS"
    assert missing_hsts[0].severity in (Severity.HIGH, Severity.CRITICAL)


@pytest.mark.asyncio
@respx.mock
async def test_all_headers_present_passes() -> None:
    respx.head("https://example.com").mock(
        return_value=httpx.Response(
            200,
            headers={
                "strict-transport-security": "max-age=31536000; includeSubDomains",
                "x-content-type-options":    "nosniff",
                "x-frame-options":           "DENY",
                "content-security-policy":   "default-src 'self'",
                "referrer-policy":           "no-referrer",
                "permissions-policy":        "geolocation=()",
            },
        )
    )
    from checks.website.http_headers import HTTPHeadersCheck

    check = HTTPHeadersCheck()
    async with httpx.AsyncClient() as session:
        findings = await check.run("https://example.com", session, {})

    non_pass = [f for f in findings if f.severity not in (Severity.PASS, Severity.INFO)]
    assert not non_pass, f"Unexpected findings: {[f.title for f in non_pass]}"


# ---------------------------------------------------------------------------
# banner_leakage check
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
@respx.mock
async def test_server_header_version_is_low() -> None:
    respx.head("https://example.com").mock(
        return_value=httpx.Response(
            200,
            headers={"server": "Apache/2.4.51 (Ubuntu)"},
        )
    )
    from checks.website.banner_leakage import BannerLeakageCheck

    check = HTTPHeadersCheck = BannerLeakageCheck()
    async with httpx.AsyncClient() as session:
        findings = await check.run("https://example.com", session, {})

    version_findings = [f for f in findings if f.severity != Severity.PASS]
    assert version_findings, "Expected a finding for server version in header"


@pytest.mark.asyncio
@respx.mock
async def test_no_server_header_passes() -> None:
    respx.head("https://example.com").mock(
        return_value=httpx.Response(200, headers={"content-type": "text/html"})
    )
    from checks.website.banner_leakage import BannerLeakageCheck

    check = BannerLeakageCheck()
    async with httpx.AsyncClient() as session:
        findings = await check.run("https://example.com", session, {})

    non_pass = [f for f in findings if f.severity not in (Severity.PASS, Severity.INFO)]
    assert not non_pass


# ---------------------------------------------------------------------------
# cors_posture check — wildcard origin
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
@respx.mock
async def test_wildcard_cors_is_medium_or_higher() -> None:
    respx.get("https://example.com").mock(
        return_value=httpx.Response(
            200,
            headers={"access-control-allow-origin": "*"},
        )
    )
    from checks.website.cors_posture import CORSPostureCheck

    check = CORSPostureCheck()
    async with httpx.AsyncClient() as session:
        findings = await check.run("https://example.com", session, {})

    bad = [f for f in findings if f.severity in (Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL)]
    assert bad, "Expected a finding for wildcard CORS"
