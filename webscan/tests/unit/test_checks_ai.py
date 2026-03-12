"""tests/unit/test_checks_ai.py — mocked tests for AI endpoint checks."""
from __future__ import annotations

import httpx
import pytest
import respx

from core.models import Severity


# ---------------------------------------------------------------------------
# tls_auth — HTTP (not HTTPS) should be flagged CRITICAL
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
@respx.mock
async def test_http_ai_endpoint_is_critical() -> None:
    respx.head("http://api.example.com/v1/chat").mock(
        return_value=httpx.Response(200, headers={})
    )
    from checks.ai_endpoint.tls_auth import TLSAuthCheck

    check = TLSAuthCheck()
    async with httpx.AsyncClient() as session:
        findings = await check.run("http://api.example.com/v1/chat", session, {})

    critical = [f for f in findings if f.severity == Severity.CRITICAL]
    assert critical, "HTTP AI endpoint must be CRITICAL"


# ---------------------------------------------------------------------------
# tls_auth — missing auth header should be flagged HIGH
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
@respx.mock
async def test_no_auth_header_is_high() -> None:
    respx.head("https://api.example.com/v1/chat").mock(
        return_value=httpx.Response(200, headers={})
    )
    from checks.ai_endpoint.tls_auth import TLSAuthCheck

    check = TLSAuthCheck()
    async with httpx.AsyncClient() as session:
        findings = await check.run("https://api.example.com/v1/chat", session, {})

    auth_findings = [
        f for f in findings
        if "auth" in (f.title or "").lower() or "auth" in (f.check_id or "").lower()
    ]
    assert auth_findings
    assert any(f.severity in (Severity.HIGH, Severity.CRITICAL) for f in auth_findings)


# ---------------------------------------------------------------------------
# rate_limit_headers — missing headers should produce a finding
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
@respx.mock
async def test_missing_rate_limit_headers() -> None:
    respx.head("https://api.example.com/v1/chat").mock(
        return_value=httpx.Response(200, headers={"content-type": "application/json"})
    )
    from checks.ai_endpoint.rate_limit_headers import RateLimitHeadersCheck

    check = RateLimitHeadersCheck()
    async with httpx.AsyncClient() as session:
        findings = await check.run("https://api.example.com/v1/chat", session, {})

    non_pass = [f for f in findings if f.severity not in (Severity.PASS,)]
    assert non_pass, "Should flag missing rate-limit headers"


# ---------------------------------------------------------------------------
# content_type — wrong content-type should be flagged
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
@respx.mock
async def test_wrong_content_type_ai() -> None:
    respx.head("https://api.example.com/v1/chat").mock(
        return_value=httpx.Response(200, headers={"content-type": "text/html"})
    )
    from checks.ai_endpoint.content_type import ContentTypeCheck

    check = ContentTypeCheck()
    async with httpx.AsyncClient() as session:
        findings = await check.run("https://api.example.com/v1/chat", session, {})

    non_pass = [f for f in findings if f.severity not in (Severity.PASS, Severity.INFO)]
    assert non_pass, "Should flag non-JSON content type for AI endpoint"
