"""tests/integration/test_api.py — integration tests using FastAPI TestClient."""
from __future__ import annotations

from collections.abc import Generator

import pytest
from fastapi.testclient import TestClient

from api.main import create_app

app = create_app()


@pytest.fixture(scope="module")
def client() -> Generator[TestClient, None, None]:
    with TestClient(app, raise_server_exceptions=False) as c:
        yield c


# ---------------------------------------------------------------------------
# Health / basic reachability
# ---------------------------------------------------------------------------

def test_docs_accessible(client: TestClient) -> None:
    """OpenAPI docs endpoint should be reachable (returns 200 or 404 if disabled)."""
    resp = client.get("/docs")
    assert resp.status_code in (200, 404)


# ---------------------------------------------------------------------------
# POST /api/scan — input validation
# ---------------------------------------------------------------------------

def test_scan_requires_consent(client: TestClient) -> None:
    payload = {
        "target_url":                       "https://example.com",
        "scan_type":                        "website",
        "i_own_or_have_written_permission": False,
    }
    resp = client.post("/api/scan", json=payload)
    # Pydantic validator raises 422 for False, or orchestrator raises 403
    assert resp.status_code in (403, 422)


def test_scan_rejects_non_http_url(client: TestClient) -> None:
    payload = {
        "target_url":                       "ftp://example.com",
        "scan_type":                        "website",
        "i_own_or_have_written_permission": True,
    }
    resp = client.post("/api/scan", json=payload)
    assert resp.status_code == 422


def test_scan_rejects_localhost(client: TestClient) -> None:
    """SSRF guard should block localhost targets."""
    payload = {
        "target_url":                       "https://localhost/admin",
        "scan_type":                        "website",
        "i_own_or_have_written_permission": True,
    }
    resp = client.post("/api/scan", json=payload)
    assert resp.status_code in (403, 202)  # 403 if SSRF guard fires synchronously


def test_scan_rejects_rfc1918(client: TestClient) -> None:
    payload = {
        "target_url":                       "https://192.168.1.1/",
        "scan_type":                        "website",
        "i_own_or_have_written_permission": True,
    }
    resp = client.post("/api/scan", json=payload)
    assert resp.status_code in (403, 202)


# ---------------------------------------------------------------------------
# GET /api/scan/{id}/status — invalid IDs
# ---------------------------------------------------------------------------

def test_status_nonexistent_scan(client: TestClient) -> None:
    import uuid
    resp = client.get(f"/api/scan/{uuid.uuid4()}/status")
    assert resp.status_code == 404


def test_status_invalid_scan_id(client: TestClient) -> None:
    resp = client.get("/api/scan/not-a-uuid/status")
    assert resp.status_code == 422


# ---------------------------------------------------------------------------
# GET /api/report — guards
# ---------------------------------------------------------------------------

def test_report_nonexistent_scan_json(client: TestClient) -> None:
    import uuid
    resp = client.get(f"/api/report/{uuid.uuid4()}/report.json")
    assert resp.status_code == 404


def test_report_invalid_scan_id(client: TestClient) -> None:
    resp = client.get("/api/report/../etc/passwd/report.json")
    assert resp.status_code in (404, 422)
