"""tests/conftest.py — shared pytest fixtures and markers."""
from __future__ import annotations

import pytest

# ---------------------------------------------------------------------------
# Custom marks
# ---------------------------------------------------------------------------
# live  — requires actual network access (skip in CI without --run-live)
# slow  — slower integration tests (skip with -m "not slow")


def pytest_configure(config: pytest.Config) -> None:
    config.addinivalue_line("markers", "live: requires live network access")
    config.addinivalue_line("markers", "slow: slower tests, skip with -m 'not slow'")


def pytest_collection_modifyitems(
    config: pytest.Config, items: list[pytest.Item]
) -> None:
    if not config.getoption("--run-live", default=False):
        skip_live = pytest.mark.skip(reason="Pass --run-live to run live network tests")
        for item in items:
            if "live" in item.keywords:
                item.add_marker(skip_live)


def pytest_addoption(parser: pytest.Parser) -> None:
    parser.addoption(
        "--run-live",
        action="store_true",
        default=False,
        help="Include tests that make live network requests",
    )


# ---------------------------------------------------------------------------
# Common fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def sample_target() -> str:
    return "https://example.com"


@pytest.fixture
def default_config() -> dict:
    from config.defaults import (
        MAX_CONCURRENT_CHECKS,
        REQUEST_TIMEOUT_SEC,
        MAX_REQUESTS_PER_SCAN,
        DELAY_BETWEEN_REQS_SEC,
    )
    return {
        "MAX_CONCURRENT_CHECKS":  MAX_CONCURRENT_CHECKS,
        "REQUEST_TIMEOUT_SEC":    REQUEST_TIMEOUT_SEC,
        "MAX_REQUESTS_PER_SCAN":  MAX_REQUESTS_PER_SCAN,
        "DELAY_BETWEEN_REQS_SEC": DELAY_BETWEEN_REQS_SEC,
    }
