# config/defaults.py
# Safety defaults — all overridable DOWNWARD only (never raise above these in code).
# These constants are imported by Settings as fallback values.

MAX_CONCURRENT_CHECKS: int = 3          # asyncio semaphore cap
REQUEST_TIMEOUT_SEC: float = 8.0        # per-request timeout
MAX_REDIRECTS: int = 5                  # redirect chain cap
MAX_REQUESTS_PER_SCAN: int = 50         # hard ceiling across all checks
DELAY_BETWEEN_REQS_SEC: float = 0.5    # politeness floor between requests
ALLOWED_HTTP_METHODS: frozenset = frozenset({"HEAD", "GET"})
# POST is only used for AI endpoint probes when the user supplies a safe_test_prompt.
