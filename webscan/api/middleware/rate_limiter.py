"""api/middleware/rate_limiter.py — Per-IP token-bucket rate limiter middleware."""
from __future__ import annotations

import time
import threading
from collections import defaultdict

from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse

# Each IP is allowed this many requests per window.
_RATE_LIMIT   = 20         # max requests
_WINDOW_SEC   = 60         # rolling window in seconds
_SCAN_LIMIT   = 5          # stricter limit for POST /api/scan
_SCAN_WINDOW  = 300        # 5-minute window for scan starts

# Paths that are never rate-limited:
#   - NiceGUI internal static/socket paths (/_nicegui/, /socket.io/)
#   - SSE scan streams (high-frequency single long-lived connection)
#   - Report downloads (single request per scan)
_EXEMPT_PREFIXES = (
    "/_nicegui/",
    "/socket.io/",
    "/api/scan/",    # covers /api/scan/{id}/stream and /api/scan/{id}/status
    "/api/report/",
)


class _Bucket:
    __slots__ = ("timestamps",)

    def __init__(self):
        self.timestamps: list[float] = []

    def is_allowed(self, now: float, window: float, limit: int) -> bool:
        self.timestamps = [t for t in self.timestamps if now - t < window]
        if len(self.timestamps) >= limit:
            return False
        self.timestamps.append(now)
        return True


class RateLimitMiddleware(BaseHTTPMiddleware):
    def __init__(self, app, rate_limit: int = _RATE_LIMIT, window_sec: float = _WINDOW_SEC):
        super().__init__(app)
        self._rate_limit  = rate_limit
        self._window_sec  = window_sec
        self._buckets: dict[str, _Bucket] = defaultdict(_Bucket)
        self._scan_buckets: dict[str, _Bucket] = defaultdict(_Bucket)
        self._lock = threading.Lock()

    async def dispatch(self, request: Request, call_next):
        client_ip = request.client.host if request.client else "unknown"
        path = request.url.path

        # Skip rate-limiting for NiceGUI internals, SSE streams and report downloads
        if any(path.startswith(prefix) for prefix in _EXEMPT_PREFIXES):
            return await call_next(request)

        now = time.monotonic()

        with self._lock:
            # Global rate limit
            if not self._buckets[client_ip].is_allowed(now, self._window_sec, self._rate_limit):
                return JSONResponse(
                    status_code=429,
                    content={"detail": "Rate limit exceeded. Please wait before retrying."},
                )
            # Stricter limit for scan starts
            if request.method == "POST" and request.url.path.rstrip("/") == "/api/scan":
                if not self._scan_buckets[client_ip].is_allowed(now, _SCAN_WINDOW, _SCAN_LIMIT):
                    return JSONResponse(
                        status_code=429,
                        content={"detail": "Scan rate limit exceeded. Max 5 scans per 5 minutes."},
                    )

        response = await call_next(request)
        return response
