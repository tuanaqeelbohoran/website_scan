# ──────────────────────────────────────────────────────────────────
#  WebScan — Dockerfile
#  Multi-stage build: slim final image, non-root user.
# ──────────────────────────────────────────────────────────────────

# ── Stage 1: dependency builder ────────────────────────────────────
FROM python:3.11-slim AS builder

WORKDIR /build

# Install build tools required by some Python packages
RUN apt-get update \
 && apt-get install -y --no-install-recommends gcc libssl-dev \
 && rm -rf /var/lib/apt/lists/*

COPY webscan/pyproject.toml .
# Create a minimal package layout for pip to resolve deps
RUN mkdir -p config core api checks reporter ui agents tests

# Install all runtime deps into a prefix we can copy
RUN pip install --upgrade pip \
 && pip install --prefix=/install --no-cache-dir ".[dev]" 2>/dev/null || \
    pip install --prefix=/install --no-cache-dir .

# ── Stage 2: final image ────────────────────────────────────────────
FROM python:3.11-slim AS final

# Non-root user (UID 1000)
RUN addgroup --gid 1000 webscan \
 && adduser  --uid 1000 --gid 1000 --disabled-password --gecos "" webscan

WORKDIR /app

# Copy installed packages from builder
COPY --from=builder /install /usr/local

# Copy application code
COPY webscan/ .

# Ensure reports and audit log directories are writable
RUN mkdir -p /app/reports /app/logs \
 && chown -R webscan:webscan /app

USER webscan

# Expose only on loopback equivalent inside container;
# docker-compose maps this to a localhost port on the host
EXPOSE 8080

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=15s --retries=3 \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8080/docs')" || exit 1

# Run via uvicorn directly (NiceGUI's run_with() is used in ui/app.py)
CMD ["python", "-m", "ui.app"]
