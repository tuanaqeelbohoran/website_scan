# WebScan — Defensive Vulnerability Checker
### Implementation-Ready Architecture & Design Plan
> **Legal notice:** This tool must only be used against targets you own or for which you hold **explicit written authorization**. Unauthorized scanning is illegal under the CFAA, Computer Misuse Act, and equivalent laws worldwide. No exploit payloads are included.

---

## Table of Contents
1. [Safety & Legal Gate Design](#1-safety--legal-gate-design)
2. [High-Level Architecture](#2-high-level-architecture)
3. [Package Structure](#3-package-structure)
4. [Core Interfaces & Data Models](#4-core-interfaces--data-models)
5. [Website Scanning Engine](#5-website-scanning-engine)
6. [AI Endpoint Scanning Engine](#6-ai-endpoint-scanning-engine)
7. [UI Stack](#7-ui-stack)
8. [SLM Agent Orchestration (Optional)](#8-slm-agent-orchestration-optional)
9. [Reporting: JSON Schema + PDF](#9-reporting-json-schema--pdf)
10. [Configuration & Logging](#10-configuration--logging)
11. [Testing Strategy](#11-testing-strategy)
12. [Extensibility Guidelines](#12-extensibility-guidelines)

---

## 1. Safety & Legal Gate Design

Every scan request **must** pass through a four-layer gate before any network activity occurs.

### 1.1 Gate Layers

| Layer | Mechanism | Blocks if... |
|-------|-----------|-------------|
| UI Consent | Checkbox + disclaimer modal | Not checked |
| API Authorization Assertion | Signed JSON body field `"i_own_or_have_written_permission": true` | Field absent or false |
| Target Allowlist (optional) | `ALLOWED_TARGETS` env-var regex list | Target doesn't match any allowlist entry |
| Audit Log | Immutable append-only log | Always writes — scan blocked if log write fails |

### 1.2 Immutable Audit Log Schema
```json
{
  "ts": "2026-03-12T10:00:00Z",
  "session_id": "uuid4",
  "operator_ip": "127.0.0.1",
  "target_url": "https://example.com",
  "consent_checked": true,
  "permission_asserted": true,
  "scan_type": "website|ai_endpoint",
  "outcome": "started|blocked|completed|error"
}
```

### 1.3 Rate-Limit & Safety Defaults (all overridable downward only)

```python
# config/defaults.py
MAX_CONCURRENT_CHECKS  = 3        # asyncio semaphore
REQUEST_TIMEOUT_SEC    = 8        # per request
MAX_REDIRECTS          = 5
MAX_REQUESTS_PER_SCAN  = 50       # hard ceiling across all checks
DELAY_BETWEEN_REQS_SEC = 0.5      # politeness floor
ALLOWED_HTTP_METHODS   = {"HEAD", "GET"}   # POST only for AI probe (user-consented)
```

---

## 2. High-Level Architecture

```
┌──────────────────────────────────────────────────────────────┐
│                        Browser / Client                       │
└────────────────────────┬─────────────────────────────────────┘
                         │ HTTP (localhost only by default)
┌────────────────────────▼─────────────────────────────────────┐
│              FastAPI Application  (api/)                      │
│  POST /scan  ──►  ConsentGate ──► ScanOrchestrator           │
│  GET  /scan/{id}/status  (SSE progress stream)               │
│  GET  /scan/{id}/report.json                                  │
│  GET  /scan/{id}/report.pdf                                   │
└────┬──────────────────┬────────────────────────┬─────────────┘
     │                  │                        │
┌────▼──────┐   ┌───────▼────────┐   ┌──────────▼──────────┐
│  Website  │   │  AI Endpoint   │   │  Reporter /          │
│  Scanner  │   │  Scanner       │   │  PDF Generator       │
│ (checks/) │   │ (checks/)      │   │  (reporter/)         │
└────┬──────┘   └───────┬────────┘   └──────────┬──────────-┘
     │                  │                        │
     └──────────────────┴──────────► FindingStore (in-memory + JSON)
                                                │
                                     ┌──────────▼──────────┐
                                     │  NiceGUI front-end   │
                                     │  (ui/)               │
                                     │  • Input screen      │
                                     │  • Progress stream   │
                                     │  • Findings dashboard│
                                     │  • Weak-points map   │
                                     │  • Download PDF btn  │
                                     └─────────────────────┘

Optional SLM Layer (runs inside ScanOrchestrator when enabled):
  ReconAgent → WebChecksAgent → AIEndpointAgent
      → VisualizerAgent → ReporterAgent
```

---

## 3. Package Structure

```
webscan/
├── pyproject.toml
├── .env.example
├── README.md
├── ARCHITECTURE.md          ← this document
│
├── config/
│   ├── __init__.py
│   ├── defaults.py          ← safety defaults (constants)
│   └── settings.py          ← Pydantic BaseSettings (env-driven)
│
├── api/
│   ├── __init__.py
│   ├── main.py              ← FastAPI app factory
│   ├── routers/
│   │   ├── scan.py          ← /scan endpoints
│   │   └── report.py        ← /report endpoints
│   ├── middleware/
│   │   ├── consent_gate.py  ← authorization assertion middleware
│   │   └── rate_limiter.py  ← per-IP token bucket
│   └── schemas.py           ← Pydantic request/response models
│
├── core/
│   ├── __init__.py
│   ├── interfaces.py        ← abstract base classes (Scanner, Check, Finding…)
│   ├── models.py            ← Finding, Evidence, ScanResult dataclasses
│   ├── orchestrator.py      ← ScanOrchestrator (sync + async modes)
│   ├── finding_store.py     ← in-memory store keyed by scan_id
│   └── audit_log.py        ← append-only audit logger
│
├── checks/
│   ├── __init__.py
│   ├── base.py              ← BaseCheck abstract class
│   ├── website/
│   │   ├── __init__.py
│   │   ├── tls_cert.py
│   │   ├── http_headers.py
│   │   ├── cookie_flags.py
│   │   ├── redirect_chain.py
│   │   ├── cors_posture.py
│   │   ├── banner_leakage.py
│   │   ├── robots_sitemap.py
│   │   ├── misconfig_hints.py
│   │   ├── tech_fingerprint.py
│   │   └── sensitive_paths.py
│   └── ai_endpoint/
│       ├── __init__.py
│       ├── tls_auth.py
│       ├── rate_limit_headers.py
│       ├── cors_check.py
│       ├── content_type.py
│       ├── openapi_discovery.py
│       ├── error_leakage.py
│       ├── pii_signal.py
│       ├── prompt_injection_rubric.py
│       ├── data_retention_policy.py
│       └── jailbreak_posture.py
│
├── reporter/
│   ├── __init__.py
│   ├── json_reporter.py     ← ScanResult → JSON
│   └── pdf_reporter.py      ← ScanResult → PDF (ReportLab)
│
├── ui/
│   ├── __init__.py
│   ├── app.py               ← NiceGUI entry-point
│   ├── pages/
│   │   ├── input_page.py
│   │   ├── progress_page.py
│   │   ├── dashboard_page.py
│   │   └── report_page.py
│   └── components/
│       ├── weak_points_map.py
│       ├── severity_heatmap.py
│       └── finding_card.py
│
├── agents/                  ← optional SLM orchestration
│   ├── __init__.py
│   ├── base_agent.py
│   ├── recon_agent.py
│   ├── web_checks_agent.py
│   ├── ai_endpoint_agent.py
│   ├── visualizer_agent.py
│   └── reporter_agent.py
│
└── tests/
    ├── conftest.py
    ├── unit/
    │   ├── test_models.py
    │   ├── test_checks_website.py
    │   ├── test_checks_ai.py
    │   └── test_reporter.py
    └── integration/
        ├── test_api.py
        └── test_orchestrator.py
```

---

## 4. Core Interfaces & Data Models

### 4.1 `core/models.py`

```python
"""Core data models — no I/O, pure dataclasses."""
from __future__ import annotations
from dataclasses import dataclass, field
from enum import Enum
from typing import Any
import uuid, datetime


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH     = "high"
    MEDIUM   = "medium"
    LOW      = "low"
    INFO     = "info"
    PASS     = "pass"


class ScanType(str, Enum):
    WEBSITE     = "website"
    AI_ENDPOINT = "ai_endpoint"


@dataclass
class Evidence:
    """Raw proof attached to a finding."""
    label:       str
    value:       str               # truncated header value, cert field, etc.
    source_url:  str  = ""
    http_method: str  = "GET"
    redacted:    bool = False       # mark if value was sanitised


@dataclass
class Finding:
    id:          str            = field(default_factory=lambda: str(uuid.uuid4()))
    check_id:    str            = ""        # e.g. "tls_cert.expiry"
    title:       str            = ""
    description: str            = ""
    severity:    Severity       = Severity.INFO
    affected_url: str           = ""
    evidence:    list[Evidence] = field(default_factory=list)
    remediation: str            = ""
    references:  list[str]      = field(default_factory=list)
    cwe:         str            = ""        # e.g. "CWE-295"
    cvss_score:  float | None   = None
    tags:        list[str]      = field(default_factory=list)


@dataclass
class ScanResult:
    scan_id:     str            = field(default_factory=lambda: str(uuid.uuid4()))
    target_url:  str            = ""
    scan_type:   ScanType       = ScanType.WEBSITE
    started_at:  datetime.datetime = field(default_factory=datetime.datetime.utcnow)
    finished_at: datetime.datetime | None = None
    findings:    list[Finding]  = field(default_factory=list)
    metadata:    dict[str, Any] = field(default_factory=dict)
    errors:      list[str]      = field(default_factory=list)

    @property
    def by_severity(self) -> dict[Severity, list[Finding]]:
        out: dict[Severity, list[Finding]] = {s: [] for s in Severity}
        for f in self.findings:
            out[f.severity].append(f)
        return out
```

### 4.2 `core/interfaces.py`

```python
"""Abstract base interfaces — implement these, don't import from checks/ directly."""
from __future__ import annotations
from abc import ABC, abstractmethod
from typing import AsyncIterator
from core.models import Finding, ScanResult, ScanType


class Check(ABC):
    """A single atomic security check."""
    check_id:    str = ""          # override in subclass, e.g. "tls_cert.expiry"
    scan_type:   ScanType = ScanType.WEBSITE
    description: str = ""

    @abstractmethod
    async def run(self, target_url: str, session, config: dict) -> list[Finding]:
        """
        Execute the check. MUST:
        - Respect config["timeout"], config["max_requests"]
        - Only use HEAD or GET (or POST for AI probes with user consent)
        - Return empty list rather than raise on network error (log instead)
        """
        ...


class Scanner(ABC):
    """Aggregates Check instances for a scan type."""

    @abstractmethod
    async def scan(self, target_url: str, config: dict) -> ScanResult:
        ...

    @abstractmethod
    def checks(self) -> list[Check]:
        """Return registered checks (for introspection / UI display)."""
        ...


class Reporter(ABC):
    """Transforms a ScanResult into an output artifact."""

    @abstractmethod
    def render(self, result: ScanResult) -> bytes:
        ...


class Visualizer(ABC):
    """Prepares structured data for the UI weak-points map."""

    @abstractmethod
    def build_graph(self, result: ScanResult) -> dict:
        """Return a graph dict consumed by the NiceGUI front-end."""
        ...
```

### 4.3 `core/orchestrator.py`

```python
"""ScanOrchestrator — coordinates checks, emits progress events."""
from __future__ import annotations
import asyncio, datetime, logging
from typing import AsyncIterator

import httpx

from config.settings import Settings
from core.models import ScanResult, ScanType
from core.audit_log import AuditLog
from checks.website import WEBSITE_CHECKS
from checks.ai_endpoint import AI_CHECKS

logger = logging.getLogger(__name__)


class ScanOrchestrator:
    def __init__(self, settings: Settings, audit_log: AuditLog):
        self._settings  = settings
        self._audit_log = audit_log

    async def run(
        self,
        scan_id: str,
        target_url: str,
        scan_type: ScanType,
        config: dict,
    ) -> AsyncIterator[ScanResult]:
        """
        Yields intermediate ScanResult objects as checks complete.
        Caller collects the final one.
        """
        result = ScanResult(
            scan_id=scan_id,
            target_url=target_url,
            scan_type=scan_type,
            started_at=datetime.datetime.utcnow(),
        )
        checks = WEBSITE_CHECKS if scan_type == ScanType.WEBSITE else AI_CHECKS
        sem    = asyncio.Semaphore(self._settings.MAX_CONCURRENT_CHECKS)

        limits  = httpx.Limits(max_connections=5, max_keepalive_connections=2)
        timeout = httpx.Timeout(self._settings.REQUEST_TIMEOUT_SEC)

        async with httpx.AsyncClient(
            timeout=timeout,
            limits=limits,
            follow_redirects=False,        # redirect chain check handles this itself
            http2=True,
        ) as session:
            tasks = [
                self._run_check(check, target_url, session, config, sem, result)
                for check in checks
            ]
            for coro in asyncio.as_completed(tasks):
                await coro
                yield result                # stream partial results to UI

        result.finished_at = datetime.datetime.utcnow()
        self._audit_log.record(scan_id=scan_id, target_url=target_url, outcome="completed")
        yield result

    async def _run_check(self, check, target_url, session, config, sem, result):
        async with sem:
            await asyncio.sleep(self._settings.DELAY_BETWEEN_REQS_SEC)
            try:
                findings = await check.run(target_url, session, config)
                result.findings.extend(findings)
            except Exception as exc:
                logger.warning("Check %s failed: %s", check.check_id, exc)
                result.errors.append(f"{check.check_id}: {exc}")
```

---

## 5. Website Scanning Engine

### 5.1 `checks/base.py`

```python
from abc import ABC, abstractmethod
from core.interfaces import Check


class BaseCheck(Check, ABC):
    """Shared helpers for all checks."""

    def _truncate(self, value: str, max_len: int = 256) -> str:
        return value[:max_len] + ("…" if len(value) > max_len else "")

    def _redact_auth(self, headers: dict) -> dict:
        """Strip credential-bearing headers from evidence."""
        sensitive = {"authorization", "cookie", "set-cookie", "x-api-key"}
        return {k: ("***REDACTED***" if k.lower() in sensitive else v)
                for k, v in headers.items()}
```

### 5.2 `checks/website/tls_cert.py`

```python
"""TLS/Certificate hygiene checks."""
import ssl, socket, datetime
from checks.base import BaseCheck
from core.models import Finding, Evidence, Severity, ScanType
from urllib.parse import urlparse


class TLSCertCheck(BaseCheck):
    check_id  = "tls_cert"
    scan_type = ScanType.WEBSITE
    description = "Validates TLS configuration and certificate health."

    async def run(self, target_url: str, session, config: dict) -> list[Finding]:
        findings: list[Finding] = []
        parsed = urlparse(target_url)
        host   = parsed.hostname
        port   = parsed.port or 443

        if parsed.scheme != "https":
            findings.append(Finding(
                check_id="tls_cert.no_https",
                title="Site not served over HTTPS",
                description="All traffic is unencrypted.",
                severity=Severity.CRITICAL,
                affected_url=target_url,
                remediation="Redirect all HTTP traffic to HTTPS and obtain a valid TLS certificate.",
                cwe="CWE-319",
                references=["https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Security_Cheat_Sheet.html"],
            ))
            return findings

        try:
            ctx = ssl.create_default_context()
            conn = ctx.wrap_socket(
                socket.create_connection((host, port), timeout=config.get("timeout", 8)),
                server_hostname=host,
            )
            cert = conn.getpeercert()
            conn.close()
        except ssl.SSLCertVerificationError as exc:
            findings.append(Finding(
                check_id="tls_cert.invalid",
                title="TLS certificate validation failed",
                description=str(exc),
                severity=Severity.CRITICAL,
                affected_url=target_url,
                remediation="Renew or replace the TLS certificate with one from a trusted CA.",
                cwe="CWE-295",
            ))
            return findings

        # Expiry check
        not_after = datetime.datetime.strptime(
            cert["notAfter"], "%b %d %H:%M:%S %Y %Z"
        )
        days_left = (not_after - datetime.datetime.utcnow()).days
        if days_left < 0:
            findings.append(Finding(
                check_id="tls_cert.expired",
                title="TLS certificate has expired",
                severity=Severity.CRITICAL,
                affected_url=target_url,
                evidence=[Evidence(label="Expiry", value=cert["notAfter"])],
                remediation="Immediately renew the certificate.",
                cwe="CWE-298",
            ))
        elif days_left < 30:
            findings.append(Finding(
                check_id="tls_cert.expiry_soon",
                title=f"TLS certificate expires in {days_left} days",
                severity=Severity.MEDIUM,
                affected_url=target_url,
                evidence=[Evidence(label="Expiry", value=cert["notAfter"])],
                remediation="Renew the certificate before it expires.",
                cwe="CWE-298",
            ))

        # Weak cipher / protocol (sampled from negotiated connection)
        # NOTE: protocol version comes from the live conn object, not getpeercert()
        # A full check would use ssl.SSLSocket.version() — omitted here for brevity.

        return findings
```

### 5.3 `checks/website/http_headers.py`

```python
"""HTTP security header checks."""
from checks.base import BaseCheck
from core.models import Finding, Evidence, Severity, ScanType


REQUIRED_HEADERS = {
    "strict-transport-security": {
        "severity": Severity.HIGH,
        "cwe": "CWE-319",
        "remediation": "Add: Strict-Transport-Security: max-age=63072000; includeSubDomains; preload",
    },
    "content-security-policy": {
        "severity": Severity.HIGH,
        "cwe": "CWE-693",
        "remediation": "Define a strict CSP. Start with default-src 'self' and tighten iteratively.",
    },
    "x-content-type-options": {
        "severity": Severity.MEDIUM,
        "cwe": "CWE-693",
        "remediation": "Add: X-Content-Type-Options: nosniff",
    },
    "x-frame-options": {
        "severity": Severity.MEDIUM,
        "cwe": "CWE-1021",
        "remediation": "Add: X-Frame-Options: DENY  (or use CSP frame-ancestors instead).",
    },
    "referrer-policy": {
        "severity": Severity.LOW,
        "cwe": "CWE-200",
        "remediation": "Add: Referrer-Policy: strict-origin-when-cross-origin",
    },
    "permissions-policy": {
        "severity": Severity.LOW,
        "cwe": "CWE-693",
        "remediation": "Add a Permissions-Policy header restricting unused browser features.",
    },
}

DISCLOSING_HEADERS = {"server", "x-powered-by", "x-aspnet-version", "x-generator"}


class HTTPHeadersCheck(BaseCheck):
    check_id  = "http_headers"
    scan_type = ScanType.WEBSITE
    description = "Audits presence and correctness of HTTP security headers."

    async def run(self, target_url: str, session, config: dict) -> list[Finding]:
        findings: list[Finding] = []
        try:
            resp = await session.head(target_url, follow_redirects=True)
        except Exception as exc:
            return [Finding(
                check_id="http_headers.connect_error",
                title="Could not fetch headers",
                description=str(exc),
                severity=Severity.INFO,
                affected_url=target_url,
            )]

        lower_headers = {k.lower(): v for k, v in resp.headers.items()}

        # Missing security headers
        for header, meta in REQUIRED_HEADERS.items():
            if header not in lower_headers:
                findings.append(Finding(
                    check_id=f"http_headers.missing.{header.replace('-','_')}",
                    title=f"Missing security header: {header}",
                    description=f"The response does not include the '{header}' header.",
                    severity=meta["severity"],
                    affected_url=str(resp.url),
                    remediation=meta["remediation"],
                    cwe=meta["cwe"],
                    references=["https://owasp.org/www-project-secure-headers/"],
                ))

        # Information-disclosing headers
        for header in DISCLOSING_HEADERS:
            if header in lower_headers:
                findings.append(Finding(
                    check_id=f"http_headers.disclosure.{header.replace('-','_')}",
                    title=f"Server information disclosed via '{header}' header",
                    description=f"Value: {self._truncate(lower_headers[header])}",
                    severity=Severity.LOW,
                    affected_url=str(resp.url),
                    evidence=[Evidence(label=header, value=self._truncate(lower_headers[header]))],
                    remediation=f"Remove or suppress the '{header}' response header.",
                    cwe="CWE-200",
                ))

        return findings
```

### 5.4 `checks/website/cookie_flags.py`

```python
"""Cookie security flag checks."""
from checks.base import BaseCheck
from core.models import Finding, Evidence, Severity, ScanType
import http.cookiejar


class CookieFlagsCheck(BaseCheck):
    check_id  = "cookie_flags"
    scan_type = ScanType.WEBSITE
    description = "Checks Set-Cookie headers for Secure, HttpOnly, and SameSite flags."

    async def run(self, target_url: str, session, config: dict) -> list[Finding]:
        findings: list[Finding] = []
        try:
            resp = await session.get(target_url, follow_redirects=True)
        except Exception:
            return findings

        raw_cookies = resp.headers.get_list("set-cookie")
        for raw in raw_cookies:
            name  = raw.split("=")[0].strip()
            lower = raw.lower()

            if "secure" not in lower:
                findings.append(Finding(
                    check_id="cookie_flags.no_secure",
                    title=f"Cookie '{name}' missing Secure flag",
                    severity=Severity.MEDIUM,
                    affected_url=str(resp.url),
                    evidence=[Evidence(label="Set-Cookie", value=self._truncate(raw), redacted=True)],
                    remediation="Add the Secure attribute to prevent transmission over HTTP.",
                    cwe="CWE-614",
                ))
            if "httponly" not in lower:
                findings.append(Finding(
                    check_id="cookie_flags.no_httponly",
                    title=f"Cookie '{name}' missing HttpOnly flag",
                    severity=Severity.MEDIUM,
                    affected_url=str(resp.url),
                    evidence=[Evidence(label="Set-Cookie", value=self._truncate(raw), redacted=True)],
                    remediation="Add HttpOnly to prevent JavaScript access.",
                    cwe="CWE-1004",
                ))
            if "samesite" not in lower:
                findings.append(Finding(
                    check_id="cookie_flags.no_samesite",
                    title=f"Cookie '{name}' missing SameSite attribute",
                    severity=Severity.LOW,
                    affected_url=str(resp.url),
                    evidence=[Evidence(label="Set-Cookie", value=self._truncate(raw), redacted=True)],
                    remediation="Add SameSite=Strict or SameSite=Lax.",
                    cwe="CWE-352",
                ))

        return findings
```

### 5.5 `checks/website/redirect_chain.py`

```python
"""Redirect chain analysis."""
from checks.base import BaseCheck
from core.models import Finding, Evidence, Severity, ScanType
from config.defaults import MAX_REDIRECTS


class RedirectChainCheck(BaseCheck):
    check_id  = "redirect_chain"
    scan_type = ScanType.WEBSITE
    description = "Follows and audits redirect hops for mixed-content and open-redirect risks."

    async def run(self, target_url: str, session, config: dict) -> list[Finding]:
        findings: list[Finding] = []
        current_url = target_url
        hops: list[str] = [target_url]
        max_hops = config.get("max_redirects", MAX_REDIRECTS)

        for _ in range(max_hops):
            try:
                resp = await session.head(current_url, follow_redirects=False)
            except Exception:
                break
            if resp.status_code not in (301, 302, 303, 307, 308):
                break
            location = resp.headers.get("location", "")
            if not location:
                break
            # Detect downgrades: https → http
            if current_url.startswith("https://") and location.startswith("http://"):
                findings.append(Finding(
                    check_id="redirect_chain.https_downgrade",
                    title="Redirect downgrades HTTPS to HTTP",
                    severity=Severity.HIGH,
                    affected_url=current_url,
                    evidence=[
                        Evidence(label="From", value=current_url),
                        Evidence(label="To",   value=location),
                    ],
                    remediation="Ensure all redirects preserve the HTTPS scheme.",
                    cwe="CWE-319",
                ))
            hops.append(location)
            current_url = location

        if len(hops) > 3:
            findings.append(Finding(
                check_id="redirect_chain.long_chain",
                title=f"Redirect chain has {len(hops)-1} hops",
                severity=Severity.LOW,
                affected_url=target_url,
                evidence=[Evidence(label="Chain", value=" → ".join(hops))],
                remediation="Consolidate redirects to a single hop where possible.",
            ))

        return findings
```

### 5.6 Remaining Website Checks — Skeleton Signatures

```python
# checks/website/cors_posture.py
class CORSPostureCheck(BaseCheck):
    check_id = "cors_posture"
    # Checks: Access-Control-Allow-Origin: *  with credentialed requests
    # Checks: ACAO reflects arbitrary Origin header
    async def run(self, target_url, session, config): ...

# checks/website/banner_leakage.py
class BannerLeakageCheck(BaseCheck):
    check_id = "banner_leakage"
    # Checks: Server, X-Powered-By, X-Generator, PHP/ASP version strings
    async def run(self, target_url, session, config): ...

# checks/website/robots_sitemap.py
class RobotsSitemapCheck(BaseCheck):
    check_id = "robots_sitemap"
    # HEAD /robots.txt, HEAD /sitemap.xml — note existence/disallow hints, do NOT spider
    async def run(self, target_url, session, config): ...

# checks/website/misconfig_hints.py
class MisconfigHintsCheck(BaseCheck):
    check_id = "misconfig_hints"
    # HEAD allowlisted paths: /.env (exists?), /admin/ (status), /phpinfo.php
    # Only HEAD requests — do NOT read content
    ALLOWLISTED_PATHS = ["/.well-known/security.txt", "/robots.txt", "/.env",
                         "/admin/", "/phpinfo.php", "/server-status"]
    async def run(self, target_url, session, config): ...

# checks/website/tech_fingerprint.py
class TechFingerprintCheck(BaseCheck):
    check_id = "tech_fingerprint"
    # Passive: response headers, HTML meta tags (via GET /), cookie names
    # Builds technology inventory for the report — informational, no probing
    async def run(self, target_url, session, config): ...

# checks/website/sensitive_paths.py
class SensitivePathsCheck(BaseCheck):
    check_id = "sensitive_paths"
    # HEAD-only probes from a SHORT, STATIC allowlist (no fuzzing, no wordlists)
    # Returns INFO findings with status codes only — no content retrieval
    STATIC_ALLOWLIST = ["/swagger.json", "/openapi.json", "/api/docs",
                        "/.git/HEAD", "/wp-login.php", "/actuator/health"]
    async def run(self, target_url, session, config): ...
```

### 5.7 `checks/website/__init__.py`

```python
from checks.website.tls_cert       import TLSCertCheck
from checks.website.http_headers    import HTTPHeadersCheck
from checks.website.cookie_flags    import CookieFlagsCheck
from checks.website.redirect_chain  import RedirectChainCheck
from checks.website.cors_posture    import CORSPostureCheck
from checks.website.banner_leakage  import BannerLeakageCheck
from checks.website.robots_sitemap  import RobotsSitemapCheck
from checks.website.misconfig_hints import MisconfigHintsCheck
from checks.website.tech_fingerprint import TechFingerprintCheck
from checks.website.sensitive_paths import SensitivePathsCheck

WEBSITE_CHECKS = [
    TLSCertCheck(),
    HTTPHeadersCheck(),
    CookieFlagsCheck(),
    RedirectChainCheck(),
    CORSPostureCheck(),
    BannerLeakageCheck(),
    RobotsSitemapCheck(),
    MisconfigHintsCheck(),
    TechFingerprintCheck(),
    SensitivePathsCheck(),
]
```

---

## 6. AI Endpoint Scanning Engine

### 6.1 Design Principles for AI Endpoint Checks

- **Only probe with user-provided safe test prompts** — never auto-generate adversarial content.
- POST requests are allowed for AI probes, but `Content-Type: application/json` only.
- PII signal detection is pattern-based on *response* content, not attack-based.
- Prompt-injection resilience is scored via a **rubric** (documentation review + header analysis), not by sending injection payloads.

### 6.2 `checks/ai_endpoint/tls_auth.py`

```python
"""TLS + authentication presence check for AI endpoints."""
from checks.base import BaseCheck
from core.models import Finding, Evidence, Severity, ScanType
from urllib.parse import urlparse


class TLSAuthCheck(BaseCheck):
    check_id  = "ai.tls_auth"
    scan_type = ScanType.AI_ENDPOINT
    description = "Checks HTTPS enforcement and presence of authentication requirements."

    async def run(self, target_url: str, session, config: dict) -> list[Finding]:
        findings: list[Finding] = []
        parsed = urlparse(target_url)

        if parsed.scheme != "https":
            findings.append(Finding(
                check_id="ai.tls_auth.no_https",
                title="AI endpoint served over plain HTTP",
                severity=Severity.CRITICAL,
                affected_url=target_url,
                remediation="Enforce HTTPS. AI APIs must never be exposed without TLS.",
                cwe="CWE-319",
            ))
            return findings

        # Probe without auth to detect 401/403 vs 200
        try:
            resp = await session.head(target_url)
        except Exception:
            return findings

        if resp.status_code == 200:
            findings.append(Finding(
                check_id="ai.tls_auth.no_auth_required",
                title="AI endpoint accessible without authentication",
                description=(
                    f"HEAD {target_url} returned HTTP {resp.status_code} "
                    "without any Authorization header."
                ),
                severity=Severity.CRITICAL,
                affected_url=target_url,
                evidence=[Evidence(label="Status", value=str(resp.status_code))],
                remediation=(
                    "Require API key or OAuth2 Bearer token for all requests. "
                    "Return 401 for unauthenticated requests."
                ),
                cwe="CWE-306",
            ))
        elif resp.status_code in (401, 403):
            findings.append(Finding(
                check_id="ai.tls_auth.auth_required_pass",
                title="Authentication requirement confirmed",
                severity=Severity.PASS,
                affected_url=target_url,
                evidence=[Evidence(label="Status", value=str(resp.status_code))],
            ))

        return findings
```

### 6.3 `checks/ai_endpoint/rate_limit_headers.py`

```python
"""Rate-limit header checks for AI endpoints."""
from checks.base import BaseCheck
from core.models import Finding, Evidence, Severity, ScanType

RATELIMIT_HEADERS = [
    "x-ratelimit-limit",
    "x-ratelimit-remaining",
    "retry-after",
    "ratelimit-limit",
    "ratelimit-reset",
]


class RateLimitHeadersCheck(BaseCheck):
    check_id  = "ai.rate_limit_headers"
    scan_type = ScanType.AI_ENDPOINT
    description = "Checks whether rate-limit signal headers are present in responses."

    async def run(self, target_url: str, session, config: dict) -> list[Finding]:
        findings: list[Finding] = []
        try:
            resp = await session.head(target_url, follow_redirects=True)
        except Exception:
            return findings

        lower = {k.lower(): v for k, v in resp.headers.items()}
        present = [h for h in RATELIMIT_HEADERS if h in lower]

        if not present:
            findings.append(Finding(
                check_id="ai.rate_limit_headers.missing",
                title="No rate-limit signal headers in AI endpoint response",
                description=(
                    "Callers cannot detect throttling programmatically, "
                    "increasing risk of runaway usage or cost."
                ),
                severity=Severity.MEDIUM,
                affected_url=target_url,
                remediation="Return X-RateLimit-Limit, X-RateLimit-Remaining, and Retry-After headers.",
                references=["https://datatracker.ietf.org/doc/html/draft-ietf-httpapi-ratelimit-headers"],
            ))
        else:
            for h in present:
                findings.append(Finding(
                    check_id=f"ai.rate_limit_headers.present.{h.replace('-','_')}",
                    title=f"Rate-limit header present: {h}",
                    severity=Severity.PASS,
                    affected_url=target_url,
                    evidence=[Evidence(label=h, value=self._truncate(lower[h]))],
                ))

        return findings
```

### 6.4 Remaining AI Endpoint Checks — Skeleton Signatures

```python
# checks/ai_endpoint/cors_check.py
class AICORSCheck(BaseCheck):
    check_id = "ai.cors"
    # Same logic as website CORS but tailored to API context
    async def run(self, target_url, session, config): ...

# checks/ai_endpoint/content_type.py
class ContentTypeCheck(BaseCheck):
    check_id = "ai.content_type"
    # Verifies responses return application/json, not text/html (error pages)
    async def run(self, target_url, session, config): ...

# checks/ai_endpoint/openapi_discovery.py
class OpenAPIDiscoveryCheck(BaseCheck):
    check_id = "ai.openapi_discovery"
    # HEAD /openapi.json, /swagger.json, /docs — note exposure only
    PROBE_PATHS = ["/openapi.json", "/swagger.json", "/api/docs", "/docs", "/.well-known/openapi"]
    async def run(self, target_url, session, config): ...

# checks/ai_endpoint/error_leakage.py
class ErrorLeakageCheck(BaseCheck):
    check_id = "ai.error_leakage"
    # GET nonexistent path, expect 404; inspect response body for stack traces/PII
    # Uses regex patterns: file paths, email, IP, DB connection strings
    LEAKAGE_PATTERNS = [
        r"Traceback \(most recent call last\)",
        r"(?i)connection string",
        r"\b[A-Z]:\\",
        r"(?i)internal server error.*at .+\.(py|js|rb|go)",
    ]
    async def run(self, target_url, session, config): ...

# checks/ai_endpoint/pii_signal.py
class PIISignalCheck(BaseCheck):
    check_id = "ai.pii_signal"
    # Only runs if user supplies a safe_test_prompt in config
    # Sends POST with user prompt, pattern-scans response for PII signals:
    # SSN, credit card, email, phone — informational detection only
    PII_PATTERNS = {
        "email":       r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}",
        "ssn_us":      r"\b(?!000|666|9\d{2})\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b",
        "credit_card": r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14})\b",
    }
    async def run(self, target_url, session, config): ...

# checks/ai_endpoint/prompt_injection_rubric.py
class PromptInjectionRubricCheck(BaseCheck):
    check_id = "ai.prompt_injection_rubric"
    # Purely PASSIVE — scores documentation, system prompt hints from OpenAPI spec
    # RUBRIC (not attacks):
    # [x] System prompt isolation documented? [x] Input sanitisation mentioned?
    # [x] Output validation documented? [x] Allowlist/denylist in API schema?
    # [x] Rate limits per user token? [x] Monitoring/alerting described?
    async def run(self, target_url, session, config): ...

# checks/ai_endpoint/data_retention_policy.py
class DataRetentionPolicyCheck(BaseCheck):
    check_id = "ai.data_retention"
    # Looks for: X-Data-Retention, X-Log-Policy, privacy policy URL in OpenAPI info
    # Informational — captures presence/absence, does not assert correctness
    async def run(self, target_url, session, config): ...

# checks/ai_endpoint/jailbreak_posture.py
class JailbreakPostureCheck(BaseCheck):
    check_id = "ai.jailbreak_posture"
    # NON-ADVERSARIAL scoring:
    # Based purely on OpenAPI schema, headers, and public documentation
    # Produces a 0–5 posture score with explanations
    # Does NOT send any harmful or adversarial content
    POSTURE_CRITERIA = [
        "content_moderation_documented",
        "safety_filter_mentioned",
        "rate_limits_per_token",
        "monitoring_described",
        "terms_of_service_restricts_misuse",
    ]
    async def run(self, target_url, session, config): ...
```

---

## 7. UI Stack

### 7.1 Recommended Stack

| Layer | Choice | Rationale |
|-------|--------|-----------|
| Web framework | **FastAPI** | Async, type-safe, OpenAPI schema for free |
| UI framework | **NiceGUI** | Python-native, reactive, runs inside FastAPI |
| HTTP client | **httpx** (async) | HTTP/2, type-safe, composable |
| PDF | **ReportLab** | Mature, Python-native, no Java/headless-browser |
| Progress stream | **Server-Sent Events** (SSE via FastAPI) | Lightweight, unidirectional |
| Charts/heatmap | **Plotly** (via NiceGUI's `ui.plotly`) | Interactive, no JS required |

### 7.2 Screen Flow

```
[Input Screen]
  ├── URL text field (validated with urllib.parse)
  ├── Scan type selector (Website / AI Endpoint)
  ├── ☑ Authorization disclaimer checkbox (REQUIRED)
  ├── Collapsible "Advanced" panel (timeout, allowlist, safe test prompt)
  └── [Scan] button (disabled until checkbox checked)
         │
         ▼
[Progress Screen]  ← SSE stream updates
  ├── Live check list with ✓/✗/⏳ per check ID
  ├── Running count: "7 / 10 checks complete"
  └── Cancel button (graceful shutdown via asyncio cancellation)
         │
         ▼
[Findings Dashboard]
  ├── Severity summary bar (Critical/High/Medium/Low/Info/Pass)
  ├── Weak Points Map (see §7.3)
  ├── Findings Table (filterable by severity, check_id, tag)
  ├── Finding detail drawer (description, evidence, remediation, CWE, refs)
  └── [Download PDF Report] button
         │
         ▼
[PDF Download]  — streams bytes, no server-side storage required
```

### 7.3 Weak Points Map (NiceGUI Component)

The map is built from `Visualizer.build_graph(result)` and rendered as two panels:

**Panel A — Route Tree + Risk Badges**
- Tree view of all probed URLs/paths
- Each node badge: coloured dot per highest severity finding at that path
- Click → opens finding detail drawer

**Panel B — Headers/Cookies/Endpoints Grid**
- Tabbed: Security Headers | Cookie Flags | AI Endpoint Inventory
- Each cell: green ✓ / amber ⚠ / red ✗ with hover tooltip (finding title)
- Severity heatmap built from `ui.plotly` treemap coloured by CVSS/severity

### 7.4 `ui/app.py` Skeleton

```python
"""NiceGUI application entry-point wired into FastAPI."""
from fastapi import FastAPI
from nicegui import ui, app as ngapp

from api.main     import create_app
from ui.pages.input_page     import render_input_page
from ui.pages.progress_page  import render_progress_page
from ui.pages.dashboard_page import render_dashboard_page

fastapi_app: FastAPI = create_app()


@ui.page("/")
def index():
    render_input_page()


@ui.page("/progress/{scan_id}")
def progress(scan_id: str):
    render_progress_page(scan_id)


@ui.page("/dashboard/{scan_id}")
def dashboard(scan_id: str):
    render_dashboard_page(scan_id)


ui.run_with(
    fastapi_app,
    title="WebScan — Defensive Vulnerability Checker",
    favicon="🔒",
    host="127.0.0.1",   # localhost only by default
    port=8080,
    reload=False,
)
```

### 7.5 `ui/pages/input_page.py` Skeleton

```python
"""URL input and consent screen."""
from nicegui import ui
import httpx, asyncio
from urllib.parse import urlparse


def render_input_page():
    ui.label("WebScan — Defensive Vulnerability Checker").classes("text-2xl font-bold")
    ui.separator()

    with ui.card().classes("w-full max-w-2xl mx-auto mt-8 p-6"):
        url_input = ui.input(
            label="Target URL",
            placeholder="https://example.com  or  https://api.openai.com/v1/chat/completions",
            validation={"Must be a valid https:// URL": lambda v: bool(urlparse(v).scheme in ("http","https"))},
        ).classes("w-full")

        scan_type = ui.select(
            label="Scan Type",
            options={"website": "Website", "ai_endpoint": "AI Endpoint"},
            value="website",
        )

        with ui.expansion("Advanced Options", icon="settings"):
            timeout_slider = ui.slider(min=3, max=30, value=8, step=1)
            ui.label().bind_text_from(timeout_slider, "value", lambda v: f"Timeout: {v}s")
            safe_prompt = ui.input(
                label="Safe test prompt (AI endpoint only)",
                placeholder='{"role":"user","content":"What is 2+2?"}'
            )

        ui.separator()
        with ui.row().classes("items-center gap-2"):
            consent_box = ui.checkbox()
            ui.markdown(
                "I confirm that I **own** this target or have **explicit written authorization** "
                "to scan it. I accept all legal responsibility for this scan."
            )

        scan_btn = ui.button("Scan", icon="security").props("color=negative")
        scan_btn.bind_enabled_from(consent_box, "value")

        async def start_scan():
            scan_btn.props("loading=true")
            payload = {
                "target_url": url_input.value,
                "scan_type":  scan_type.value,
                "i_own_or_have_written_permission": True,
                "config": {"timeout": timeout_slider.value},
            }
            if safe_prompt.value:
                payload["config"]["safe_test_prompt"] = safe_prompt.value
            async with httpx.AsyncClient() as client:
                resp = await client.post("http://127.0.0.1:8080/api/scan", json=payload)
                if resp.status_code == 202:
                    scan_id = resp.json()["scan_id"]
                    ui.navigate.to(f"/progress/{scan_id}")
                else:
                    ui.notify(f"Error: {resp.text}", type="negative")
            scan_btn.props("loading=false")

        scan_btn.on_click(start_scan)
```

---

## 8. SLM Agent Orchestration (Optional)

Agents wrap the scan engine with an LLM reasoning layer. The system works fully **without** agents — this layer is purely additive. When `ENABLE_SLM_AGENTS=true`, `ScanOrchestrator` delegates to `AgentPipeline` instead of running checks directly.

### 8.1 Agent Interfaces

```python
# agents/base_agent.py
from __future__ import annotations
from abc import ABC, abstractmethod
from typing import Any


class BaseAgent(ABC):
    """
    Thin wrapper around an SLM (e.g. Ollama/llama.cpp running locally).
    Agents reason about CHECK RESULTS — they never issue raw network requests.
    All network I/O is done by Check instances.
    """
    name: str = ""

    def __init__(self, llm_client):
        self._llm = llm_client          # e.g. ollama.Client() or llamacpp wrapper

    @abstractmethod
    async def run(self, context: dict[str, Any]) -> dict[str, Any]:
        """
        Args:
            context: upstream data (target_url, findings so far, config, etc.)
        Returns:
            enriched context dict passed to next agent
        """
        ...

    def _prompt(self, system: str, user: str) -> str:
        """Call local SLM synchronously. Replace with async as needed."""
        response = self._llm.chat(model="phi3:mini", messages=[
            {"role": "system", "content": system},
            {"role": "user",   "content": user},
        ])
        return response["message"]["content"]
```

### 8.2 Agent Definitions

```python
# agents/recon_agent.py
class ReconAgent(BaseAgent):
    """
    Input:  { target_url, scan_type, config }
    Output: { target_url, resolved_ips, tech_hints, scan_plan }
    Task:   Passive DNS + HTTP recon (no active probing). Produces a scan plan
            (ordered list of check_ids) prioritised by target type.
    """
    name = "ReconAgent"
    async def run(self, context): ...


# agents/web_checks_agent.py
class WebChecksAgent(BaseAgent):
    """
    Input:  { scan_plan, raw findings from WEBSITE_CHECKS }
    Output: { findings with severity re-scored, false-positive candidates flagged }
    Task:   LLM reviews each finding, adjusts severity in context of tech stack,
            flags probable false positives, adds contextual remediation detail.
    SAFETY: Receives only findings data — issues NO network requests.
    """
    name = "WebChecksAgent"
    async def run(self, context): ...


# agents/ai_endpoint_agent.py
class AIEndpointAgent(BaseAgent):
    """
    Input:  { raw findings from AI_CHECKS, openapi_schema (if discovered) }
    Output: { findings enriched with AI-specific risk context, posture score }
    Task:   Interprets AI endpoint findings in ML security framework context
            (OWASP LLM Top 10, MITRE ATLAS). Produces posture score 0–100.
    """
    name = "AIEndpointAgent"
    async def run(self, context): ...


# agents/visualizer_agent.py
class VisualizerAgent(BaseAgent):
    """
    Input:  { enriched findings }
    Output: { graph_data: dict }  ← consumed by NiceGUI weak-points map
    Task:   Builds route tree, severity heatmap matrix, and endpoint inventory.
    """
    name = "VisualizerAgent"
    async def run(self, context): ...


# agents/reporter_agent.py
class ReporterAgent(BaseAgent):
    """
    Input:  { enriched findings, graph_data, scan_metadata }
    Output: { executive_summary: str, methodology: str, remediation_narrative: str }
    Task:   Drafts human-readable sections of the PDF report.
            All factual content (findings, evidence) comes from deterministic checks.
            LLM only generates prose summaries.
    SAFETY: Must not invent CVEs, CWEs, or CVSS scores — these come from checks.
    """
    name = "ReporterAgent"
    async def run(self, context): ...
```

### 8.3 Agent Pipeline

```python
# agents/__init__.py
from agents.recon_agent       import ReconAgent
from agents.web_checks_agent  import WebChecksAgent
from agents.ai_endpoint_agent import AIEndpointAgent
from agents.visualizer_agent  import VisualizerAgent
from agents.reporter_agent    import ReporterAgent
from core.models import ScanType


class AgentPipeline:
    def __init__(self, llm_client, orchestrator):
        self._orchestrator = orchestrator
        self._recon       = ReconAgent(llm_client)
        self._web         = WebChecksAgent(llm_client)
        self._ai          = AIEndpointAgent(llm_client)
        self._visualizer  = VisualizerAgent(llm_client)
        self._reporter    = ReporterAgent(llm_client)

    async def run(self, scan_id, target_url, scan_type, config):
        ctx = {"target_url": target_url, "scan_type": scan_type, "config": config}

        ctx = await self._recon.run(ctx)

        # Run checks via orchestrator (deterministic, no LLM)
        async for result in self._orchestrator.run(scan_id, target_url, scan_type, config):
            ctx["raw_result"] = result

        # Enrich
        if scan_type == ScanType.WEBSITE:
            ctx = await self._web.run(ctx)
        else:
            ctx = await self._ai.run(ctx)

        ctx = await self._visualizer.run(ctx)
        ctx = await self._reporter.run(ctx)
        return ctx
```

---

## 9. Reporting: JSON Schema + PDF

### 9.1 JSON Report Schema

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "$id": "webscan-report-v1",
  "title": "WebScan Report",
  "type": "object",
  "required": ["scan_id","target_url","scan_type","started_at","finished_at","summary","findings"],
  "properties": {
    "scan_id":     { "type": "string", "format": "uuid" },
    "target_url":  { "type": "string", "format": "uri" },
    "scan_type":   { "type": "string", "enum": ["website","ai_endpoint"] },
    "started_at":  { "type": "string", "format": "date-time" },
    "finished_at": { "type": "string", "format": "date-time" },
    "summary": {
      "type": "object",
      "properties": {
        "total_findings":   { "type": "integer" },
        "by_severity": {
          "type": "object",
          "properties": {
            "critical": { "type": "integer" },
            "high":     { "type": "integer" },
            "medium":   { "type": "integer" },
            "low":      { "type": "integer" },
            "info":     { "type": "integer" },
            "pass":     { "type": "integer" }
          }
        },
        "risk_score":       { "type": "number", "minimum": 0, "maximum": 100 },
        "executive_summary":{ "type": "string" }
      }
    },
    "methodology": { "type": "string" },
    "scope": {
      "type": "object",
      "properties": {
        "target_url":       { "type": "string" },
        "authorized_by":    { "type": "string" },
        "checks_performed": { "type": "array", "items": { "type": "string" } }
      }
    },
    "findings": {
      "type": "array",
      "items": {
        "type": "object",
        "required": ["id","check_id","title","severity","affected_url"],
        "properties": {
          "id":           { "type": "string", "format": "uuid" },
          "check_id":     { "type": "string" },
          "title":        { "type": "string" },
          "description":  { "type": "string" },
          "severity":     { "type": "string", "enum": ["critical","high","medium","low","info","pass"] },
          "affected_url": { "type": "string" },
          "evidence": {
            "type": "array",
            "items": {
              "type": "object",
              "properties": {
                "label":      { "type": "string" },
                "value":      { "type": "string" },
                "source_url": { "type": "string" },
                "redacted":   { "type": "boolean" }
              }
            }
          },
          "remediation":  { "type": "string" },
          "references":   { "type": "array", "items": { "type": "string", "format": "uri" } },
          "cwe":          { "type": "string", "pattern": "^CWE-[0-9]+$" },
          "cvss_score":   { "type": ["number","null"], "minimum": 0, "maximum": 10 },
          "tags":         { "type": "array", "items": { "type": "string" } }
        }
      }
    },
    "errors": { "type": "array", "items": { "type": "string" } }
  }
}
```

### 9.2 `reporter/json_reporter.py`

```python
"""Converts ScanResult to a validated JSON report."""
import json, dataclasses, datetime
from core.models import ScanResult, Severity
from core.interfaces import Reporter


class JSONReporter(Reporter):
    def render(self, result: ScanResult) -> bytes:
        doc = {
            "scan_id":    result.scan_id,
            "target_url": result.target_url,
            "scan_type":  result.scan_type.value,
            "started_at":  result.started_at.isoformat() + "Z",
            "finished_at": (result.finished_at or datetime.datetime.utcnow()).isoformat() + "Z",
            "summary": {
                "total_findings": len(result.findings),
                "by_severity": {
                    s.value: len(result.by_severity[s]) for s in Severity
                },
                "risk_score":        self._risk_score(result),
                "executive_summary": "",   # filled by ReporterAgent or static template
            },
            "methodology": (
                "Passive and low-impact checks only. All requests were HEAD or GET "
                "(POST for user-consented AI probes). No exploit payloads were used."
            ),
            "scope": {
                "target_url":       result.target_url,
                "checks_performed": list({f.check_id for f in result.findings}),
            },
            "findings": [dataclasses.asdict(f) for f in result.findings],
            "errors":   result.errors,
        }
        return json.dumps(doc, default=str, indent=2).encode()

    def _risk_score(self, result: ScanResult) -> float:
        """Weighted risk score 0–100."""
        weights = {
            Severity.CRITICAL: 40,
            Severity.HIGH:     20,
            Severity.MEDIUM:   10,
            Severity.LOW:      3,
            Severity.INFO:     1,
            Severity.PASS:     0,
        }
        raw = sum(
            weights[f.severity]
            for f in result.findings
            if f.severity != Severity.PASS
        )
        return min(round(raw, 1), 100.0)
```

### 9.3 `reporter/pdf_reporter.py`

```python
"""PDF report generator using ReportLab."""
from __future__ import annotations
import io, datetime
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
    HRFlowable, PageBreak,
)
from reportlab.lib.styles  import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.pagesizes import A4
from reportlab.lib          import colors
from reportlab.lib.units    import cm

from core.models import ScanResult, Severity
from core.interfaces import Reporter


SEVERITY_COLORS = {
    Severity.CRITICAL: colors.HexColor("#d32f2f"),
    Severity.HIGH:     colors.HexColor("#f57c00"),
    Severity.MEDIUM:   colors.HexColor("#fbc02d"),
    Severity.LOW:      colors.HexColor("#388e3c"),
    Severity.INFO:     colors.HexColor("#1976d2"),
    Severity.PASS:     colors.HexColor("#757575"),
}


class PDFReporter(Reporter):
    """
    PDF outline:
    1. Cover page       — title, target, date, disclaimer
    2. Executive Summary — risk score, finding counts
    3. Scope & Methodology
    4. Findings by Severity — critical → info → pass
       Each finding: title, severity badge, affected URL,
       description, evidence table, remediation, CWE, references
    5. Appendix          — full check inventory, scan metadata
    """

    def render(self, result: ScanResult) -> bytes:
        buf    = io.BytesIO()
        doc    = SimpleDocTemplate(buf, pagesize=A4,
                                   rightMargin=2*cm, leftMargin=2*cm,
                                   topMargin=2*cm, bottomMargin=2*cm)
        styles = getSampleStyleSheet()
        story  = []

        story += self._cover(result, styles)
        story.append(PageBreak())
        story += self._executive_summary(result, styles)
        story.append(PageBreak())
        story += self._scope_methodology(result, styles)
        story.append(PageBreak())
        story += self._findings_section(result, styles)
        story.append(PageBreak())
        story += self._appendix(result, styles)

        doc.build(story)
        return buf.getvalue()

    # ── Section builders ──────────────────────────────────────────────────────

    def _cover(self, result, styles):
        elems = []
        elems.append(Spacer(1, 4*cm))
        elems.append(Paragraph("WebScan — Defensive Vulnerability Report",
                                ParagraphStyle("Title", parent=styles["Title"],
                                               fontSize=22, spaceAfter=12)))
        elems.append(Paragraph(f"<b>Target:</b> {result.target_url}", styles["Normal"]))
        elems.append(Paragraph(f"<b>Scan ID:</b> {result.scan_id}", styles["Normal"]))
        elems.append(Paragraph(
            f"<b>Date:</b> {(result.finished_at or datetime.datetime.utcnow()).strftime('%Y-%m-%d %H:%M UTC')}",
            styles["Normal"]
        ))
        elems.append(Spacer(1, 1*cm))
        disclaimer = (
            "<b>LEGAL DISCLAIMER:</b> This report was generated by an authorized user "
            "against a target they own or have explicit written permission to test. "
            "Unauthorized scanning is illegal. No exploit payloads were used."
        )
        elems.append(Paragraph(disclaimer,
                                ParagraphStyle("Disclaimer", parent=styles["Normal"],
                                               textColor=colors.red, borderColor=colors.red,
                                               borderWidth=1, borderPadding=8, fontSize=9)))
        return elems

    def _executive_summary(self, result, styles):
        elems = [Paragraph("Executive Summary", styles["Heading1"])]
        by_sev = result.by_severity
        data   = [["Severity", "Count"]] + [
            [s.value.capitalize(), str(len(by_sev[s]))]
            for s in Severity if s != Severity.PASS
        ]
        tbl = Table(data, hAlign="LEFT")
        tbl.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.grey),
            ("TEXTCOLOR",  (0, 0), (-1, 0), colors.white),
            ("GRID",       (0, 0), (-1, -1), 0.5, colors.black),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.lightgrey]),
        ]))
        elems.append(tbl)
        return elems

    def _scope_methodology(self, result, styles):
        elems = [Paragraph("Scope & Methodology", styles["Heading1"])]
        elems.append(Paragraph(f"<b>Target URL:</b> {result.target_url}", styles["Normal"]))
        elems.append(Paragraph(
            "All checks used HEAD or GET requests only (POST for user-consented AI probes). "
            "No exploit payloads, brute force, or credential stuffing was performed. "
            "Concurrency was capped at 3 simultaneous requests with a 0.5s inter-request delay.",
            styles["Normal"]
        ))
        return elems

    def _findings_section(self, result, styles):
        elems = [Paragraph("Findings", styles["Heading1"])]
        order = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM,
                 Severity.LOW, Severity.INFO, Severity.PASS]
        for sev in order:
            for finding in result.by_severity[sev]:
                elems += self._finding_block(finding, sev, styles)
        return elems

    def _finding_block(self, finding, sev, styles):
        colour = SEVERITY_COLORS[sev]
        elems  = []
        badge  = ParagraphStyle(
            f"badge_{sev.value}",
            parent=styles["Normal"],
            textColor=colors.white,
            backColor=colour,
            borderPadding=4,
            fontSize=9,
        )
        elems.append(HRFlowable(width="100%", thickness=1, color=colour))
        elems.append(Paragraph(f"[{sev.value.upper()}]  {finding.title}", badge))
        elems.append(Paragraph(f"<b>Affected URL:</b> {finding.affected_url}", styles["Normal"]))
        if finding.description:
            elems.append(Paragraph(f"<b>Description:</b> {finding.description}", styles["Normal"]))
        if finding.evidence:
            ev_data = [["Label", "Value"]] + [
                [e.label, e.value[:80] + ("…" if len(e.value) > 80 else "")]
                for e in finding.evidence
            ]
            tbl = Table(ev_data, hAlign="LEFT", colWidths=[4*cm, 11*cm])
            tbl.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), colors.lightgrey),
                ("GRID",       (0, 0), (-1, -1), 0.3, colors.grey),
                ("FONTSIZE",   (0, 0), (-1, -1), 8),
            ]))
            elems.append(tbl)
        if finding.remediation:
            elems.append(Paragraph(f"<b>Remediation:</b> {finding.remediation}", styles["Normal"]))
        if finding.cwe:
            elems.append(Paragraph(f"<b>CWE:</b> {finding.cwe}", styles["Normal"]))
        if finding.references:
            refs = " | ".join(finding.references)
            elems.append(Paragraph(f"<b>References:</b> {refs}", styles["Normal"]))
        elems.append(Spacer(1, 0.4*cm))
        return elems

    def _appendix(self, result, styles):
        elems = [Paragraph("Appendix — Scan Metadata", styles["Heading1"])]
        meta  = [
            ["Scan ID",     result.scan_id],
            ["Target",      result.target_url],
            ["Scan Type",   result.scan_type.value],
            ["Started",     str(result.started_at)],
            ["Finished",    str(result.finished_at)],
            ["Total Errors",str(len(result.errors))],
        ]
        tbl = Table(meta, hAlign="LEFT", colWidths=[4*cm, 11*cm])
        tbl.setStyle(TableStyle([
            ("GRID",       (0, 0), (-1, -1), 0.3, colors.grey),
            ("FONTSIZE",   (0, 0), (-1, -1), 8),
        ]))
        elems.append(tbl)
        return elems
```

---

## 10. Configuration & Logging

### 10.1 `config/settings.py`

```python
"""All settings drawn from env vars — never hardcode secrets."""
from pydantic_settings import BaseSettings
from typing import Optional


class Settings(BaseSettings):
    # Safety
    MAX_CONCURRENT_CHECKS:  int   = 3
    REQUEST_TIMEOUT_SEC:    float = 8.0
    MAX_REDIRECTS:          int   = 5
    MAX_REQUESTS_PER_SCAN:  int   = 50
    DELAY_BETWEEN_REQS_SEC: float = 0.5
    ALLOWED_TARGETS_REGEX:  str   = ""          # empty = no allowlist enforced

    # Server
    HOST:                   str   = "127.0.0.1"  # never expose on 0.0.0.0 in prod
    PORT:                   int   = 8080
    LOG_LEVEL:              str   = "INFO"
    AUDIT_LOG_PATH:         str   = "audit.jsonl"

    # SLM agents
    ENABLE_SLM_AGENTS:      bool  = False
    SLM_MODEL:              str   = "phi3:mini"
    SLM_BASE_URL:           str   = "http://localhost:11434"   # Ollama default

    # Report
    REPORT_STORE_DIR:       str   = "/tmp/webscan_reports"

    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"
```

### 10.2 `.env.example`

```dotenv
# === WebScan Configuration ===
# Copy to .env and edit — NEVER commit .env to source control

MAX_CONCURRENT_CHECKS=3
REQUEST_TIMEOUT_SEC=8
ALLOWED_TARGETS_REGEX=^https://(localhost|127\.0\.0\.1|.*\.yourdomain\.com)

HOST=127.0.0.1
PORT=8080
LOG_LEVEL=INFO
AUDIT_LOG_PATH=audit.jsonl

ENABLE_SLM_AGENTS=false
SLM_MODEL=phi3:mini
SLM_BASE_URL=http://localhost:11434
```

### 10.3 Logging Configuration

```python
# config/logging_config.py
import logging.config

LOGGING = {
    "version": 1,
    "disable_existing_loggers": False,
    "formatters": {
        "json": {
            "()": "pythonjsonlogger.jsonlogger.JsonFormatter",
            "format": "%(asctime)s %(name)s %(levelname)s %(message)s",
        },
    },
    "handlers": {
        "console": {
            "class":     "logging.StreamHandler",
            "formatter": "json",
            "stream":    "ext://sys.stdout",
        },
        "audit_file": {
            "class":     "logging.handlers.WatchedFileHandler",
            "formatter": "json",
            "filename":  "audit.jsonl",    # overridden by settings at startup
            "mode":      "a",
        },
    },
    "root": {
        "level":    "INFO",
        "handlers": ["console"],
    },
    "loggers": {
        "webscan.audit": {
            "level":     "INFO",
            "handlers":  ["audit_file", "console"],
            "propagate": False,
        },
        "webscan.checks": {
            "level":     "WARNING",
        },
    },
}
```

---

## 11. Testing Strategy

### 11.1 Unit Tests

```
tests/unit/
├── test_models.py          ← Finding/ScanResult dataclass behaviour
├── test_checks_website.py  ← Each check mocked with httpx respx
├── test_checks_ai.py       ← AI checks mocked
└── test_reporter.py        ← JSON schema validation + PDF byte output
```

**Example — mocked TLS check:**

```python
# tests/unit/test_checks_website.py
import pytest, respx, httpx
from checks.website.http_headers import HTTPHeadersCheck
from core.models import Severity


@pytest.mark.asyncio
@respx.mock
async def test_missing_hsts_is_high():
    """Missing HSTS header should produce a HIGH finding."""
    respx.head("https://example.com").mock(
        return_value=httpx.Response(200, headers={"Content-Type": "text/html"})
    )
    check = HTTPHeadersCheck()
    async with httpx.AsyncClient() as session:
        findings = await check.run("https://example.com", session, {"timeout": 5})

    hsts_findings = [f for f in findings if "strict_transport_security" in f.check_id]
    assert len(hsts_findings) == 1
    assert hsts_findings[0].severity == Severity.HIGH


@pytest.mark.asyncio
@respx.mock
async def test_server_header_disclosure_is_low():
    respx.head("https://example.com").mock(
        return_value=httpx.Response(200, headers={"Server": "Apache/2.4.51"})
    )
    check = HTTPHeadersCheck()
    async with httpx.AsyncClient() as session:
        findings = await check.run("https://example.com", session, {"timeout": 5})

    disc = [f for f in findings if "disclosure" in f.check_id]
    assert any(f.severity == Severity.LOW for f in disc)
```

### 11.2 Integration Tests

```python
# tests/integration/test_api.py
import pytest
from fastapi.testclient import TestClient
from api.main import create_app

client = TestClient(create_app())


def test_scan_blocked_without_consent():
    resp = client.post("/api/scan", json={
        "target_url": "https://example.com",
        "scan_type":  "website",
        "i_own_or_have_written_permission": False,
    })
    assert resp.status_code == 403
    assert "authorization" in resp.json()["detail"].lower()


def test_scan_blocked_invalid_url():
    resp = client.post("/api/scan", json={
        "target_url": "not-a-url",
        "scan_type":  "website",
        "i_own_or_have_written_permission": True,
    })
    assert resp.status_code == 422
```

### 11.3 Testing Tools & Commands

```toml
# pyproject.toml [tool.pytest.ini_options]
[tool.pytest.ini_options]
asyncio_mode  = "auto"
testpaths     = ["tests"]
addopts       = "--strict-markers -v --tb=short"

[tool.coverage.run]
source        = ["webscan"]
omit          = ["tests/*", "*/migrations/*"]
```

```bash
# Run unit tests with coverage
pytest tests/unit --cov=webscan --cov-report=term-missing

# Run integration tests (no network)
pytest tests/integration -m "not live"

# Type check
mypy webscan --strict

# Lint + format
ruff check webscan
ruff format webscan
```

### 11.4 Test Marks

```python
# conftest.py
import pytest

def pytest_configure(config):
    config.addinivalue_line("markers", "live: marks tests requiring real network")
    config.addinivalue_line("markers", "slow: marks slow tests")
```

---

## 12. Extensibility Guidelines

### 12.1 Adding a New Check

1. Create `checks/website/my_check.py` (or `checks/ai_endpoint/`)
2. Subclass `BaseCheck`, set `check_id`, `scan_type`, `description`
3. Implement `async def run(self, target_url, session, config) -> list[Finding]`
4. Register it in `checks/website/__init__.py` → `WEBSITE_CHECKS` list
5. Add a unit test in `tests/unit/test_checks_website.py`
6. No other files need changing — orchestrator picks it up automatically

### 12.2 Adding a New Report Format

1. Subclass `Reporter` in `reporter/`
2. Implement `render(result: ScanResult) -> bytes`
3. Register the new endpoint in `api/routers/report.py`

### 12.3 Adding a New UI Screen

1. Create `ui/pages/my_page.py` → define `render_my_page()`
2. Register `@ui.page("/my-route")` in `ui/app.py`

### 12.4 Swapping the SLM Backend

Replace the `llm_client` in `agents/base_agent.py._prompt()`. The `BaseAgent` interface is backend-agnostic. Tested backends:
- **Ollama** (phi3:mini, llama3.2, gemma2:2b) — lowest overhead
- **llama-cpp-python** — maximum privacy, no server required
- **OpenAI-compatible API** — drop-in if API key is available

### 12.5 Dependency Summary

```toml
# pyproject.toml
[project]
name       = "webscan"
requires-python = ">=3.11"
dependencies = [
    "fastapi>=0.111",
    "uvicorn[standard]>=0.29",
    "nicegui>=1.4",
    "httpx[http2]>=0.27",
    "pydantic>=2.7",
    "pydantic-settings>=2.2",
    "reportlab>=4.1",
    "python-json-logger>=2.0",
    # Optional agent deps (install with: pip install webscan[agents])
]

[project.optional-dependencies]
agents = ["ollama>=0.2", "llama-cpp-python>=0.2"]
dev    = [
    "pytest>=8", "pytest-asyncio>=0.23", "respx>=0.21",
    "pytest-cov>=5", "mypy>=1.10", "ruff>=0.4",
]
```

---

## Quick-Start Reference

```bash
# 1. Clone and install
git clone https://github.com/your-org/webscan
cd webscan
python -m venv .venv && .venv\Scripts\activate    # Windows
pip install -e ".[dev]"

# 2. Configure
cp .env.example .env
# Edit ALLOWED_TARGETS_REGEX for your lab/staging domain

# 3. Run
python -m uvicorn api.main:app --host 127.0.0.1 --port 8080
# NiceGUI auto-starts at http://127.0.0.1:8080

# 4. (Optional) Enable SLM agents with Ollama
ollama pull phi3:mini
ENABLE_SLM_AGENTS=true python -m uvicorn api.main:app --host 127.0.0.1 --port 8080

# 5. Test
pytest tests/unit --cov=webscan
```

---

*Document version 1.0 — Generated for authorized defensive security use only.*
