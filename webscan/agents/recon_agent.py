"""agents/recon_agent.py — passive DNS / certificate recon agent.

Produces a brief text reconnaissance summary that the orchestrator can
attach to the ScanResult as an informational finding.

All recon is strictly passive:
- DNS A/AAAA resolution  (socket.getaddrinfo — no zone transfer, no brute-force)
- TLS certificate subject/SAN extraction  (ssl.get_server_certificate)
- No port scanning, no active enumeration
"""
from __future__ import annotations

import asyncio
import logging
import re
import socket
import ssl
from urllib.parse import urlparse

from agents.base_agent import BaseAgent
from core.models import Evidence, Finding, Severity

log = logging.getLogger("webscan.agents")

_SAFE_HOSTNAME = re.compile(r"^[A-Za-z0-9.\-]+$")


class ReconAgent(BaseAgent):
    """Gather passive DNS + cert metadata and optionally enrich with LLM commentary."""

    async def run(self, target_url: str) -> Finding | None:
        """Return an INFO-level recon finding, or None on failure."""
        parsed = urlparse(target_url)
        hostname = parsed.hostname or ""

        if not hostname or not _SAFE_HOSTNAME.match(hostname):
            return None

        evidence: list[Evidence] = []

        # ── DNS resolution ───────────────────────────────────────────────────
        try:
            loop = asyncio.get_event_loop()
            infos = await loop.run_in_executor(
                None,
                lambda: socket.getaddrinfo(hostname, None, type=socket.SOCK_STREAM),
            )
            ips = sorted({str(i[4][0]) for i in infos})
            evidence.append(Evidence(label="Resolved IPs", value=", ".join(ips)))
        except Exception as exc:
            evidence.append(Evidence(label="DNS error", value=str(exc)))

        # ── TLS cert SANs ────────────────────────────────────────────────────
        if parsed.scheme == "https":
            try:
                ctx = ssl.create_default_context()
                with ctx.wrap_socket(
                    socket.create_connection((hostname, parsed.port or 443), timeout=6),
                    server_hostname=hostname,
                ) as s:
                    der = s.getpeercert()
                    if der is None:
                        raise Exception("no certificate data returned")
                    subj: dict[str, str] = {}
                    for rdn in der.get("subject", ()):
                        for key, val in rdn:
                            subj[str(key)] = str(val)
                    cn   = subj.get("commonName", "")
                    sans: list[str] = [
                        str(v) for t, v in der.get("subjectAltName", ()) if t == "DNS"
                    ]
                    evidence.append(Evidence(label="Cert CN",  value=cn or ""))
                    evidence.append(Evidence(label="Cert SANs", value=", ".join(sans[:10])))
            except Exception as exc:
                evidence.append(Evidence(label="TLS cert error", value=str(exc)))

        # ── Optional LLM enrichment ──────────────────────────────────────────
        evidence_text = "\n".join(f"  {e.label}: {e.value}" for e in evidence)
        commentary = await self._prompt(
            system=(
                "You are a defensive security analyst. "
                "Given passive DNS and TLS reconnaissance data, write 2-3 sentences "
                "noting any interesting infrastructure patterns. "
                "Do NOT invent vulnerabilities. Do NOT suggest offensive actions. "
                "If nothing notable, say so briefly."
            ),
            user=f"Target: {hostname}\n\nPassive recon data:\n{evidence_text}",
        )
        if commentary:
            evidence.append(Evidence(label="LLM commentary", value=commentary))

        return Finding(
            check_id     = "recon.passive",
            title        = f"Passive recon: {hostname}",
            severity     = Severity.INFO,
            description  = f"Passive DNS and TLS metadata for {hostname}.",
            affected_url = target_url,
            evidence     = evidence,
        )
