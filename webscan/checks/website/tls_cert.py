"""checks/website/tls_cert.py — TLS/Certificate hygiene checks."""
from __future__ import annotations

import datetime
import socket
import ssl
from urllib.parse import urlparse

from checks.base import BaseCheck
from core.models import Evidence, Finding, Severity, ScanType


class TLSCertCheck(BaseCheck):
    check_id = "tls_cert"
    scan_type = ScanType.WEBSITE
    description = "Validates TLS configuration and certificate health (expiry, trust chain)."

    async def run(self, target_url: str, session, config: dict) -> list[Finding]:
        findings: list[Finding] = []
        parsed = urlparse(target_url)
        host = parsed.hostname or ""
        port = parsed.port or (443 if parsed.scheme == "https" else 80)

        if parsed.scheme != "https":
            findings.append(Finding(
                check_id="tls_cert.no_https",
                title="Site not served over HTTPS",
                description="All traffic is transmitted in plaintext.",
                severity=Severity.CRITICAL,
                affected_url=target_url,
                remediation=(
                    "Redirect all HTTP to HTTPS (301) and obtain a valid TLS certificate "
                    "from a trusted CA (e.g., Let's Encrypt)."
                ),
                cwe="CWE-319",
                references=["https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Security_Cheat_Sheet.html"],
            ))
            return findings

        ctx = ssl.create_default_context()
        try:
            raw_sock = socket.create_connection(
                (host, port), timeout=config.get("timeout", 8)
            )
            tls_sock = ctx.wrap_socket(raw_sock, server_hostname=host)
            cert = tls_sock.getpeercert()
            protocol = tls_sock.version()
            cipher = tls_sock.cipher()
            tls_sock.close()
        except ssl.SSLCertVerificationError as exc:  # type: ignore[misc]
            findings.append(Finding(
                check_id="tls_cert.invalid",
                title="TLS certificate validation failed",
                description=str(exc),
                severity=Severity.CRITICAL,
                affected_url=target_url,
                remediation="Renew or replace the certificate with one from a trusted CA.",
                cwe="CWE-295",
            ))
            return findings
        except Exception as exc:
            findings.append(Finding(
                check_id="tls_cert.connect_error",
                title="Could not establish TLS connection",
                description=str(exc),
                severity=Severity.HIGH,
                affected_url=target_url,
                cwe="CWE-295",
            ))
            return findings

        # Guard against getpeercert() returning None (binary_form=True or odd servers)
        if cert is None:
            return findings

        # Expiry
        not_after_str: str = str(cert.get("notAfter", ""))
        if not_after_str:
            not_after = datetime.datetime.strptime(not_after_str, "%b %d %H:%M:%S %Y %Z")
            days_left = (not_after - datetime.datetime.utcnow()).days
            if days_left < 0:
                findings.append(Finding(
                    check_id="tls_cert.expired",
                    title="TLS certificate has EXPIRED",
                    severity=Severity.CRITICAL,
                    affected_url=target_url,
                    evidence=[Evidence(label="Not After", value=not_after_str)],
                    remediation="Renew the certificate immediately.",
                    cwe="CWE-298",
                ))
            elif days_left < 14:
                findings.append(Finding(
                    check_id="tls_cert.expiry_critical",
                    title=f"TLS certificate expires in {days_left} days (critical)",
                    severity=Severity.HIGH,
                    affected_url=target_url,
                    evidence=[Evidence(label="Not After", value=not_after_str)],
                    remediation="Renew the certificate now — it will expire within 2 weeks.",
                    cwe="CWE-298",
                ))
            elif days_left < 30:
                findings.append(Finding(
                    check_id="tls_cert.expiry_soon",
                    title=f"TLS certificate expires in {days_left} days",
                    severity=Severity.MEDIUM,
                    affected_url=target_url,
                    evidence=[Evidence(label="Not After", value=not_after_str)],
                    remediation="Plan certificate renewal before expiry.",
                    cwe="CWE-298",
                ))
            else:
                findings.append(Finding(
                    check_id="tls_cert.valid",
                    title=f"TLS certificate valid ({days_left} days remaining)",
                    severity=Severity.PASS,
                    affected_url=target_url,
                    evidence=[Evidence(label="Not After", value=not_after_str)],
                ))

        # Deprecated protocol check
        if protocol and protocol in ("SSLv2", "SSLv3", "TLSv1", "TLSv1.1"):
            findings.append(Finding(
                check_id="tls_cert.weak_protocol",
                title=f"Deprecated TLS protocol in use: {protocol}",
                severity=Severity.HIGH,
                affected_url=target_url,
                evidence=[Evidence(label="Protocol", value=protocol)],
                remediation="Disable TLS 1.0 and 1.1. Require TLS 1.2 minimum; prefer TLS 1.3.",
                cwe="CWE-326",
                references=["https://www.rfc-editor.org/rfc/rfc8996"],
            ))

        # Weak cipher family
        if cipher:
            cipher_name = cipher[0] if isinstance(cipher, (list, tuple)) else str(cipher)
            if any(w in cipher_name.upper() for w in ("RC4", "DES", "NULL", "EXPORT", "MD5")):
                findings.append(Finding(
                    check_id="tls_cert.weak_cipher",
                    title=f"Weak cipher suite in use: {cipher_name}",
                    severity=Severity.HIGH,
                    affected_url=target_url,
                    evidence=[Evidence(label="Cipher", value=cipher_name)],
                    remediation="Configure server to use modern AEAD cipher suites (AES-GCM, ChaCha20-Poly1305).",
                    cwe="CWE-326",
                ))

        return findings
