"""core/ssrf_guard.py — Block SSRF targets before any network request is issued.

Resolves the hostname and rejects RFC-1918, loopback, link-local, cloud
metadata, and other non-routable addresses.  Fails CLOSED on resolution error.
"""
from __future__ import annotations

import ipaddress
import socket
from urllib.parse import urlparse

# Networks that must never be scanned
_BLOCKED_NETWORKS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),   # link-local / AWS IMDS
    ipaddress.ip_network("100.64.0.0/10"),    # shared address space
    ipaddress.ip_network("192.0.2.0/24"),     # TEST-NET-1
    ipaddress.ip_network("198.51.100.0/24"),  # TEST-NET-2
    ipaddress.ip_network("203.0.113.0/24"),   # TEST-NET-3
    ipaddress.ip_network("::1/128"),           # IPv6 loopback
    ipaddress.ip_network("fc00::/7"),          # IPv6 ULA
    ipaddress.ip_network("fe80::/10"),         # IPv6 link-local
]


class SSRFError(ValueError):
    """Raised when a target URL resolves to a blocked address."""


def assert_safe_target(url: str) -> None:
    """
    Raise SSRFError if *url* resolves to a blocked / private address.
    Also rejects non-http(s) schemes and bare IP literals in the blocked ranges.

    Call this ONCE per scan, before the first HTTP request is issued.
    """
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        raise SSRFError(f"Disallowed scheme '{parsed.scheme}'. Only http/https are permitted.")

    host = parsed.hostname
    if not host:
        raise SSRFError("Could not parse hostname from URL.")

    # Resolve to IP (fails closed on DNS error)
    try:
        resolved = socket.getaddrinfo(host, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise SSRFError(f"DNS resolution failed for '{host}': {exc}") from exc

    for _family, _type, _proto, _canon, sockaddr in resolved:
        raw_ip = sockaddr[0]
        try:
            ip = ipaddress.ip_address(raw_ip)
        except ValueError:
            continue
        if ip.is_loopback or ip.is_link_local or ip.is_private:
            raise SSRFError(
                f"Target '{host}' resolves to a private/loopback address ({ip}). "
                "Scanning private infrastructure is not permitted."
            )
        for net in _BLOCKED_NETWORKS:
            if ip in net:
                raise SSRFError(
                    f"Target '{host}' resolves to blocked network {net} ({ip})."
                )
