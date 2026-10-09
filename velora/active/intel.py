"""Minimal INTEL: DNS + response-header fingerprint (finalplan §9).

Shared by blackbox (off-default `--with-intel`) and bughunt (default).
No crawling — one HEAD-equivalent GET at most; failures are recorded as
data (`dns_error` / `fetch_error`), never fatal.
"""

from __future__ import annotations

import socket
from typing import Dict, List, Optional, Tuple

from velora.active.client import BudgetExhausted, host_of, origin_of

# Version/product headers worth keeping (first fetch only).
HEADER_SIGNAL_KEYS: Tuple[str, ...] = (
    "server",
    "x-powered-by",
    "x-aspnet-version",
    "x-generator",
    "x-drupal-cache",
)


def dns_addresses(host: str) -> Tuple[List[str], Optional[str]]:
    """A-record/IP list for `host`; errors are returned, not raised."""
    if not host:
        return [], None
    try:
        return sorted({
            info[4][0] for info in socket.getaddrinfo(host, None)
        }), None
    except OSError as exc:
        return [], str(exc)


def header_signals(headers) -> Dict[str, str]:
    """Pick the fingerprint-relevant headers out of a response mapping."""
    seen: Dict[str, str] = {}
    for key in HEADER_SIGNAL_KEYS:
        value = headers.get(key) if headers is not None else None
        if value:
            seen[key] = value
    return seen


def fingerprint_target(url: str, client) -> Dict[str, object]:
    """One-shot intel payload for `url` (client may be None for DNS-only)."""
    host = host_of(url)
    addresses, dns_error = dns_addresses(host)
    headers_seen: Dict[str, str] = {}
    fetch_error: Optional[str] = None
    status: Optional[int] = None
    if url:
        if client is None:
            fetch_error = "no client (source-only run)"
        else:
            try:
                response = client.get(url)
                headers_seen = header_signals(response.headers)
                status = response.status
            except BudgetExhausted:
                fetch_error = "budget exhausted"
            except Exception as exc:  # scope/network — recorded, not fatal
                fetch_error = f"{type(exc).__name__}: {exc}"
    return {
        "target": url or None,
        "origin": origin_of(url) if url else None,
        "host": host,
        "addresses": addresses,
        "dns_error": dns_error,
        "headers": headers_seen,
        "status": status,
        "fetch_error": fetch_error,
    }
