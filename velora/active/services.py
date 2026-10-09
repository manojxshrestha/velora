"""SERVICE MAPPING: bounded TCP connect scan + banner grab (finalplan §10).

Connect scan only — no raw/SYN sockets, so it runs unprivileged and never
sends attack traffic. Callers pass the in-scope host allow-list; nothing
resolves or connects outside it. Open ports are classified with, in order:

1. passive banner read (SSH/SMTP/FTP/… announce themselves on connect),
2. TLS handshake probe on well-known TLS ports (cert subject/issuer),
3. HTTP HEAD probe through the shared budgeted/rate-limited client, so web
   services on non-standard ports are still identified as http(s).

The HTTP probe is an inert verb (HEAD) charged against the client budget.
"""
from __future__ import annotations

import socket
from concurrent.futures import ThreadPoolExecutor
from typing import Dict, List, Optional, Sequence, Tuple

from velora.active.osint import fetch_certificate

DEFAULT_TIMEOUT = 0.35      # seconds: connect + passive banner read
DEFAULT_WORKERS = 16
_BANNER_BYTES = 256

DEFAULT_PORTS: Tuple[int, ...] = (
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445,
    465, 587, 636, 993, 995, 1433, 1521, 2049, 2375, 3306, 3389,
    5432, 5900, 5984, 6379, 8000, 8008, 8080, 8081, 8443, 8888,
    9000, 9090, 9200, 9300, 11211, 27017,
)

TLS_PORTS = frozenset({443, 465, 636, 993, 995, 8443, 9443})

PORT_SERVICE: Dict[int, str] = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns",
    80: "http", 110: "pop3", 111: "rpcbind", 135: "msrpc", 139: "netbios",
    143: "imap", 443: "https", 445: "smb", 465: "smtps", 587: "smtp",
    636: "ldaps", 993: "imaps", 995: "pop3s", 1433: "mssql",
    1521: "oracle", 2049: "nfs", 2375: "docker", 3306: "mysql",
    3389: "rdp", 5432: "postgres", 5900: "vnc", 5984: "couchdb",
    6379: "redis", 8000: "http-alt", 8008: "http-alt", 8080: "http-alt",
    8081: "http-alt", 8443: "https-alt", 8888: "http-alt", 9000: "http-alt",
    9090: "http-alt", 9200: "elasticsearch", 9300: "elasticsearch",
    11211: "memcached", 27017: "mongodb",
}


def classify(port: int, banner: Optional[str] = None) -> str:
    """Service guess: banner evidence first, well-known port map fallback."""
    if banner:
        head = banner.lstrip()
        upper = head.upper()
        if head.startswith("SSH-"):
            return "ssh"
        if "ESMTP" in upper or "SMTP" in upper:
            return "smtp"
        if head.startswith("220"):
            return "ftp" if port == 21 else ("smtp" if port in (25, 465, 587) else "banner")
        if "MYSQL" in upper:
            return "mysql"
        if "POSTGRES" in upper or head.startswith("\x00\x00"):
            return "postgres" if port == 5432 else "banner"
        if head.startswith("+"):
            return "redis" if port == 6379 else "banner"
        if "HTTP/" in upper:
            return "http"
        return PORT_SERVICE.get(port, "banner")
    return PORT_SERVICE.get(port, "unknown")


def read_banner(host: str, port: int, *, timeout: float) -> Optional[str]:
    """Passive first-bytes read — servers that announce themselves on connect."""
    try:
        with socket.create_connection((host, int(port)), timeout=timeout) as sock:
            sock.settimeout(timeout)
            data = sock.recv(_BANNER_BYTES)
    except (OSError, socket.timeout):
        return None
    if not data:
        return None
    text = data.decode("latin-1", "replace").strip()
    return text or None


def _probe(host: str, port: int, timeout: float) -> Optional[Dict[str, object]]:
    """One worker unit: single connect; banner read on the same socket."""
    try:
        sock = socket.create_connection((host, int(port)), timeout=timeout)
    except (OSError, socket.timeout):
        return None
    with sock:
        entry: Dict[str, object] = {"host": host, "port": int(port),
                                    "state": "open"}
        if int(port) in TLS_PORTS:
            entry["probe"] = "tls-pending"
            entry["service"] = PORT_SERVICE.get(int(port), "tls")
            return entry
        try:
            sock.settimeout(timeout)
            data: bytes = sock.recv(_BANNER_BYTES)
        except (OSError, socket.timeout):
            data = b""
        if data:
            banner = data.decode("latin-1", "replace").strip() or None
        else:
            banner = None
        if banner:
            entry["banner"] = banner
            entry["probe"] = "banner"
            entry["service"] = classify(int(port), banner)
        else:
            entry["probe"] = "connect"
            entry["service"] = classify(int(port), None)
        return entry


def scan_ports(hosts: Sequence[str], ports: Optional[Sequence[int]] = None, *,
               timeout: float = DEFAULT_TIMEOUT,
               workers: int = DEFAULT_WORKERS) -> Dict[str, object]:
    """Parallel TCP connect scan over in-scope hosts only. Open ports only."""
    port_list = [int(p) for p in (ports or DEFAULT_PORTS)]
    jobs = [(h, p) for h in hosts for p in port_list]
    services: List[Dict[str, object]] = []
    errors = 0
    if not jobs:
        return {"services": [], "stats": {"hosts": len(hosts), "probed": 0,
                                           "open": 0, "errors": 0}}
    with ThreadPoolExecutor(max_workers=min(max(1, workers), len(jobs))) as pool:
        futures = [pool.submit(_probe, h, p, timeout) for h, p in jobs]
        for future in futures:
            try:
                result = future.result()
            except Exception:
                errors += 1
                continue
            if result is None:
                continue
            services.append(result)
    services.sort(key=lambda s: (str(s["host"]), int(s["port"])))
    return {
        "services": services,
        "stats": {
            "hosts": len(hosts),
            "ports_per_host": len(port_list),
            "probed": len(jobs),
            "open": len(services),
            "errors": errors,
        },
    }


def tls_upgrade(entry: Dict[str, object], *, timeout: float = 2.0) -> None:
    """TLS handshake on a TLS-preferred port → subject/issuer or service=None."""
    host, port = str(entry["host"]), int(entry["port"])
    cert = fetch_certificate(host, port, timeout=timeout)
    if "error" in cert:
        entry["probe"] = "connect"
        entry["service"] = classify(port, None)
        return
    entry["probe"] = "tls"
    entry["tls"] = {"subject": cert.get("subject"),
                    "issuer": cert.get("issuer"),
                    "not_after": cert.get("not_after")}
    entry["service"] = PORT_SERVICE.get(port, "https")


def http_head(client, entry: Dict[str, object], *, timeout: float) -> bool:
    """HTTP HEAD through the shared client (budgeted, rate-limited, scoped)."""
    host, port = str(entry["host"]), int(entry["port"])
    scheme = "http"
    try:
        response = client.request(
            "HEAD", f"{scheme}://{host}:{port}/", timeout=timeout,
        )
    except Exception:  # budget, scope, transport — keep connect-only result
        return False
    if response.error or not response.status:
        return False
    entry["service"] = "http"  # any HTTP status proves the HTTP service
    entry["scheme"] = scheme
    entry["status"] = int(response.status)
    server = (response.headers or {}).get("server")
    if server:
        entry["banner"] = server
    entry["probe"] = "http-head"
    return True


def collect_services(hosts: Sequence[str], ports: Optional[Sequence[int]] = None,
                     *, client=None, timeout: float = DEFAULT_TIMEOUT,
                     workers: int = DEFAULT_WORKERS,
                     http_timeout: float = 5.0) -> Dict[str, object]:
    """Connect scan + TLS upgrade + (optional) HTTP HEAD classification."""
    scan = scan_ports(hosts, ports, timeout=timeout, workers=workers)
    services: List[Dict[str, object]] = scan["services"]
    for entry in services:
        if entry.get("probe") == "tls-pending":
            tls_upgrade(entry, timeout=http_timeout)
    if client is not None:
        for entry in services:
            if entry.get("probe") != "connect":
                continue
            if int(entry["port"]) in TLS_PORTS:
                continue  # TLS already failed — skip plaintext HEAD
            http_head(client, entry, timeout=http_timeout)
    return {"services": services, "stats": scan["stats"]}
