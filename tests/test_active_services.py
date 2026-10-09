"""SERVICE MAPPING network adapter tests (finalplan §10 Phase 4).

Loopback sockets only — banner/silent/TLS servers on ephemeral ports.
"""

import socket
import ssl
import tempfile
import threading

import pytest

from tests.test_active_osint import CERT_UTCTIME_PEM, KEY_UTCTIME_PEM
from velora.active.services import (
    DEFAULT_PORTS,
    classify,
    collect_services,
    http_head,
    scan_ports,
    tls_upgrade,
)


# ---------------------------------------------------------------------------
# Helpers: loopback servers on ephemeral ports
# ---------------------------------------------------------------------------

def _banner_server(banner: bytes) -> int:
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    port = listener.getsockname()[1]

    def serve() -> None:
        try:
            listener.settimeout(5)
            conn, _ = listener.accept()
            with conn:
                conn.sendall(banner)
                conn.settimeout(3)
                try:
                    conn.recv(64)
                except (OSError, socket.timeout):
                    pass
        except OSError:
            pass
        finally:
            listener.close()

    threading.Thread(target=serve, daemon=True).start()
    return port


def _silent_server() -> int:
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    port = listener.getsockname()[1]

    def serve() -> None:
        try:
            listener.settimeout(5)
            conn, _ = listener.accept()
            with conn:
                conn.settimeout(3)
                try:
                    conn.recv(64)
                except (OSError, socket.timeout):
                    pass
        except OSError:
            pass
        finally:
            listener.close()

    threading.Thread(target=serve, daemon=True).start()
    return port


@pytest.fixture
def tls_endpoint():
    """Loopback TLS server presenting CERT_UTCTIME_PEM (single handshake)."""
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    with tempfile.TemporaryDirectory() as tmp:
        cert_path = f"{tmp}/cert.pem"
        key_path = f"{tmp}/key.pem"
        with open(cert_path, "w") as handle:
            handle.write(CERT_UTCTIME_PEM)
        with open(key_path, "w") as handle:
            handle.write(KEY_UTCTIME_PEM)
        context.load_cert_chain(cert_path, key_path)

    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen(2)
    port = listener.getsockname()[1]

    def serve() -> None:
        try:
            listener.settimeout(5)
            conn, _ = listener.accept()
            with context.wrap_socket(conn, server_side=True) as tls:
                tls.settimeout(3)
                try:
                    tls.recv(1024)
                except (OSError, ssl.SSLError):
                    pass
        except (OSError, ssl.SSLError):
            pass
        finally:
            listener.close()

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    try:
        yield port
    finally:
        thread.join(timeout=5)


class _Resp:
    def __init__(self, status=200, headers=None, error=None):
        self.status = status
        self.headers = headers or {}
        self.error = error


class _Client:
    def __init__(self, resp=None, exc=None):
        self.resp = resp if resp is not None else _Resp()
        self.exc = exc
        self.calls = []

    def request(self, method, url, *, timeout=None, **_):
        self.calls.append((method, url))
        if self.exc is not None:
            raise self.exc
        return self.resp


# ---------------------------------------------------------------------------
# Classification
# ---------------------------------------------------------------------------

def test_classify_banner_evidence():
    assert classify(22, "SSH-2.0-OpenSSH_9.0") == "ssh"
    assert classify(25, "mail.example ESMTP ready") == "smtp"
    assert classify(21, "220 ftp ready") == "ftp"
    assert classify(587, "220 mx ESMTP") == "smtp"
    assert classify(80, "HTTP/1.1 200 OK") == "http"


def test_classify_port_fallback():
    assert classify(22, None) == "ssh"
    assert classify(443, None) == "https"
    assert classify(6379, None) == "redis"
    assert classify(47000, None) == "unknown"
    assert classify(47000, "weird banner") == "banner"


def test_default_ports_are_unique():
    assert len(DEFAULT_PORTS) == len(set(DEFAULT_PORTS))
    assert all(1 < p < 65536 for p in DEFAULT_PORTS)


# ---------------------------------------------------------------------------
# Connect scan
# ---------------------------------------------------------------------------

def test_scan_finds_banner_service():
    port = _banner_server(b"SSH-2.0-OpenSSH_9.0\r\n")
    result = scan_ports(["127.0.0.1"], [port, 1], timeout=1.0)
    stats = result["stats"]
    assert stats["probed"] == 2
    assert stats["open"] == 1
    (entry,) = result["services"]
    assert entry["host"] == "127.0.0.1"
    assert entry["port"] == port
    assert entry["state"] == "open"
    assert entry["probe"] == "banner"
    assert entry["service"] == "ssh"
    assert "OpenSSH" in entry["banner"]


def test_scan_silent_server_is_connect_probe():
    port = _silent_server()
    result = scan_ports(["127.0.0.1"], [port], timeout=0.6)
    (entry,) = result["services"]
    assert entry["probe"] == "connect"
    assert "banner" not in entry


def test_scan_closed_ports_reports_empty():
    result = scan_ports(["127.0.0.1"], [1, 2, 3], timeout=0.3)
    assert result["services"] == []
    assert result["stats"]["open"] == 0
    assert result["stats"]["probed"] == 3


def test_scan_no_hosts_no_jobs():
    result = scan_ports([], [22, 80])
    assert result["services"] == []
    assert result["stats"]["probed"] == 0


# ---------------------------------------------------------------------------
# HTTP HEAD classification (budgeted client)
# ---------------------------------------------------------------------------

def test_http_head_classifies_web_service():
    port = _silent_server()
    entry = {"host": "127.0.0.1", "port": port, "state": "open",
             "probe": "connect", "service": "unknown"}
    client = _Client(_Resp(status=200, headers={"server": "fixture/1.0"}))
    assert http_head(client, entry, timeout=3.0) is True
    assert entry["service"] == "http"
    assert entry["scheme"] == "http"
    assert entry["status"] == 200
    assert entry["banner"] == "fixture/1.0"
    assert entry["probe"] == "http-head"
    assert client.calls == [("HEAD", f"http://127.0.0.1:{port}/")]


def test_http_head_client_failure_keeps_connect_probe():
    port = _silent_server()
    entry = {"host": "127.0.0.1", "port": port, "state": "open",
             "probe": "connect", "service": "unknown"}
    client = _Client(exc=RuntimeError("budget exhausted"))
    assert http_head(client, entry, timeout=3.0) is False
    assert entry["probe"] == "connect"
    assert entry["service"] == "unknown"


# ---------------------------------------------------------------------------
# TLS upgrade
# ---------------------------------------------------------------------------

def test_tls_upgrade_success(tls_endpoint):
    entry = {"host": "127.0.0.1", "port": tls_endpoint, "state": "open",
             "probe": "tls-pending", "service": "tls"}
    tls_upgrade(entry, timeout=3.0)
    assert entry["probe"] == "tls"
    assert entry["service"] == "https"
    assert entry["tls"]["subject"] == "velora.test"
    assert entry["tls"]["issuer"] == "velora.test"


def test_tls_upgrade_failure_falls_back_to_connect():
    port = _silent_server()
    entry = {"host": "127.0.0.1", "port": port, "state": "open",
             "probe": "tls-pending", "service": "tls"}
    tls_upgrade(entry, timeout=1.0)
    assert entry["probe"] == "connect"
    assert "tls" not in entry
    assert entry["service"] == "unknown"


# ---------------------------------------------------------------------------
# collect_services orchestration
# ---------------------------------------------------------------------------

def test_collect_services_scan_then_head():
    port = _silent_server()
    client = _Client(_Resp(status=204, headers={"server": "head/1"}))
    result = collect_services(["127.0.0.1"], [port], client=client, timeout=0.6)
    (entry,) = result["services"]
    assert entry["probe"] == "http-head"
    assert entry["service"] == "http"
    assert entry["status"] == 204
    assert result["stats"]["open"] == 1


def test_collect_services_without_client_stays_connect():
    port = _silent_server()
    result = collect_services(["127.0.0.1"], [port], client=None, timeout=0.6)
    (entry,) = result["services"]
    assert entry["probe"] == "connect"


def test_collect_services_skips_head_for_failed_tls_ports(monkeypatch):
    # A TLS-preferred port that fails the handshake must not get a plaintext
    # HEAD attempt afterwards.
    import velora.active.services as services

    port = _silent_server()
    monkeypatch.setattr(services, "TLS_PORTS", frozenset({port}))
    client = _Client()
    result = collect_services(["127.0.0.1"], [port], client=client,
                              timeout=0.6, http_timeout=1.0)
    (entry,) = result["services"]
    assert entry["probe"] == "connect"      # TLS failed → connect fallback
    assert client.calls == []               # and no plaintext HEAD followed
