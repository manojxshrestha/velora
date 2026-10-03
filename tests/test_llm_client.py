

import json
import socket as _socket
import threading as _threading
import time as _time

import pytest as _pytest

from velora.sil.llm_client import LLMClient, LLMConfig


def _hung_server():
    """A TCP server that accepts a connection and never replies (worst case:
    blocks the client inside urlopen before any HTTP response)."""
    srv = _socket.socket(_socket.AF_INET, _socket.SOCK_STREAM)
    srv.bind(("127.0.0.1", 0))
    srv.listen(1)
    held = []
    _threading.Thread(target=lambda: held.append(srv.accept()), daemon=True).start()
    return srv.getsockname()[1], srv, held


def test_wall_clock_deadline_unblocks_caller():
    """A hung endpoint must not block past the wall-clock deadline, even when the
    client is stuck inside urlopen (no response object to close)."""
    port, srv, _held = _hung_server()
    try:
        cfg = LLMConfig(base_url=f"http://127.0.0.1:{port}/v1", api_key="x",
                        model="m", timeout=60, total_timeout=2)
        client = LLMClient(cfg)
        t0 = _time.time()
        with _pytest.raises(TimeoutError):
            client._post_chat([{"role": "user", "content": "hi"}], 10, None)
        elapsed = _time.time() - t0
        assert elapsed < 10, f"caller blocked {elapsed:.1f}s past a 2s deadline"
    finally:
        srv.close()


def test_effective_total_timeout_defaults_generously():
    """total_timeout=0 derives a generous deadline from the socket timeout so a
    legitimately slow reasoning generation is not cut off."""
    assert LLMClient(LLMConfig(timeout=60, total_timeout=0))._effective_total_timeout() == 600.0
    assert LLMClient(LLMConfig(timeout=60, total_timeout=45))._effective_total_timeout() == 45.0


def test_heartbeat_announces_while_waiting(monkeypatch, capsys):
    """A silent wait must never be a blank screen: the heartbeat prints elapsed/
    deadline lines while the request is outstanding (slow = visible, not frozen)."""
    import velora.sil.llm_client as lc
    monkeypatch.setattr(lc, "_HEARTBEAT_INTERVAL", 0.05)
    monkeypatch.setattr(lc, "_HEARTBEAT_AFTER", 0.05)
    port, srv, _held = _hung_server()
    try:
        cfg = LLMConfig(base_url=f"http://127.0.0.1:{port}/v1", api_key="x",
                        model="m", timeout=60, total_timeout=0.4)
        client = LLMClient(cfg)
        with _pytest.raises(TimeoutError):
            client._post_chat([{"role": "user", "content": "hi"}], 10, None)
        err = capsys.readouterr().err
        assert "still waiting" in err
        assert "/0.4s" in err           # deadline shown, not rounded away
    finally:
        srv.close()


class _FlakyHTTP:
    """Minimal OpenAI-compatible endpoint: `fails` 500s, then a valid completion."""

    def __init__(self, fails: int):
        from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
        state = {"fails": fails}

        class H(BaseHTTPRequestHandler):
            def do_POST(self):
                if state["fails"] > 0:
                    state["fails"] -= 1
                    self.send_response(500)
                    self.end_headers()
                    return
                body = json.dumps({"choices": [{"message": {"content": "ok"}}]}).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *a):
                pass

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), H)
        _threading.Thread(target=self.server.serve_forever, daemon=True).start()

    @property
    def port(self):
        return self.server.server_address[1]

    def close(self):
        self.server.shutdown()
        self.server.server_close()


def test_transport_retry_announced_on_stderr(monkeypatch, capsys):
    """chat_raw retries must say so — silent retries read as a hang."""
    import velora.sil.llm_client as lc
    monkeypatch.setattr(lc.time, "sleep", lambda s: None)   # no backoff wait in tests
    flaky = _FlakyHTTP(fails=1)
    try:
        cfg = LLMConfig(base_url=f"http://127.0.0.1:{flaky.port}/v1", api_key="x",
                        model="m", agent_retries=2, agent_timeout=5)
        client = LLMClient(cfg)
        msg = client.chat_raw([{"role": "user", "content": "hi"}])
        assert msg and msg.get("content") == "ok"
        err = capsys.readouterr().err
        assert "transport attempt 1/3 failed" in err and "retrying" in err
    finally:
        flaky.close()
