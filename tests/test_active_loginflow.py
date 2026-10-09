"""Unit tests for scripted login flows (finalplan §8.4 login-script DSL)."""

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from tests.blackbox_fixture import fixture_env
from velora.active.client import HttpClient
from velora.active.loginflow import (
    MAX_STEPS,
    FlowFormatError,
    FlowRunError,
    _substitute,
    load_flow,
    run_flow,
)


def _write(tmp_path, data, name="flow.json"):
    path = tmp_path / name
    path.write_text(json.dumps(data) if not isinstance(data, str) else data)
    return str(path)


def test_load_flow_ok(tmp_path):
    path = _write(tmp_path, {
        "name": "login",
        "steps": [
            {"get": "/login", "expect": {"status": 200}},
            {"post": "/login", "form": {"u": "${ENV_X}"}},
            {"extract": {"name": "csrf", "pattern": "csrf=([0-9a-f]+)"}},
            {"set_header": {"X-Token": "$csrf"}},
        ],
    })
    flow = load_flow(path)
    assert flow.name == "login"
    assert len(flow.steps) == 4
    assert flow.source == path


def test_load_flow_name_defaults_to_stem(tmp_path):
    path = _write(tmp_path, {"steps": [{"get": "/x"}]}, name="myflow.json")
    assert load_flow(path).name == "myflow"


@pytest.mark.parametrize("payload,fragment", [
    ("{not json", "invalid JSON"),
    ([1, 2], "expected a JSON object"),
    ({"steps": []}, "non-empty list"),
    ({"steps": [1]}, "step 1"),
    ({"steps": [{"get": "/x", "post": "/y"}]}, "exactly one"),
    ({"steps": [{"nope": "/x"}]}, "exactly one"),
    ({"steps": [{"get": "/x", "wat": 1}]}, "unknown key"),
    ({"steps": [{"get": 42}]}, "non-empty string"),
    ({"steps": [{"post": "/x", "form": {"a": 1}}]}, "strings"),
    ({"steps": [{"extract": {"name": "9bad", "pattern": "x"}}]}, "extract.name"),
    ({"steps": [{"extract": {"name": "c", "pattern": "("}}]}, "bad regex"),
    ({"steps": [{"extract": {"name": "c", "pattern": "x", "from": "cookie"}}]},
     "extract.from"),
    ({"steps": [{"set_header": {}}]}, "non-empty object"),
    ({"steps": [{"set_header": {"Bad Name": "v"}}]}, "bad header name"),
    ({"steps": [{"get": "/x", "expect": {}}]}, "non-empty object"),
    ({"steps": [{"get": "/x", "expect": {"status": 999}}]}, "expect.status"),
    ({"steps": [{"get": "/x", "expect": {"status": True}}]}, "expect.status"),
    ({"steps": [{"get": "/x", "expect": {"body_contains": []}}]},
     "body_contains"),
    ({"steps": [{"get": "/x", "expect": {"cookie": ""}}]}, "expect.cookie"),
    ({"steps": [{"get": "/x", "expect": {"zzz": 1}}]}, "unknown expect"),
    ({"steps": [{"get": "/x"}], "extra": 1}, "unknown key"),
    ("null", "expected a JSON object"),
])
def test_load_flow_schema_rejections(tmp_path, payload, fragment):
    path = _write(tmp_path, payload)
    with pytest.raises(FlowFormatError) as exc:
        load_flow(path)
    message = str(exc.value)
    assert message.startswith("--auth-script")
    assert fragment in message


def test_load_flow_step_limit(tmp_path):
    steps = [{"get": "/x"}] * (MAX_STEPS + 1)
    path = _write(tmp_path, {"steps": steps})
    with pytest.raises(FlowFormatError) as exc:
        load_flow(path)
    assert "step limit" in str(exc.value) or "exceed" in str(exc.value)


def test_load_flow_missing_file(tmp_path):
    with pytest.raises(FlowFormatError) as exc:
        load_flow(str(tmp_path / "nope.json"))
    assert "cannot read" in str(exc.value)


def test_substitute_env_and_captures():
    out = _substitute(
        "u=${U}&t=$tok", {"tok": "abc"}, {"U": "alice"}, "where"
    )
    assert out == "u=alice&t=abc"
    with pytest.raises(FlowRunError) as exc:
        _substitute("${MISSING_VAR}", {}, {}, "where")
    assert "MISSING_VAR" in str(exc.value)
    with pytest.raises(FlowRunError) as exc:
        _substitute("$nope", {}, {}, "where")
    assert "capture 'nope'" in str(exc.value)


def test_run_flow_happy_path():
    script = {
        "steps": [
            {"get": "/login", "expect": {"status": 200, "cookie": "session"}},
            {"extract": {"name": "sess",
                         "pattern": r"session=([A-Za-z0-9-]+)",
                         "from": "set-cookie"}},
            {"post": "/login", "form": {"user": "${VELORA_FLOW_USER}"},
             "expect": {"status": 200, "body_contains": "posted"}},
            {"set_header": {"X-Flow-Token": "$sess"}},
            {"get": "/api/data", "expect": {"status": 200}},
        ]
    }
    with fixture_env() as env:
        path = _write_flow(script)
        flow = load_flow(path)
        client = HttpClient(
            [env.host], rate=0, allow_active=True, cookie_jar=True
        )
        headers = run_flow(
            client, flow, env.base_url, env={"VELORA_FLOW_USER": "alice"}
        )
        assert headers["Cookie"] == "session=fixture-secret-abc"
        assert headers["X-Flow-Token"] == "fixture-secret-abc"
        assert "POST" in env.methods
        api = [h for m, p, h in env.log if p.startswith("/api")]
        assert api and api[0].get("Cookie") == "session=fixture-secret-abc"
        # login traffic never lands in client evidence
        assert client.evidence == []


def _write_flow(data):
    import tempfile
    import os
    handle = tempfile.NamedTemporaryFile(
        "w", suffix=".json", delete=False
    )
    json.dump(data, handle)
    handle.close()
    return handle.name


def test_run_flow_missing_env_exits_run_error():
    with fixture_env() as env:
        path = _write_flow(
            {"steps": [{"post": "/login",
                        "form": {"u": "${VELORA_FLOW_ABSENT}"}}]}
        )
        flow = load_flow(path)
        client = HttpClient([env.host], rate=0, allow_active=True, cookie_jar=True)
        with pytest.raises(FlowRunError) as exc:
            run_flow(client, flow, env.base_url, env={})
        assert "VELORA_FLOW_ABSENT" in str(exc.value)


def test_run_flow_expect_status_failure():
    with fixture_env() as env:
        path = _write_flow(
            {"steps": [{"get": "/login", "expect": {"status": 500}}]}
        )
        flow = load_flow(path)
        client = HttpClient([env.host], rate=0, allow_active=True, cookie_jar=True)
        with pytest.raises(FlowRunError) as exc:
            run_flow(client, flow, env.base_url, env={})
        assert "step 1" in str(exc.value)
        assert "expected status" in str(exc.value)


def test_run_flow_extract_miss():
    with fixture_env() as env:
        path = _write_flow(
            {"steps": [{"get": "/login"},
                       {"extract": {"name": "x", "pattern": "NOPE-NOT-THERE"}}]}
        )
        flow = load_flow(path)
        client = HttpClient([env.host], rate=0, allow_active=True, cookie_jar=True)
        with pytest.raises(FlowRunError) as exc:
            run_flow(client, flow, env.base_url, env={})
        assert "step 2" in str(exc.value)


def test_run_flow_out_of_scope_absolute_url():
    with fixture_env() as env:
        path = _write_flow({"steps": [{"get": "http://offscope.example/x"}]})
        flow = load_flow(path)
        client = HttpClient([env.host], rate=0, allow_active=True, cookie_jar=True)
        with pytest.raises(FlowRunError) as exc:
            run_flow(client, flow, env.base_url, env={})
        assert "ScopeRefused" in str(exc.value)


def test_run_flow_budget_exhausted():
    with fixture_env() as env:
        path = _write_flow({"steps": [{"get": "/login"}, {"get": "/debug"}]})
        flow = load_flow(path)
        client = HttpClient(
            [env.host], rate=0, budget=1, allow_active=True, cookie_jar=True
        )
        with pytest.raises(FlowRunError) as exc:
            run_flow(client, flow, env.base_url, env={})
        assert "BudgetExhausted" in str(exc.value)


class _HopHandler(BaseHTTPRequestHandler):
    """302 with Set-Cookie on the redirect hop itself."""

    def do_GET(self):  # noqa: N802 (http.server API)
        if self.path == "/hop":
            self.send_response(302)
            self.send_header("Location", "/land")
            self.send_header("Set-Cookie", "hop=xyz; Path=/")
            self.send_header("Content-Length", "0")
            self.end_headers()
        elif self.path == "/land":
            body = f"landed cookie={self.headers.get('Cookie', '')}".encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        else:
            self.send_response(404)
            self.send_header("Content-Length", "0")
            self.end_headers()

    def log_message(self, *args):  # keep test output quiet
        pass


def test_run_flow_captures_redirect_hop_cookies():
    server = ThreadingHTTPServer(("127.0.0.1", 0), _HopHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        base = f"http://127.0.0.1:{server.server_address[1]}"
        path = _write_flow({
            "steps": [
                {"get": "/hop", "expect": {"status": 200}},
                {"get": "/land",
                 "expect": {"body_contains": "hop=xyz"}},
            ]
        })
        flow = load_flow(path)
        client = HttpClient(["127.0.0.1"], rate=0, allow_active=True, cookie_jar=True)
        headers = run_flow(client, flow, base, env={})
        assert headers["Cookie"] == "hop=xyz"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
