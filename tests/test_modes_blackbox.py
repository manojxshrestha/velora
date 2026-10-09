"""End-to-end tests for the blackbox orchestrator (finalplan §4 / §8.2–8.5 / §11).

All network traffic stays on the loopback fixture app (tests/blackbox_fixture).
"""

import json
import time
import urllib.parse
from pathlib import Path

import pytest

from tests.blackbox_fixture import fixture_env
from velora.cli import main
from velora.modes.common import EXIT_FINDINGS, EXIT_OK, EXIT_USAGE

DETECTORS = {
    "security-headers",
    "cookie-flags",
    "server-banner",
    "reflected-input",
    "error-disclosure",
}


@pytest.fixture(scope="module")
def env():
    with fixture_env() as e:
        yield e


def run(env, session, *extra):
    argv = [
        "blackbox", env.base_url,
        "--session", str(session),
        "--rate", "0",
        *extra,
    ]
    return main(argv)


@pytest.fixture(scope="module")
def full_run(env, tmp_path_factory):
    session = tmp_path_factory.mktemp("bb-full")
    code = run(env, session, "--fail-on", "none")
    assert code == EXIT_OK
    return env, session


def _read(session, name):
    return json.loads((Path(session) / name).read_text())


# ---------------------------------------------------------------------------
# Full default pipeline
# ---------------------------------------------------------------------------

def test_full_pipeline_finds_ground_truth(full_run):
    _, session = full_run
    findings = _read(session, "findings.json")
    assert len(findings) >= 5
    assert {f.get("detector") for f in findings} == DETECTORS
    for f in findings:
        assert f["mode"] == "blackbox"
        assert f["provenance"] == "dynamic"
        assert f["asset"]["kind"] == "web"
        assert f["asset"]["id"]
        assert f["evidence"]["kind"] == "reqresp"
        assert f["evidence"]["request"]
        assert f["evidence"]["response"]
        assert f["evidence"]["replay"]["method"] == "GET"
        assert f["evidence"]["replay"]["url"]
        assert f["reproduced"] >= 2
        assert f["score"]["from"] == "rubric"
        assert f["cwe_id"].startswith("CWE-")
    report = (Path(session) / "report.md").read_text()
    assert "# Velora Security Report" in report
    for f in findings:
        if str(f["severity"]).lower() in ("low", "medium", "high", "critical"):
            assert f["type"] in report


def test_verify_and_validate_reproduce(full_run):
    _, session = full_run
    verify = _read(session, "verify.json")
    validate = _read(session, "validate.json")
    assert verify["checked"] >= 5 and verify["reproduced"] == verify["checked"]
    assert validate["checked"] >= 5
    assert validate["reproduced"] == validate["checked"]


def test_surface_covers_fixture_endpoints(full_run):
    _, session = full_run
    surface = _read(session, "surface.json")
    endpoints = surface["endpoints"]
    for path in ("/", "/search", "/login", "/debug", "/robots.txt",
                 "/app.js", "/api/data", "/openapi.json"):
        assert any(u.endswith(path) for u in endpoints), path
    search = next(u for u in endpoints if u.endswith("/search"))
    assert "q" in (endpoints[search].get("params") or {})
    assert surface["tech"].get("server")


def test_recon_discovery(full_run):
    _, session = full_run
    recon = _read(session, "recon.json")

    def path_of(url):
        return urllib.parse.urlsplit(url).path.strip("/")

    paths = {path_of(p["url"]) for p in recon["pages"]}
    discovered = {path_of(d) for d in recon["discovered"]}
    assert "admin" in discovered  # robots.txt Disallow
    assert "api/data" in discovered  # app.js extraction
    assert any("evil.example" in u for u in recon["external"])
    assert any("external.example" in u for u in recon["external"])
    assert recon["budget_exhausted"] is False
    assert len(recon["pages"]) >= 12
    assert "search" in paths


def test_non_destructive_default(full_run, env):
    # A default run may only use inert verbs (§11): no state-changing calls.
    # HEAD (service-mapping probe) is inert — client INERT_VERBS.
    assert set(env.methods) <= {"GET", "OPTIONS", "HEAD"}


def test_api_operations_adapter(full_run):
    _, session = full_run
    recon = _read(session, "recon.json")
    (op,) = recon["api_ops"]
    assert op["method"] == "GET"
    assert op["path"] == "/api/data"
    assert op["summary"] == "data"
    assert op["operation_id"] is None
    assert op["params"] == []
    assert op["security"] is None
    surface = _read(session, "surface.json")
    assert surface["api_ops"] == recon["api_ops"]
    assert surface["counts"]["api_ops"] == 1
    stats = _read(session, "enumerate.json")
    assert stats["api_ops"] == 1
    assert stats["api_ops_unverified"] == []


def test_service_mapping_full_adapter(full_run):
    _, session = full_run
    mapping = _read(session, "service-map.json")
    assert mapping["capability"] == "full"
    assert "no raw/SYN" in (mapping.get("note") or "")
    assert mapping["stats"]["open"] >= 1
    scanned = [s for s in mapping["services"] if s["host"] == "127.0.0.1"]
    assert scanned
    target = next(s for s in scanned if "scan" in s.get("source", ""))
    assert target["service"] in ("http", "https")
    assert target["probe"] in ("http-head", "banner", "tls")
    assert target.get("scheme") in ("http", "https")


def test_ai_exploit_disabled_is_na(env, tmp_path, capsys):
    code = run(env, tmp_path, "--fail-on", "none")
    assert code == EXIT_OK
    assert "n/a: EXPLOIT" in capsys.readouterr().err


# ---------------------------------------------------------------------------
# Safety rails: scope pinning + indirect prompt injection (§11)
# ---------------------------------------------------------------------------

def test_scope_and_egress_pinned(full_run, env):
    _, session = full_run
    target_netloc = f"{env.host}:{env.port}"
    evidence = _read(session, "evidence.json")["evidence"]
    assert evidence
    for entry in evidence:
        netloc = urllib.parse.urlsplit(entry["url"]).netloc
        assert netloc == target_netloc, entry["url"]
        assert "evil.example" not in entry["url"]
        assert "localhost" not in netloc
    scope = _read(session, "scope.json")
    assert scope["hosts"] == ["127.0.0.1"]
    recon = _read(session, "recon.json")
    assert any("ScopeRefused" in err for err in recon["errors"])


def test_ipi_poisoned_page_not_interpreted(full_run, env):
    _, session = full_run
    # The poisoned fixture page injects directives (HTML/JS/header) telling the
    # agent to widen scope and exfiltrate to evil.example. None of that may
    # become behaviour or content.
    scope = _read(session, "scope.json")
    assert scope["hosts"] == ["127.0.0.1"]
    evidence = _read(session, "evidence.json")["evidence"]
    assert all("evil.example" not in e["url"] for e in evidence)
    report = (Path(session) / "report.md").read_text()
    assert "evil.example" not in report
    assert "IGNORE ALL PREVIOUS" not in report
    # Scope/refusal behaviour still worked: the poisoned page itself was
    # fetched (it is in-scope data), and only with inert verbs.
    assert any("poisoned" in e["url"] for e in evidence)
    assert set(env.methods) <= {"GET", "OPTIONS", "HEAD"}


# ---------------------------------------------------------------------------
# Budget / rate rails
# ---------------------------------------------------------------------------

def test_budget_exhaustion_is_normal_stop(env, tmp_path):
    code = run(env, tmp_path, "--fail-on", "none", "--budget", "3")
    assert code == EXIT_OK
    recon = _read(tmp_path, "recon.json")
    assert recon["budget_exhausted"] is True
    assert (Path(tmp_path) / "report.md").exists()
    assert (Path(tmp_path) / "evidence.json").exists()


def test_rate_cap_spaces_requests(env, tmp_path):
    started = time.monotonic()
    code = run(
        env, tmp_path,
        "--until", "surface",
        "--rate", "5",
        "--depth", "0",
    )
    elapsed = time.monotonic() - started
    assert code == EXIT_OK
    # At 5 rps the seed + robots + sitemap fetches need >= ~0.4s of spacing;
    # the assert is loosened to stay robust on fast machines.
    assert elapsed >= 0.25


# ---------------------------------------------------------------------------
# Grammar: exit codes, refusals, stage selection
# ---------------------------------------------------------------------------

def test_missing_target_exits_findings(tmp_path, capsys):
    code = main(["blackbox", "--session", str(tmp_path / "s")])
    assert code == EXIT_FINDINGS
    assert "missing required input" in capsys.readouterr().err


def test_only_validate_without_findings_exits_findings(env, tmp_path, capsys):
    assert run(env, tmp_path, "--until", "surface") == EXIT_OK
    code = run(env, tmp_path, "--only", "validate")
    assert code == EXIT_FINDINGS
    assert "requires findings" in capsys.readouterr().err


def test_osint_with_target_runs_cert_and_dns(env, tmp_path, capsys):
    session = tmp_path / "osint-sess"
    code = run(env, session, "--only", "osint", "--fail-on", "none")
    assert code == EXIT_OK
    err = capsys.readouterr().err
    assert "OSINT" in err
    data = _read(session, "osint.json")
    assert "partial" in data["capability"]
    entry = data["hosts"][0]
    assert entry["host"] == "127.0.0.1"
    assert entry["dns"]["a"] == ["127.0.0.1"]
    assert "error" in entry["cert"] or "subject" in entry["cert"]


def test_malformed_header_exits_usage(env, tmp_path, capsys):
    code = run(env, tmp_path, "--header", "NoColonValue")
    assert code == EXIT_USAGE
    assert "--header" in capsys.readouterr().err


def test_bad_auth_file_exits_findings(env, tmp_path, capsys):
    code = run(env, tmp_path, "--auth-file", str(tmp_path / "missing.txt"))
    assert code == EXIT_FINDINGS
    assert "--auth-file" in capsys.readouterr().err


def test_until_surface_is_recon_only(env, tmp_path):
    code = run(env, tmp_path, "--until", "surface")
    assert code == EXIT_OK
    assert (Path(tmp_path) / "surface.json").exists()
    assert not (Path(tmp_path) / "findings.json").exists()
    assert not (Path(tmp_path) / "hunt.json").exists()


def test_resume_from_hunt(env, tmp_path):
    assert run(env, tmp_path, "--until", "enumerate") == EXIT_OK
    code = run(env, tmp_path, "--from", "hunt", "--fail-on", "none")
    assert code == EXIT_OK
    findings = _read(tmp_path, "findings.json")
    assert len(findings) >= 5


def test_offscope_seed_is_refused(env, tmp_path, capsys):
    code = run(
        env, tmp_path,
        "--until", "recon",
        "--seed", "http://evil.example/seed",
    )
    assert code == EXIT_OK
    err = capsys.readouterr().err
    assert "out of scope" in err
    recon = _read(tmp_path, "recon.json")
    assert all("evil.example" not in p["url"] for p in recon["pages"])


# ---------------------------------------------------------------------------
# Auth: sent on the wire, redacted at rest (§8.5)
# ---------------------------------------------------------------------------

def test_header_auth_sent_and_redacted(env, tmp_path):
    token = "e2e-secret-tok-931"
    code = run(env, tmp_path, "--header", f"Authorization: Bearer {token}")
    assert code == EXIT_OK
    seen = [
        headers.get("Authorization") or headers.get("authorization")
        for _method, _path, headers in env.log
    ]
    assert any(v == f"Bearer {token}" for v in seen)
    evidence = _read(tmp_path, "evidence.json")["evidence"]
    auth_headers = [
        (e.get("request_headers") or {}).get("Authorization")
        or (e.get("request_headers") or {}).get("authorization")
        for e in evidence
    ]
    assert auth_headers and all(v == "***" for v in auth_headers if v)
    for path in Path(tmp_path).iterdir():
        if path.is_file():
            assert token not in path.read_text(errors="ignore"), path.name


def test_auth_refs_unreplayable_warns(env, tmp_path, capsys):
    token = "e2e-secret-tok-replay"
    # Stage the header as a refs-only secret, then resume with recon: the
    # auth stage is already committed, but the client still replays refs on
    # resume and must warn that the value is not recoverable.
    assert run(env, tmp_path, "--only", "auth",
               "--header", f"X-Api-Key: {token}") == EXIT_OK
    code = run(env, tmp_path, "--until", "recon", "--fail-on", "none")
    assert code == EXIT_OK
    err = capsys.readouterr().err
    assert "not replayable" in err


# ---------------------------------------------------------------------------
# Reports: json / sarif / formats
# ---------------------------------------------------------------------------

def test_json_report(env, tmp_path):
    out = tmp_path / "report.json"
    code = run(env, tmp_path, "-f", "json", "-o", str(out),
               "--fail-on", "none")
    assert code == EXIT_OK
    payload = json.loads(out.read_text())
    assert payload["mode"] == "blackbox"
    assert payload["count"] >= 4  # info severity floored out at "low"
    assert all(f["provenance"] == "dynamic" for f in payload["findings"])
    assert all(f["evidence"]["kind"] == "reqresp" for f in payload["findings"])


def test_sarif_report(env, tmp_path):
    out = tmp_path / "report.sarif"
    code = run(env, tmp_path, "-f", "sarif", "-o", str(out),
               "--fail-on", "none")
    assert code == EXIT_OK
    doc = json.loads(out.read_text())
    assert doc["version"] == "2.1.0"
    results = doc["runs"][0]["results"]
    assert results
    for res in results:
        assert res["ruleId"].startswith("velora/")
        assert res["properties"]["provenance"] == "dynamic"
        assert res["properties"]["mode"] == "blackbox"


def test_text_report_to_stdout(env, tmp_path, capsys):
    code = run(env, tmp_path, "--fail-on", "none")
    assert code == EXIT_OK
    out = capsys.readouterr().out
    assert "# Velora Security Report" in out


# ---------------------------------------------------------------------------
# Off-default stages / plan (§7.3 surface[])
# ---------------------------------------------------------------------------

def test_with_plan_yields_dynamic_leads(env, tmp_path):
    code = run(env, tmp_path, "--fail-on", "none", "--with-plan")
    assert code == EXIT_OK
    guidance = _read(tmp_path, "guidance.json")
    leads = guidance["leads"]
    assert len(leads) >= 5
    assert guidance["provenance"] == "dynamic"
    assert guidance["surface"]
    for lead in leads:
        assert lead["provenance"] == "dynamic"
        assert isinstance(lead["surface"], list)
        assert lead["surface"]
        assert all(
            "evil.example" not in str(s) for s in lead["surface"]
        )


# ---------------------------------------------------------------------------
# CLI surfaces
# ---------------------------------------------------------------------------

def test_dry_run_shows_blackbox_budget_default(env, tmp_path, capsys):
    code = main([
        "blackbox", env.base_url,
        "--session", str(tmp_path),
        "--dry-run",
    ])
    assert code == EXIT_OK
    out = capsys.readouterr().out
    assert "500 HTTP requests" in out


def test_list_stages_has_no_planned_engines(env, tmp_path, capsys):
    code = main(["blackbox", "--list-stages"])
    assert code == EXIT_OK
    out = capsys.readouterr().out
    assert "hunt" in out
    assert "planned (" not in out


# ---------------------------------------------------------------------------
# Phase 4: scripted AUTH login flows (login-script DSL)
# ---------------------------------------------------------------------------

def _write_flow(tmp_path, steps, name="login.json"):
    path = Path(tmp_path) / name
    path.write_text(json.dumps({"steps": steps}))
    return str(path)


def test_auth_script_logs_in_and_sends_session(env, tmp_path, monkeypatch):
    monkeypatch.setenv("VELORA_BB_FLOW_USER", "alice")
    monkeypatch.setenv("VELORA_BB_FLOW_PASS", "s3cret-via-env")
    script = _write_flow(tmp_path, [
        {"get": "/login", "expect": {"status": 200, "cookie": "session"}},
        {"extract": {"name": "sess", "pattern": r"session=([A-Za-z0-9-]+)",
                     "from": "set-cookie"}},
        {"post": "/login", "form": {"user": "${VELORA_BB_FLOW_USER}",
                                    "pass": "${VELORA_BB_FLOW_PASS}"},
         "expect": {"status": 200, "body_contains": "posted"}},
        {"set_header": {"X-Flow-Token": "$sess"}},
        {"get": "/api/data", "expect": {"status": 200, "body_contains": "ok"}},
    ])
    start = len(env.log)
    code = run(env, tmp_path, "--auth-script", script, "--until", "auth",
               "--fail-on", "none")
    assert code == EXIT_OK
    auth = _read(tmp_path, "auth.json")
    assert auth["refs"] == [{
        "kind": "auth-script",
        "name": script,
        "ref": f"file:{script}",
        "role": "default",
    }]
    assert set(auth["headers"]) == {"Cookie", "X-Flow-Token"}
    assert auth["scripts"][0]["steps"] == 5
    flow_log = env.log[start:]
    assert any(m == "POST" and p == "/login" for m, p, _h in flow_log)
    api = [h for m, p, h in flow_log if p.startswith("/api")]
    assert api, flow_log
    lowered = {k.lower(): v for k, v in api[0].items()}
    assert lowered.get("cookie") == "session=fixture-secret-abc"
    assert lowered.get("x-flow-token") == "fixture-secret-abc"
    # secrets-at-rest: captured cookies and env credentials never hit the
    # session — only file: references and header *names* may appear
    for path in Path(tmp_path).iterdir():
        if path.is_file():
            text = path.read_text(errors="ignore")
            assert "fixture-secret-abc" not in text, path.name
            assert "s3cret-via-env" not in text, path.name
            assert "alice" not in text, path.name


def test_auth_script_missing_env_exits_findings(env, tmp_path, capsys):
    script = _write_flow(tmp_path, [
        {"post": "/login", "form": {"u": "${VELORA_BB_ABSENT_VAR}"}},
    ])
    code = run(env, tmp_path, "--auth-script", script, "--until", "auth")
    assert code == EXIT_FINDINGS
    err = capsys.readouterr().err
    assert "--auth-script" in err
    assert "VELORA_BB_ABSENT_VAR" in err


def test_auth_script_expect_failure_exits_findings(env, tmp_path, capsys):
    script = _write_flow(tmp_path, [
        {"get": "/login", "expect": {"status": 500}},
    ])
    code = run(env, tmp_path, "--auth-script", script, "--until", "auth")
    assert code == EXIT_FINDINGS
    err = capsys.readouterr().err
    assert "step 1" in err
    assert "expected status" in err


def test_auth_script_missing_file_exits_findings(env, tmp_path, capsys):
    code = run(env, tmp_path, "--auth-script",
               str(tmp_path / "no-such-flow.json"), "--until", "auth")
    assert code == EXIT_FINDINGS
    assert "--auth-script" in capsys.readouterr().err


def test_auth_script_ignored_when_auth_not_selected(env, tmp_path, capsys):
    script = _write_flow(tmp_path, [{"get": "/login"}])
    code = run(env, tmp_path, "--auth-script", script, "--only", "recon",
               "--fail-on", "none")
    assert code == EXIT_OK
    err = capsys.readouterr().err
    assert "--auth-script ignored" in err


def test_script_budget_offsets_main_client():
    from types import SimpleNamespace

    from velora.modes.blackbox import _client

    ctx = SimpleNamespace(
        args=SimpleNamespace(
            http_budget=10, budget=None, rate=0, proxy=None, insecure=False,
            user_agent=None, header=None, auth_file=None, auth_script=None,
            scope=None, scope_file=None,
        ),
        inputs=SimpleNamespace(target="http://example.test"),
        session=None,
        selection=None,
        _bb_budget_used=3,
    )
    assert _client(ctx).budget == 7


def test_auth_file_roles_isolated(env, tmp_path):
    user_file = tmp_path / "user.txt"
    user_file.write_text("X-Run-Key: run-value\n")
    admin_file = tmp_path / "admin.txt"
    admin_file.write_text("X-Admin-Key: admin-value\n")
    start = len(env.log)
    code = run(env, tmp_path,
               "--auth-file", str(user_file),
               "--auth-file", f"admin={admin_file}",
               "--until", "recon", "--fail-on", "none")
    assert code == EXIT_OK
    auth = _read(tmp_path, "auth.json")
    assert auth["roles"] == {
        "admin": ["X-Admin-Key"],
        "default": ["X-Run-Key"],
    }
    seen = [h for _m, _p, h in env.log[start:]]
    flat = [{k.lower(): v for k, v in h.items()} for h in seen]
    assert any(h.get("x-run-key") == "run-value" for h in flat)
    assert all("x-admin-key" not in h for h in flat)


# ---------------------------------------------------------------------------
# Machine-readable progress (--progress json, NDJSON stage events on stderr)
# ---------------------------------------------------------------------------
def _ndjson_events(err: str):
    events = []
    for line in err.splitlines():
        if line.startswith("{"):
            events.append(json.loads(line))
    return events


def test_progress_json_emits_stage_events(env, tmp_path, capsys):
    code = run(env, tmp_path, "--until", "surface", "--progress", "json")
    assert code == EXIT_OK
    err = capsys.readouterr().err
    events = _ndjson_events(err)
    starts = [e for e in events if e["event"] == "stage_start"]
    ends = [e for e in events if e["event"] == "stage_end"]
    assert starts and ends
    assert {e["stage"] for e in starts} <= {
        "scope", "auth", "recon", "asset-discovery", "surface"}
    assert all(e["status"] in ("ok", "na") for e in ends)
    assert all({"stage", "index", "total", "label"} <= set(e)
               for e in starts)
    # human stage banners are replaced by events
    assert "[velora] stage " not in err


def test_progress_json_emits_stage_skip_on_rerun(env, tmp_path, capsys):
    assert run(env, tmp_path, "--until", "surface", "--progress", "json") == EXIT_OK
    capsys.readouterr()
    code = run(env, tmp_path, "--until", "surface", "--progress", "json")
    assert code == EXIT_OK
    events = _ndjson_events(capsys.readouterr().err)
    skips = [e for e in events if e["event"] == "stage_skip"]
    assert skips
    assert skips[0]["reason"] == "already committed"
