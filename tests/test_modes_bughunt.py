"""End-to-end tests for the bughunt loop (finalplan §4 / §8.4–8.5 / §10).

All network traffic stays on the loopback fixture app (tests/blackbox_fixture).
"""

import json
import urllib.parse
from pathlib import Path

import pytest

from tests.blackbox_fixture import fixture_env
from velora.cli import main
from velora.modes.common import EXIT_FINDINGS, EXIT_OK

DETECTORS = {
    "security-headers",
    "cookie-flags",
    "server-banner",
    "reflected-input",
    "error-disclosure",
}

VALID_CLAIM = (
    "GET /search?q reflects unencoded into HTML, so an attacker injects "
    "script through q (CWE-79)"
)
VAGUE_CLAIM = "there might be a security issue somewhere on the login"
FALSE_CLAIM = (
    "GET /never-appears reflects unencoded content so an attacker injects "
    "through the id parameter (CWE-79)"
)


@pytest.fixture(scope="module")
def env():
    with fixture_env() as e:
        yield e


def run(env, session, *extra):
    return main(["bughunt", env.base_url, "--session", str(session), *extra])


def _read(session, name):
    return json.loads((Path(session) / name).read_text())


def _seed(tmp_path, entries, name="seed.json"):
    path = tmp_path / name
    path.write_text(json.dumps(entries))
    return path


@pytest.fixture(scope="module")
def full_run(env, tmp_path_factory):
    session = tmp_path_factory.mktemp("bh-full")
    code = run(env, session, "--fail-on", "none")
    assert code == EXIT_OK
    return env, session


# ---------------------------------------------------------------------------
# Full default loop: terminates, finds ground truth, stays pinned
# ---------------------------------------------------------------------------

def test_full_loop_converges_and_stays_in_scope(full_run):
    env, session = full_run
    loop = _read(session, "loop.json")
    assert loop["iterations"] >= 1
    assert loop["reason"] == "converged"
    findings = _read(session, "findings.json")
    assert len(findings) >= 5
    assert {f.get("detector") for f in findings} == DETECTORS
    assert set(env.methods) <= {"GET", "OPTIONS"}
    scope = _read(session, "scope.json")
    assert scope["hosts"] == ["127.0.0.1"]
    target_netloc = f"{env.host}:{env.port}"
    for entry in _read(session, "evidence.json")["evidence"]:
        netloc = urllib.parse.urlsplit(entry["url"]).netloc
        assert netloc == target_netloc, entry["url"]
        assert "evil.example" not in entry["url"]


def test_report_is_bounty_format(full_run):
    _, session = full_run
    text = (Path(session) / "report.md").read_text()
    # 5 detector findings; report floor (low) drops the info-severity
    # server-banner one → 4 submission sections.
    assert text.count("**Proof of concept**") == 4
    assert "**Endpoint:**" in text
    assert "detector=`server-banner`" not in text
    assert "## Hypothesis ledger" in text
    assert "**Loop:**" in text and "terminated by `converged`" in text
    ledger = _read(session, "hypotheses.json")
    assert ledger["counts"]["proven"] >= 5
    assert ledger["counts"]["open"] == 0


def test_deepthink_hypotheses_are_falsifiable(full_run):
    _, session = full_run
    for entry in _read(session, "hypotheses.json")["hypotheses"]:
        assert len(entry["claim"]) >= 20
        assert entry.get("falsifier") or entry.get("subject")
        assert entry["status"] in ("open", "proven", "eliminated")


# ---------------------------------------------------------------------------
# Termination: budget · time · max-loop · convergence
# ---------------------------------------------------------------------------

def test_budget_zero_stops_before_first_iteration(env, tmp_path, capsys):
    session = tmp_path / "s"
    assert run(env, session, "--budget", "0",
               "--fail-on", "none") == EXIT_OK
    err = capsys.readouterr().err
    loop = _read(session, "loop.json")
    assert loop["iterations"] == 0
    assert loop["reason"] == "budget"
    assert "reason=budget" in err
    assert (Path(session) / "report.md").exists()


def test_time_budget_zero_stops_before_first_iteration(env, tmp_path, capsys):
    session = tmp_path / "s"
    assert run(env, session, "--time-budget", "0",
               "--fail-on", "none") == EXIT_OK
    err = capsys.readouterr().err
    loop = _read(session, "loop.json")
    assert loop["iterations"] == 0
    assert loop["reason"] == "time"
    assert "reason=time" in err


def test_max_loop_one_runs_exactly_one_iteration(env, tmp_path, capsys):
    session = tmp_path / "s"
    assert run(env, session, "--max-loop", "1",
               "--fail-on", "none") == EXIT_OK
    err = capsys.readouterr().err
    loop = _read(session, "loop.json")
    assert loop["iterations"] == 1
    assert loop["reason"] == "max-loop"
    assert "loop iteration 1:" in err
    assert "reason=max-loop" in err


# ---------------------------------------------------------------------------
# Seed ledger: vague rejected at ingest, false claim eliminated once
# ---------------------------------------------------------------------------

def test_seed_vague_rejected_false_eliminated(env, tmp_path, capsys):
    seed = _seed(tmp_path, [
        {"claim": VALID_CLAIM, "location": "/search"},
        {"claim": VAGUE_CLAIM, "location": "/login"},
        {"claim": FALSE_CLAIM, "location": "/never-appears"},
    ])
    session = tmp_path / "s"
    assert run(env, session, "--hypotheses", str(seed),
               "--max-loop", "1", "--fail-on", "none") == EXIT_OK
    err = capsys.readouterr().err
    assert "rejected (not falsifiable)" in err

    ledger = _read(session, "hypotheses.json")
    entries = ledger["hypotheses"]
    claims = [e["claim"] for e in entries]
    assert VAGUE_CLAIM not in claims

    def status_of(claim):
        matches = [e for e in entries if e["claim"] == claim]
        assert len(matches) == 1, claim
        return matches[0]["status"]

    assert status_of(FALSE_CLAIM) == "eliminated"
    assert status_of(VALID_CLAIM) == "proven"
    ids = [e["id"] for e in entries]
    assert len(ids) == len(set(ids))
    assert ledger["counts"]["open"] == 0
    assert ledger["counts"]["eliminated"] == 1
    assert ledger["counts"]["proven"] >= 6

    fps = [e["fingerprint"] for e in entries]
    assert len(fps) == len(set(fps))


def test_rerun_neither_duplicates_nor_resurrects(env, tmp_path, capsys):
    seed = _seed(tmp_path, [
        {"claim": VALID_CLAIM, "location": "/search"},
        {"claim": FALSE_CLAIM, "location": "/never-appears"},
    ])
    session = tmp_path / "s"
    assert run(env, session, "--hypotheses", str(seed),
               "--max-loop", "1", "--fail-on", "none") == EXIT_OK
    first = _read(session, "hypotheses.json")
    assert run(env, session, "--hypotheses", str(seed),
               "--fail-on", "none") == EXIT_OK
    capsys.readouterr()
    second = _read(session, "hypotheses.json")

    assert len(second["hypotheses"]) == len(first["hypotheses"])
    assert second["counts"]["eliminated"] == 1
    fps = [e["fingerprint"] for e in second["hypotheses"]]
    assert len(fps) == len(set(fps))
    false = [e for e in second["hypotheses"] if e["claim"] == FALSE_CLAIM]
    assert len(false) == 1 and false[0]["status"] == "eliminated"


# ---------------------------------------------------------------------------
# Subcommands: ledger / gaps / resume
# ---------------------------------------------------------------------------

def test_subcommands_report_loop_state(full_run, capsys):
    _, session = full_run
    assert main(["bughunt", "ledger",
                 "--session", str(session)]) == EXIT_OK
    out = capsys.readouterr().out
    assert "ledger:" in out and "proven:" in out

    assert main(["bughunt", "gaps", "--session", str(session)]) == EXIT_OK
    out = capsys.readouterr().out
    assert "loop:" in out and "reason=converged" in out
    assert "gaps:" in out

    assert main(["bughunt", "resume", "--session", str(session)]) == EXIT_OK
    out = capsys.readouterr().out
    assert "--from hunt" in out and str(session) in out


def test_subcommands_refuse_to_guess_session(tmp_path, capsys):
    assert main(["bughunt", "ledger"]) == EXIT_FINDINGS
    captured = capsys.readouterr()
    assert "refusing to guess" in captured.err + captured.out
    assert main(["bughunt", "gaps",
                 "--session", str(tmp_path)]) == EXIT_FINDINGS
    assert "no session.json" in capsys.readouterr().err


# ---------------------------------------------------------------------------
# Stage grammar and input guards
# ---------------------------------------------------------------------------

def test_only_osint_with_target_runs(env, tmp_path, capsys):
    session = tmp_path / "s"
    assert run(env, session, "--only", "osint",
               "--fail-on", "none") == EXIT_OK
    err = capsys.readouterr().err
    assert "OSINT" in err
    data = _read(session, "osint.json")
    assert "partial" in data["capability"]
    assert data["hosts"][0]["dns"]["a"] == ["127.0.0.1"]
    assert "error" in data["hosts"][0]["cert"] or "subject" in data["hosts"][0]["cert"]


def test_only_osint_without_target_exits_findings(tmp_path, capsys):
    src = tmp_path / "src"
    src.mkdir()
    (src / "app.py").write_text("x = 1\n")
    assert main(["bughunt", "--source", str(src),
                 "--session", str(tmp_path / "sess"),
                 "--only", "osint"]) == EXIT_FINDINGS
    assert "requires a target" in capsys.readouterr().err


def test_missing_input_exits_findings(tmp_path):
    assert main(["bughunt",
                 "--session", str(tmp_path / "s")]) == EXIT_FINDINGS


def test_only_validate_without_findings(env, tmp_path, capsys):
    assert run(env, tmp_path / "s", "--only", "validate") == EXIT_FINDINGS
    assert "requires findings" in capsys.readouterr().err


def test_dry_run_shows_bughunt_budget(env, tmp_path, capsys):
    assert run(env, tmp_path / "s", "--dry-run") == EXIT_OK
    out = capsys.readouterr().out
    assert "100 LLM steps" in out
    assert "DEEPTHINK" in out and "HUNT" in out and "SEARCH" in out


def test_list_stages_reports_existing_loop_engines(capsys):
    assert main(["bughunt", "--list-stages"]) == EXIT_OK
    out = capsys.readouterr().out
    assert "exists (gap analysis + convergence)" in out
    assert "exists (falsifiable hypotheses + elimination memory)" in out


# ---------------------------------------------------------------------------
# Source-only run (no target): reaches REPORT without network
# ---------------------------------------------------------------------------

def test_source_only_reaches_report(tmp_path, capsys):
    src = tmp_path / "src"
    src.mkdir()
    (src / "app.py").write_text("def handler(user):\n    return user\n")
    session = tmp_path / "sess"
    assert main(["bughunt", "--source", str(src),
                 "--session", str(session),
                 "--fail-on", "none"]) == EXIT_OK
    captured = capsys.readouterr()
    assert (Path(session) / "report.md").exists()
    loop = _read(session, "loop.json")
    assert loop["iterations"] >= 1
    assert loop["reason"] == "converged"
    assert "reason=converged" in captured.err


def test_auth_script_runs_via_blackbox_delegate(env, tmp_path):
    script = tmp_path / "login.json"
    script.write_text(json.dumps({"steps": [
        {"get": "/login", "expect": {"status": 200, "cookie": "session"}},
        {"get": "/api/data", "expect": {"status": 200}},
    ]}))
    start = len(env.log)
    code = run(env, tmp_path, "--auth-script", str(script), "--only", "auth")
    assert code == EXIT_OK
    auth = _read(tmp_path, "auth.json")
    assert auth["scripts"][0] == {
        "name": str(script),
        "role": "default",
        "steps": 2,
        "headers": ["Cookie"],
    }
    flow = [(m, p) for m, p, _h in env.log[start:]]
    assert ("GET", "/login") in flow
    assert ("GET", "/api/data") in flow
    # captured session cookie is a reference/name only — value never stored
    assert "fixture-secret-abc" not in Path(tmp_path, "auth.json").read_text()
