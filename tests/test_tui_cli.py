"""CLI-level TUI wiring: gate truth table, child argv construction, report cmd."""

import io
import json
import os
import sys

import pytest

from velora.cli import _run_tui_wrap, _tui_active, cmd_report, create_parser, main


@pytest.fixture
def clean_env(monkeypatch):
    monkeypatch.delenv("VELORA_TUI", raising=False)
    monkeypatch.delenv("VELORA_TUI_CHILD", raising=False)
    return monkeypatch


def _args(raw):
    return create_parser().parse_args(raw)


# -- gate truth table ---------------------------------------------------
def test_gate_off_when_not_a_tty(clean_env):
    assert _tui_active(_args(["scan", "."]), ["scan", "."]) is False


def test_gate_off_for_child_process(clean_env, monkeypatch):
    monkeypatch.setattr(sys.stdin, "isatty", lambda: True)
    monkeypatch.setattr(sys.stdout, "isatty", lambda: True)
    clean_env.setenv("VELORA_TUI_CHILD", "1")
    assert _tui_active(_args(["scan", "."]), ["scan", "."]) is False


def test_gate_off_when_env_disabled(clean_env, monkeypatch):
    monkeypatch.setattr(sys.stdin, "isatty", lambda: True)
    monkeypatch.setattr(sys.stdout, "isatty", lambda: True)
    clean_env.setenv("VELORA_TUI", "0")
    assert _tui_active(_args(["scan", "."]), ["scan", "."]) is False


def test_gate_off_with_no_tui_flag(clean_env, monkeypatch):
    monkeypatch.setattr(sys.stdin, "isatty", lambda: True)
    monkeypatch.setattr(sys.stdout, "isatty", lambda: True)
    assert _tui_active(_args(["scan", ".", "--no-tui"]),
                       ["scan", ".", "--no-tui"]) is False


def test_gate_off_when_guidance_reads_stdin(clean_env, monkeypatch):
    monkeypatch.setattr(sys.stdin, "isatty", lambda: True)
    monkeypatch.setattr(sys.stdout, "isatty", lambda: True)
    args = _args(["exploit", "--target", "http://x", "--guidance", "-"])
    assert _tui_active(args, ["exploit", "--target", "http://x"]) is False


def test_gate_on_for_tty(clean_env, monkeypatch):
    monkeypatch.setattr(sys.stdin, "isatty", lambda: True)
    monkeypatch.setattr(sys.stdout, "isatty", lambda: True)
    assert _tui_active(_args(["exploit", "--target", "http://x"]),
                       ["exploit", "--target", "http://x"]) is True
    assert _tui_active(_args(["scan", ".", "--ai"]),
                       ["scan", ".", "--ai"]) is True


# -- dispatch: main routes scan/exploit with raw argv --------------------
def test_main_passes_raw_argv_to_scan(clean_env, monkeypatch, tmp_path):
    import velora.cli as cli_mod
    seen = {}

    def fake_cmd(args, _raw_argv=None):
        seen["raw"] = _raw_argv
        return 0

    monkeypatch.setattr(cli_mod, "cmd_scan", fake_cmd)
    assert cli_mod.main(["scan", ".", "--ai"]) == 0
    assert seen["raw"] == ["scan", ".", "--ai"]


def test_non_tty_main_scan_stays_plain(clean_env, monkeypatch):
    """Piped run must reach the real scan handler, never the TUI wrapper."""
    import velora.cli as cli_mod
    called = {"wrap": 0, "scan": 0}

    monkeypatch.setattr(cli_mod, "_run_tui_wrap",
                        lambda *a, **k: called.__setitem__("wrap", 1) or 99)

    def plain(args, _raw_argv=None):
        called["scan"] += 1
        return 0

    monkeypatch.setattr(cli_mod, "cmd_scan", plain)
    rc = cli_mod.main(["scan", "examples/app.py", "--no-verify"])
    assert rc == 0 and called["scan"] == 1 and called["wrap"] == 0


# -- child argv construction --------------------------------------------
def test_wrap_builds_child_from_raw_argv(clean_env, monkeypatch):
    import velora.cli as cli_mod
    seen = {}

    class FakeRunner:
        def __init__(self, spec):
            seen["spec"] = spec

        def child_done(self):
            return True

        def stop(self):
            pass

    monkeypatch.setattr("velora.tui.runner.TuiRunner", FakeRunner)

    def fake_run_tui(runner, kind, subject):
        seen[("tui", kind, subject)] = True
        return 0

    monkeypatch.setattr("velora.tui.render.run_tui", fake_run_tui)

    args = _args(["exploit", "--target", "http://t", "--max-steps", "7"])
    rc = cli_mod._run_tui_wrap(args, ["exploit", "--target", "http://t",
                                      "--max-steps", "7"])
    assert rc == 0
    spec = seen["spec"]
    assert spec.argv[1:3] == ["-m", "velora"]
    assert spec.argv[3:] == ["exploit", "--target", "http://t", "--max-steps", "7"]
    assert spec.env["VELORA_TUI_CHILD"] == "1"
    assert spec.kind == "exploit" and spec.feed is True
    assert spec.subject == "http://t"
    assert ("tui", "exploit", "http://t") in seen


def test_wrap_scan_sets_findings_out_only_for_json(clean_env, monkeypatch):
    import velora.cli as cli_mod
    seen = {}

    class FakeRunner:
        def __init__(self, spec):
            seen["spec"] = spec

    monkeypatch.setattr("velora.tui.runner.TuiRunner", FakeRunner)
    monkeypatch.setattr("velora.tui.render.run_tui",
                        lambda *a, **k: 0)

    args = _args(["scan", ".", "-f", "json", "-o", "/tmp/out.json"])
    cli_mod._run_tui_wrap(args, ["scan", ".", "-f", "json", "-o", "/tmp/out.json"])
    assert seen["spec"].findings_out == "/tmp/out.json"
    assert seen["spec"].feed is False

    args2 = _args(["scan", ".", "-f", "text"])
    cli_mod._run_tui_wrap(args2, ["scan", ".", "-f", "text"])
    assert seen["spec"].findings_out is None


# -- cmd_report ----------------------------------------------------------
def test_report_writes_file(tmp_path):
    findings = {"vulnerabilities": [
        {"type": "sqli", "severity": "critical", "location": "a.py",
         "line": 3, "description": "d", "cwe_id": "CWE-89"}]}
    f = tmp_path / "f.json"
    f.write_text(json.dumps(findings))
    out = tmp_path / "r.md"
    args = _args(["report", str(f), "-o", str(out), "--subject", "https://t"])
    rc = cmd_report(args)
    assert rc == 0
    md = out.read_text()
    assert "[CRITICAL] sqli" in md
    assert "**Subject:** `https://t`" in md


def test_report_missing_file_errors(tmp_path, capsys):
    args = _args(["report", str(tmp_path / "nope.json")])
    assert cmd_report(args) == 1
    assert "Error reading" in capsys.readouterr().err


def test_report_pipe_emits_markdown(tmp_path, monkeypatch, capsys):
    findings = [{"type": "xss", "severity": "high", "location": "w.py"}]
    f = tmp_path / "f.json"
    f.write_text(json.dumps(findings))
    monkeypatch.setattr(sys.stdout, "isatty", lambda: False)
    args = _args(["report", str(f)])
    assert cmd_report(args) == 0
    md = capsys.readouterr().out
    assert md.startswith("# Velora Security Report")
    assert "[HIGH] xss" in md


def test_report_trace_only(tmp_path, monkeypatch, capsys):
    trace = {"model": "m", "summary": {"target": "http://t", "solved": True,
                                       "steps": 2, "reason": "objective observed"}}
    t = tmp_path / "t.json"
    t.write_text(json.dumps(trace))
    monkeypatch.setattr(sys.stdout, "isatty", lambda: False)
    args = _args(["report", "--trace-out", str(t)])
    assert cmd_report(args) == 0
    out = capsys.readouterr().out
    assert "## Exploit run" in out and "✅ SOLVED" in out


def test_report_no_inputs_empty_markdown(monkeypatch, capsys):
    monkeypatch.setattr(sys.stdout, "isatty", lambda: False)
    args = _args(["report"])
    assert cmd_report(args) == 0
    assert capsys.readouterr().out.startswith("# Velora Security Report")
