"""Tests for the child-process runner (headless) -- real subprocesses, no network."""

import json
import sys
import time

from velora.tui.events import FINDING, PROGRESS, RESULT, VERIFIED
from velora.tui.runner import RunSpec, TuiRunner, child_argv


def _spec(code, kind="exploit", **kw):
    return RunSpec(argv=[sys.executable, "-c", code], kind=kind,
                   feed=False, **kw)


def test_child_argv_wraps_module_entry():
    argv = child_argv(["scan", ".", "--ai"])
    assert argv[1:3] == ["-m", "velora"]
    assert argv[3:] == ["scan", ".", "--ai"]


def test_headless_run_collects_events_and_result():
    payload = {"target": "http://x", "solved": True, "steps": 2,
               "reason": "objective observed"}
    code = (
        "import sys\n"
        "print('[exploit] step 1/2: thinking... (deadline 600s/attempt, 3 attempts)')\n"
        "sys.stdout.flush()\n"
        "print('[llm] · still waiting… 30s/600s (model turn in progress; times out at the deadline)')\n"
        f"print({json.dumps(json.dumps(payload, indent=2))})\n"
    )
    runner = TuiRunner(_spec(code))
    result = runner.run_to_completion(timeout=20)
    kinds = [e.kind for e in result.events]
    assert PROGRESS in kinds and RESULT in kinds
    assert result.result["solved"] is True
    assert result.returncode == 0
    st = runner.status()
    assert st["step"] == 1 and st["max_steps"] == 2
    assert st["heartbeat"] == (30, 600)


def test_headless_scan_text_findings_and_fail_exit():
    code = (
        "print('='*60)\n"
        "print('Velora Security Scan: app.py')\n"
        "print('='*60)\n"
        "print('')\n"
        "print('Vulnerabilities Found: 1')\n"
        "print('-'*40)\n"
        "print('')\n"
        "print('1. [HIGH] 🔴 command_injection')\n"
        "print('   Location: app.py:7:1')\n"
        "print('   Function: run')\n"
        "print('   Description: shell with user input')\n"
        "print('   Confidence: 80%')\n"
        "print('')\n"
        "raise SystemExit(1)\n"
    )
    runner = TuiRunner(_spec(code, kind="scan"))
    result = runner.run_to_completion(timeout=20)
    assert result.returncode == 1
    assert len(result.findings) == 1
    assert result.findings[0]["severity"] == "high"
    assert result.findings[0]["line"] == 7


def test_guidance_file_becomes_finding_events(tmp_path):
    guidance = tmp_path / "findings.json"
    guidance.write_text(json.dumps({"vulnerabilities": [
        {"type": "ssrf", "severity": "critical", "location": "api.py",
         "line": 3, "description": "url fetch"}]}))
    code = "print('hello')"
    runner = TuiRunner(_spec(code, guidance_path=str(guidance)))
    result = runner.run_to_completion(timeout=20)
    guide = [e for e in result.events if e.kind == FINDING
             and e.meta.get("provenance") == "guidance"]
    assert len(guide) == 1
    assert guide[0].meta["severity"] == "critical"


def test_findings_out_file_read_at_finalize(tmp_path):
    out = tmp_path / "findings.json"
    payload = {"vulnerabilities": [
        {"type": "xss", "severity": "medium", "location": "a.py",
         "line": 2, "description": "d"}]}
    code = (
        f"import pathlib; pathlib.Path({str(out)!r}).write_text"
        f"({json.dumps(json.dumps(payload))})\n"
    )
    runner = TuiRunner(_spec(code, kind="scan", findings_out=str(out)))
    result = runner.run_to_completion(timeout=20)
    assert len(result.findings) == 1
    assert result.findings[0]["type"] == "xss"


def test_trace_out_summary_used_for_result(tmp_path):
    trace = tmp_path / "evidence.json"
    payload = {"model": "m", "summary": {"target": "http://y", "solved": True,
                                         "steps": 4, "reason": "solved"},
               "transcript": ["..."]}
    code = (
        f"import pathlib; pathlib.Path({str(trace)!r}).write_text"
        f"({json.dumps(json.dumps(payload))})\nprint('done')\n"
    )
    runner = TuiRunner(_spec(code, trace_out=str(trace)))
    result = runner.run_to_completion(timeout=20)
    assert result.result["solved"] is True
    assert result.result["steps"] == 4
    assert result.trace["transcript"] == ["..."]


def test_stop_kills_long_running_child():
    code = "import time, signal, sys\nprint('started'); sys.stdout.flush()\ntime.sleep(30)\n"
    runner = TuiRunner(_spec(code))
    runner.start()
    deadline = time.time() + 5
    while not runner.drain() and time.time() < deadline:
        time.sleep(0.02)
    t0 = time.time()
    runner.stop()
    assert time.time() - t0 < 6
    assert runner.child_done()
    result = runner.finalize()
    assert result.returncode is not None


def test_success_check_and_verified_events_reach_queue():
    code = (
        "print('[success-check] flag{abc}')\n"
        "print('[exploit] · VERIFIED: POST /report -> 200')\n"
    )
    runner = TuiRunner(_spec(code))
    result = runner.run_to_completion(timeout=20)
    kinds = [e.kind for e in result.events]
    assert kinds.count(VERIFIED) == 2
