"""Tests for child-output line parsing -- fixtures are real output from live runs."""

import json

from velora.tui.events import FINDING, PROGRESS, RESULT, VERIFIED
from velora.tui.logparse import LineParser


def feed_all(parser, lines):
    out = []
    for ln in lines:
        out.extend(parser.feed(ln))
    return out


def test_step_banner_extracts_step_and_deadline():
    p = LineParser("exploit")
    ev = feed_all(p, ["[exploit] step 1/15: thinking... "
                      "(deadline 600s/attempt, 3 attempts)"])
    assert len(ev) == 1 and ev[0].kind == PROGRESS
    assert ev[0].meta == {"step": 1, "max": 15, "deadline": 600, "attempts": 3}


def test_heartbeat_extracts_elapsed_and_deadline():
    p = LineParser()
    ev = feed_all(p, ["[llm] · still waiting… 30s/1800s "
                      "(model turn in progress; times out at the deadline)"])
    assert ev[0].meta["heartbeat"] is True
    assert ev[0].meta["elapsed"] == 30
    assert ev[0].meta["deadline"] == 1800


def test_transport_retry_line():
    p = LineParser()
    ev = feed_all(p, ["[llm] transport attempt 1/3 failed (TimeoutError) -- retrying"])
    assert ev[0].meta == {"retry": 1, "attempts": 3, "error": "TimeoutError"}


def test_no_response_retry_and_giving_up():
    p = LineParser()
    ev = feed_all(p, ["[exploit] no response from the model -- retrying (attempt 2/3)",
                      "[exploit] no response from the model -- giving up"])
    assert ev[0].meta["transport"] == "retrying"
    assert ev[1].meta["transport"] == "giving up"


def test_success_check_becomes_verified_oracle_event():
    p = LineParser()
    ev = feed_all(p, ["[success-check] flag{pr4ct1ce_m4k3s_p3rf3ct}"])
    assert ev[0].kind == VERIFIED
    assert ev[0].meta["oracle"] is True
    assert "flag{" in ev[0].meta["evidence"]


def test_verified_claim_in_narration():
    p = LineParser()
    ev = feed_all(p, ["[exploit] · VERIFIED: `curl -X POST /report` → HTTP 200"])
    assert ev[0].kind == VERIFIED
    assert ev[0].meta["claim"] is True
    assert ev[0].text.startswith("VERIFIED: `curl")


def test_model_banner_sets_model():
    p = LineParser()
    ev = feed_all(p, ["[velora] using model 'opencode/mimo-v2.6-flash-free' from velora "
                      "config (/home/pwn/.config/velora/config.json) (VELORA_LLM_* env not set)"])
    assert ev[0].meta["model"] == "opencode/mimo-v2.6-flash-free"


def test_json_result_blob_multi_line():
    payload = {"target": "http://127.0.0.1:8080", "solved": True, "steps": 1,
               "reason": "objective observed", "guided": False, "provenance": None}
    p = LineParser()
    lines = ["[velora] using model 'm' from velora config (x) (env not set)"]
    lines += json.dumps(payload, indent=2).splitlines()
    ev = feed_all(p, lines)
    results = [e for e in ev if e.kind == RESULT]
    assert len(results) == 1
    assert results[0].meta["result"]["solved"] is True
    assert p.result["steps"] == 1


def test_text_verdict_line():
    p = LineParser()
    ev = feed_all(p, ["✓ EXPLOITED  (steps=3, reason=objective observed, guided=False)"])
    assert ev[0].kind == RESULT
    assert ev[0].meta["result"]["solved"] is True
    assert ev[0].meta["result"]["steps"] == 3
    p2 = LineParser()
    ev2 = feed_all(p2, ["✗ NOT EXPLOITED  (steps=15, reason=step budget exhausted, guided=True)"])
    assert ev2[0].meta["result"]["solved"] is False


def test_two_consecutive_text_finding_blocks():
    """Regression: blank line must close block 1 without swallowing block 2
    (real `velora scan examples/app.py` output has exactly this shape)."""
    lines = [
        "1. [CRITICAL] 🔴 sql_injection",
        "   Location: examples/app.py:20:4",
        "   Confidence: 80%",
        "",
        "2. [CRITICAL] 🔴 command_injection",
        "   Location: examples/app.py:27:4",
        "   Confidence: 80%",
        "",
        "=" * 60,
        "",
    ]
    p = LineParser("scan")
    ev = feed_all(p, lines) + p.finish()
    finds = [e.meta["finding"] for e in ev if e.kind == FINDING]
    assert len(finds) == 2
    assert finds[0]["type"] == "sql_injection" and finds[0]["line"] == 20
    assert finds[1]["type"] == "command_injection" and finds[1]["line"] == 27


def test_text_finding_emitted_live_at_block_close():
    """Live TUI highlight: the finding event fires when its block closes,
    not at EOF."""
    p = LineParser("scan")
    ev = feed_all(p, [
        "1. [HIGH] 🔴 xss",
        "   Location: web.py:9:1",
        "",
        "still more output after the finding",
    ])
    assert any(e.kind == FINDING for e in ev), "expected live finding event"
    assert p.finish() == []


def test_scan_text_finding_block():
    lines = [
        "============================================================",
        "Velora Security Scan: app.py",
        "============================================================",
        "",
        "Lines scanned: 120",
        "Vulnerabilities Found: 1",
        "----------------------------------------",
        "",
        "1. [CRITICAL] 🔴 sql_injection",
        "   Location: app.py:42:1",
        "   Function: login",
        "   Description: Unsanitized input reaches query",
        "   CWE: CWE-89",
        "   Source: user_input",
        "   Data flow: user_input → cursor.execute",
        "   Exploit witness: ' OR 1=1--",
        "   Confidence: 90%",
        "",
        "✅ No vulnerabilities found!",
        "",
        "============================================================",
        "",
    ]
    p = LineParser("scan")
    ev = feed_all(p, lines)
    ev += p.finish()
    finds = [e for e in ev if e.kind == FINDING]
    assert len(finds) == 1
    f = finds[0].meta["finding"]
    assert f["severity"] == "critical"
    assert f["type"] == "sql_injection"
    assert f["location"] == "app.py" and f["line"] == 42
    assert f["cwe_id"] == "CWE-89"
    assert f["confidence"] == 0.9
    assert f["witness"] == "' OR 1=1--"
    assert finds[0].meta["rank"] == 4


def test_scan_multifile_json_result():
    payload = {
        "files": [
            {"filename": "a.py", "vulnerabilities": [
                {"type": "xss", "severity": "high", "location": "a.py",
                 "line": 9, "description": "d"}]},
            {"filename": "b.py", "vulnerabilities": [
                {"type": "path_traversal", "severity": "medium",
                 "location": "b.py", "line": 3, "description": "d"}]},
        ],
        "summary": {"files_scanned": 2, "total_vulnerabilities": 2,
                    "critical": 0, "high": 1},
    }
    p = LineParser("scan")
    ev = feed_all(p, json.dumps(payload, indent=2).splitlines())
    finds = [e for e in ev if e.kind == FINDING]
    res = [e for e in ev if e.kind == RESULT]
    assert len(finds) == 2
    assert finds[0].meta["rank"] >= finds[1].meta["rank"]
    assert res and res[0].meta["result"]["total_vulnerabilities"] == 2


def test_generic_and_error_lines_stay_progress():
    p = LineParser()
    ev = feed_all(p, ["some random noise",
                      "Error: LLM layer unavailable -- scan aborted"])
    assert all(e.kind == PROGRESS for e in ev)
    assert ev[1].meta["level"] == "error"
