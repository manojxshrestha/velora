"""Tests for the markdown report builder."""

import json

from velora.tui.report import (
    build_report, default_report_name, flatten_findings, sort_findings,
)

CRIT = {"type": "sql_injection", "severity": "critical", "location": "app.py",
        "line": 42, "description": "Unsanitized input reaches query",
        "procedure": "login", "cwe_id": "CWE-89", "confidence": 0.9,
        "witness": "' OR 1=1--", "source_var": "user_input",
        "data_flow": ["user_input", "cursor.execute"]}
HIGH = {"type": "xss", "severity": "high", "location": "web.py",
        "line": 9, "description": "Reflected input"}
LOW = {"type": "info_leak", "severity": "low", "location": "util.py",
       "line": 1, "description": "verbose errors"}


def test_flatten_variants():
    assert flatten_findings([CRIT]) == [CRIT]
    one = {"filename": "a.py", "vulnerabilities": [HIGH]}
    got = flatten_findings(one)
    assert got == [HIGH]
    multi = {"files": [{"vulnerabilities": [CRIT]}, {"vulnerabilities": [LOW]}]}
    assert len(flatten_findings(multi)) == 2
    assert flatten_findings({"leads": [HIGH]}) == [HIGH]
    assert flatten_findings({"weird": 1}) == []


def test_sort_by_severity_then_type():
    order = [f["severity"] for f in sort_findings([LOW, HIGH, CRIT])]
    assert order == ["critical", "high", "low"]


def test_build_report_sections_and_order():
    md = build_report([LOW, CRIT, HIGH], meta={"subject": "https://target.com",
                                               "model": "m"})
    assert md.startswith("# Velora Security Report")
    assert "**Subject:** `https://target.com`" in md
    assert "**Model:** m" in md
    assert "| CRITICAL | 1 |" in md
    assert "| **TOTAL** | **3** |" in md
    # findings sorted: critical first, numbered
    i_crit = md.index("### 1. [CRITICAL]")
    i_high = md.index("### 2. [HIGH]")
    i_low = md.index("### 3. [LOW]")
    assert i_crit < i_high < i_low
    assert "**Location:** `app.py:42`" in md
    assert "**CWE:** CWE-89" in md
    assert "**Confidence:** 90%" in md
    assert "**Data flow:** user_input → cursor.execute" in md
    assert "```\n' OR 1=1--\n```" in md


def test_build_report_exploit_section():
    trace = {"model": "mimo", "summary": {
        "target": "http://127.0.0.1:8080", "solved": True, "steps": 1,
        "reason": "objective observed"}}
    md = build_report([], trace=trace)
    assert "## Exploit run" in md
    assert "✅ SOLVED" in md
    assert "http://127.0.0.1:8080" in md
    assert "_No findings._" in md


def test_build_report_unsolved_and_unknown_severity():
    trace = {"summary": {"target": "x", "solved": False, "steps": 15,
                         "reason": "step budget exhausted"}}
    md = build_report([{"type": "m", "severity": "weird", "location": "f"}],
                      trace=trace)
    assert "❌ not solved" in md
    assert "[WEIRD]" in md


def test_default_report_name_shape():
    name = default_report_name()
    assert name.startswith("velora-report-") and name.endswith(".md")
