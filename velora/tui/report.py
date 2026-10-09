"""Markdown report builder: findings JSON + optional exploit trace -> one report.

Pure functions (no I/O except the small loaders) so the TUI preview, `s`ave,
and the `velora report` subcommand all render from the same bytes.
"""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

from velora.tui.events import SEVERITY_RANK, severity_of, severity_rank

_SEV_ORDER = ["critical", "high", "medium", "low", "info", "unknown"]


def flatten_findings(data: Any) -> List[Dict[str, Any]]:
    """Accepts a bare list, one file's dict, or multi-file `{"files": [...]}`."""
    if isinstance(data, list):
        return [f for f in data if isinstance(f, dict)]
    if isinstance(data, dict):
        if isinstance(data.get("vulnerabilities"), list):
            out = [f for f in data["vulnerabilities"] if isinstance(f, dict)]
            fname = data.get("filename")
            if fname and not any(f.get("location") for f in out):
                for f in out:
                    f.setdefault("location", fname)
            return out
        if isinstance(data.get("files"), list):
            out = []
            for f in data["files"]:
                if isinstance(f, dict):
                    out.extend(flatten_findings(f))
            return out
        if "leads" in data and isinstance(data["leads"], list):
            return [f for f in data["leads"] if isinstance(f, dict)]
    return []


def load_findings(path: str) -> List[Dict[str, Any]]:
    return flatten_findings(json.loads(Path(path).read_text()))


def load_trace(path: str) -> Dict[str, Any]:
    """Exploit trace-out file: {"model": ..., "summary": {...}, "transcript": ...}."""
    try:
        data = json.loads(Path(path).read_text())
    except Exception:
        return {}
    if isinstance(data, dict) and isinstance(data.get("summary"), dict):
        return data
    if isinstance(data, dict):
        return {"summary": data}
    return {}


def sort_findings(findings: Iterable[Dict[str, Any]]) -> List[Dict[str, Any]]:
    return sorted(findings, key=lambda f: (-severity_rank(f),
                                            str(f.get("type") or "")))


def _loc(f: Dict[str, Any]) -> str:
    loc = str(f.get("location") or "-")
    line = f.get("line")
    return f"{loc}:{line}" if line is not None else loc


def _counts(findings: List[Dict[str, Any]]) -> Dict[str, int]:
    counts = {s: 0 for s in _SEV_ORDER}
    for f in findings:
        s = severity_of(f)
        counts[s if s in counts else "unknown"] += 1
    return counts


TIMELINE_MAX = 100


def timeline_lines(evidence: Optional[List[Dict[str, Any]]] = None,
                   trace: Optional[Dict[str, Any]] = None) -> List[str]:
    """Human-readable action timeline (report appendix) from evidence{}+trace.

    Derived: ordered request rows from the CAPTURE evidence trail plus the
    exploit agent's recorded turn count from trace.json. Empty list when
    neither exists (e.g. source-only whitebox runs).
    """
    entries = [e for e in (evidence or []) if isinstance(e, dict)]
    transcript = (trace or {}).get("transcript") or []
    if not entries and not transcript:
        return []
    lines: List[str] = ["## Action timeline", ""]
    for i, e in enumerate(entries[:TIMELINE_MAX], 1):
        method = str(e.get("method") or "?")
        url = str(e.get("url") or "")
        row = f"{i}. `{method} {url}`"
        final = e.get("final_url")
        if final and final != url:
            row += f" -> `{final}`"
        status = e.get("status")
        if status is not None:
            row += f" -> {status}"
        ms = e.get("elapsed_ms")
        if ms is not None:
            row += f" · {ms}ms"
        if e.get("error"):
            row += f" · error: {e['error']}"
        lines.append(row)
    if len(entries) > TIMELINE_MAX:
        lines.append(
            f"... +{len(entries) - TIMELINE_MAX} earlier requests "
            "(see evidence.json)"
        )
    if transcript:
        lines.append("")
        lines.append(
            f"Exploit agent: {len(transcript)} recorded turn(s) (trace.json)."
        )
    lines.append("")
    return lines


def build_report(findings: List[Dict[str, Any]],
                 trace: Optional[Dict[str, Any]] = None,
                 meta: Optional[Dict[str, Any]] = None,
                 evidence: Optional[List[Dict[str, Any]]] = None) -> str:
    """Assemble the markdown report."""
    meta = meta or {}
    findings = sort_findings(findings)
    counts = _counts(findings)
    lines: List[str] = []
    title = meta.get("title") or "Velora Security Report"
    lines.append(f"# {title}")
    lines.append("")
    lines.append(f"- **Generated:** {time.strftime('%Y-%m-%d %H:%M:%S')}")
    if meta.get("subject"):
        lines.append(f"- **Subject:** `{meta['subject']}`")
    if meta.get("model"):
        lines.append(f"- **Model:** {meta['model']}")
    lines.append("")

    lines.append("## Summary")
    lines.append("")
    total = len(findings)
    lines.append(f"| Severity | Count |")
    lines.append(f"|---|---:|")
    for sev in _SEV_ORDER:
        if sev == "unknown" and not counts[sev]:
            continue
        lines.append(f"| {sev.upper()} | {counts[sev]} |")
    lines.append(f"| **TOTAL** | **{total}** |")
    lines.append("")

    if trace:
        summary = trace.get("summary") or {}
        lines.append("## Exploit run")
        lines.append("")
        if summary.get("target"):
            lines.append(f"- **Target:** `{summary['target']}`")
        if "solved" in summary:
            verdict = "✅ SOLVED" if summary.get("solved") else "❌ not solved"
            lines.append(f"- **Result:** {verdict} "
                         f"(steps={summary.get('steps')}, reason={summary.get('reason')})")
        if trace.get("model"):
            lines.append(f"- **Model:** {trace['model']}")
        lines.append("")

    if findings:
        lines.append("## Findings")
        lines.append("")
        for i, f in enumerate(findings, 1):
            sev = severity_of(f).upper()
            ftype = f.get("type") or f.get("title") or "finding"
            lines.append(f"### {i}. [{sev}] {ftype}")
            lines.append("")
            lines.append(f"- **Location:** `{_loc(f)}`")
            if f.get("procedure"):
                lines.append(f"- **Procedure:** `{f['procedure']}`")
            if f.get("cwe_id") or f.get("cwe"):
                lines.append(f"- **CWE:** {f.get('cwe_id') or f.get('cwe')}")
            if f.get("confidence") is not None and f.get("confidence") != "":
                try:
                    conf = float(f["confidence"])
                    if conf <= 1.0:
                        conf *= 100
                    lines.append(f"- **Confidence:** {conf:.0f}%")
                except (TypeError, ValueError):
                    pass
            if f.get("sink_type"):
                lines.append(f"- **Sink:** {f['sink_type']}")
            if f.get("source_var"):
                lines.append(f"- **Source:** `{f['source_var']}`")
            if f.get("data_flow"):
                flow = " → ".join(str(x) for x in f["data_flow"])
                lines.append(f"- **Data flow:** {flow}")
            if f.get("description"):
                lines.append("")
                lines.append(str(f["description"]))
            if f.get("witness"):
                lines.append("")
                lines.append("**Witness / evidence:**")
                lines.append("")
                lines.append("```")
                lines.append(str(f["witness"]).rstrip())
                lines.append("```")
            lines.append("")
    else:
        lines.append("## Findings")
        lines.append("")
        lines.append("_No findings._")
        lines.append("")

    lines.extend(timeline_lines(evidence, trace))

    lines.append("---")
    lines.append("_Generated by [Velora](https://github.com/manojxshrestha/velora)._")
    lines.append("")
    return "\n".join(lines)


def default_report_name() -> str:
    return f"velora-report-{time.strftime('%Y%m%d-%H%M%S')}.md"


# ---------------------------------------------------------------------------
# Findings-only renderers (mode reports without scan artifacts, §7.1/§7.4)
# ---------------------------------------------------------------------------

_SARIF_LEVEL = {
    "critical": "error", "high": "error", "medium": "warning",
    "low": "note", "info": "note",
}


def render_findings_json(findings: List[Dict[str, Any]], *, mode: str = "") -> str:
    """JSON rendering of raw finding dicts (blackbox/bughunt evidence findings)."""
    payload: Dict[str, Any] = {"count": len(findings), "findings": findings}
    if mode:
        payload["mode"] = mode
    return json.dumps(payload, indent=2, default=str)


def render_findings_sarif(findings: List[Dict[str, Any]], *, mode: str = "") -> str:
    """Minimal SARIF 2.1 rendering with §7.1 provenance/asset properties."""
    rules: Dict[str, Dict[str, Any]] = {}
    results: List[Dict[str, Any]] = []
    for finding in findings:
        ftype = str(finding.get("type") or "finding")
        rule_id = f"velora/{ftype}"
        severity = str(finding.get("severity") or "low")
        level = _SARIF_LEVEL.get(severity, "warning")
        if rule_id not in rules:
            rules[rule_id] = {
                "id": rule_id,
                "name": ftype.replace("_", " ").title(),
                "shortDescription": {
                    "text": str(finding.get("title") or ftype)
                },
                "defaultConfiguration": {"level": level},
            }
        line = finding.get("line") or 1
        region: Dict[str, Any] = {"startLine": line}
        if finding.get("line"):
            region["endLine"] = line
        properties: Dict[str, Any] = {
            "severity": finding.get("severity"),
            "confidence": finding.get("confidence"),
            "cwe": finding.get("cwe_id") or finding.get("cwe"),
        }
        for key in ("provenance", "mode", "asset", "reproduced", "detector"):
            if finding.get(key) is not None:
                properties[key] = finding.get(key)
        if mode and "mode" not in properties:
            properties["mode"] = mode
        results.append({
            "ruleId": rule_id,
            "level": level,
            "message": {"text": str(
                finding.get("description") or finding.get("title") or ftype
            )},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {
                        "uri": str(
                            finding.get("path") or finding.get("location") or "unknown"
                        )
                    },
                    "region": region,
                }
            }],
            "properties": properties,
        })
    payload: Dict[str, Any] = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {
                "name": "Velora Security Scanner",
                "rules": list(rules.values()),
            }},
            "results": results,
        }],
    }
    if mode:
        payload["runs"][0]["properties"] = {"mode": mode}
    return json.dumps(payload, indent=2, default=str)


def _poc_steps(finding: Dict[str, Any]) -> List[str]:
    """Turn evidence.request (raw HTTP) into numbered reproduction steps."""
    evidence = finding.get("evidence") or {}
    request = evidence.get("request") or finding.get("request") or ""
    steps: List[str] = []
    if isinstance(request, str) and request.strip():
        lines = [ln.rstrip() for ln in request.strip().splitlines() if ln.strip()]
        if lines:
            request_line = lines[0].strip()
            steps.append(f"Send `{request_line}`.")
            headers = [
                ln.strip() for ln in lines[1:]
                if ln.strip() and not ln.startswith("{") and not ln.startswith("[")
            ]
            if headers:
                steps.append(
                    "With headers: "
                    + ", ".join(f"`{h.split(':', 1)[0].strip()}`" for h in headers[:6])
                    + "."
                )
            params = finding.get("parameter")
            if params:
                steps.append(
                    f"Deliver the payload through parameter `{params}`."
                )
            expect = evidence.get("response") or evidence.get("note") or ""
            if isinstance(expect, str) and expect.strip():
                snippet = expect.strip().splitlines()[0][:200]
                steps.append(f"Expect: {snippet}")
            else:
                steps.append(
                    "Expect the response to reflect or disclose the injected/"
                    "flagged content (reproduced >= 2 independent probes)."
                )
    witness = finding.get("witness")
    if witness and not steps:
        steps.append(str(witness).strip().splitlines()[0][:300])
    if not steps and finding.get("description"):
        steps.append(str(finding["description"]).strip().splitlines()[0][:300])
    return steps


def build_bounty_report(findings: List[Dict[str, Any]],
                        ledger: Optional[Dict[str, Any]] = None,
                        meta: Optional[Dict[str, Any]] = None,
                        evidence: Optional[List[Dict[str, Any]]] = None) -> str:
    """Bug-bounty submission draft: title, class, impact, PoC, evidence."""
    meta = meta or {}
    findings = sort_findings(findings)
    counts = _counts(findings)
    lines: List[str] = []
    title = meta.get("title") or "Velora Bug Bounty Submission Draft"
    lines.append(f"# {title}")
    lines.append("")
    lines.append(f"- **Generated:** {time.strftime('%Y-%m-%d %H:%M:%S')}")
    if meta.get("subject"):
        lines.append(f"- **Subject:** `{meta['subject']}`")
    loop = meta.get("loop") or {}
    if loop:
        reason = loop.get("reason") or "unknown"
        lines.append(
            f"- **Loop:** {loop.get('iterations', 0)} iteration(s), "
            f"terminated by `{reason}`"
        )
    lines.append("")

    lines.append("## Summary")
    lines.append("")
    lines.append("| Severity | Count |")
    lines.append("|---|---:|")
    for sev in _SEV_ORDER:
        if sev == "unknown" and not counts[sev]:
            continue
        lines.append(f"| {sev.upper()} | {counts[sev]} |")
    lines.append(f"| **TOTAL** | **{len(findings)}** |")
    lines.append("")

    if ledger:
        lc = ledger.get("counts") or {}
        lines.append("## Hypothesis ledger")
        lines.append("")
        lines.append(
            f"- open: {lc.get('open', 0)} · proven: {lc.get('proven', 0)} "
            f"· eliminated: {lc.get('eliminated', 0)}"
        )
        lines.append("")

    if findings:
        lines.append("## Findings")
        lines.append("")
        for i, f in enumerate(findings, 1):
            sev = severity_of(f).upper()
            ftype = f.get("type") or f.get("title") or "finding"
            lines.append(f"### {i}. [{sev}] {ftype}")
            lines.append("")
            cwe_text = str(f.get("cwe_id") or f.get("cwe") or "").strip()
            if cwe_text:
                if not cwe_text.upper().startswith("CWE"):
                    cwe_text = f"CWE-{cwe_text}"
                lines.append(f"- **Class:** `{ftype}` · {cwe_text}")
            else:
                lines.append(f"- **Class:** `{ftype}`")
            lines.append(f"- **Endpoint:** `{_loc(f)}`")
            if f.get("parameter"):
                lines.append(f"- **Parameter:** `{f['parameter']}`")
            if f.get("asset"):
                lines.append(f"- **Asset:** `{f['asset']}`")
            description = str(f.get("description") or "").strip()
            if description:
                lines.append("")
                lines.append("**Impact**")
                lines.append("")
                lines.append(description)
            steps = _poc_steps(f)
            if steps:
                lines.append("")
                lines.append("**Proof of concept**")
                lines.append("")
                for step_no, step in enumerate(steps, 1):
                    lines.append(f"{step_no}. {step}")
            evidence_bits: List[str] = []
            ev = f.get("evidence") or {}
            if ev.get("kind"):
                evidence_bits.append(f"kind=`{ev['kind']}`")
            if ev.get("reproduced") is not None:
                evidence_bits.append(f"reproduced `{ev['reproduced']}`x")
            if f.get("provenance"):
                evidence_bits.append(f"provenance=`{f['provenance']}`")
            if f.get("detector"):
                evidence_bits.append(f"detector=`{f['detector']}`")
            if evidence_bits:
                lines.append("")
                lines.append("**Evidence:** " + " · ".join(evidence_bits))
            lines.append("")
    else:
        lines.append("## Findings")
        lines.append("")
        lines.append("_No findings._")
        lines.append("")

    lines.extend(timeline_lines(evidence, trace=None))

    lines.append("---")
    lines.append("_Generated by [Velora](https://github.com/manojxshrestha/velora)._")
    lines.append("")
    return "\n".join(lines)
