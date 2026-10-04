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


def build_report(findings: List[Dict[str, Any]],
                 trace: Optional[Dict[str, Any]] = None,
                 meta: Optional[Dict[str, Any]] = None) -> str:
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

    lines.append("---")
    lines.append("_Generated by [Velora](https://github.com/manojxshrestha/velora)._")
    lines.append("")
    return "\n".join(lines)


def default_report_name() -> str:
    return f"velora-report-{time.strftime('%Y%m%d-%H%M%S')}.md"
