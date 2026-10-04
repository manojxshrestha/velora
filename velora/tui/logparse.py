"""Parses child-process output lines into TUI events.

The wrapper runs today's `velora exploit` / `velora scan` unchanged and pipes
their stdout+stderr through :class:`LineParser`, which recognizes:

* exploit step banners, heartbeat deadlines, transport retries
* ``[success-check]`` / ``VERIFIED:`` claims (promoted to FINDINGS pane)
* scan text-format vulnerability blocks and JSON result blobs
* the final exploit result (JSON or ``✓ EXPLOITED`` text verdict)
* model banner, errors/warnings (progress pane)

All patterns are pinned by tests against real output captured from live runs.
"""

from __future__ import annotations

import json
import re
from typing import Any, Dict, List, Optional

from velora.tui.events import (
    Event, FINDING, PROGRESS, RESULT, VERIFIED, event_from_finding,
)

_STEP_RE = re.compile(
    r"^\[(?P<label>[a-z-]+)\] step (?P<step>\d+)/(?P<max>\d+): thinking\.\.\."
    r"(?: \(deadline (?P<deadline>\d+)s/attempt, (?P<attempts>\d+) attempts\))?")
_HEARTBEAT_RE = re.compile(
    r"still waiting…\s*(?P<elapsed>\d+)s/(?P<deadline>\d+)s")
_RETRY_RE = re.compile(
    r"transport attempt (?P<n>\d+)/(?P<total>\d+) failed \((?P<err>[^)]*)\)")
_NO_RESPONSE_RE = re.compile(
    r"no response from the model -- (?P<what>retrying|giving up)")
_SUCCESS_RE = re.compile(r"^\[success-check\]\s*(?P<ev>.*)$")
_VERIFIED_RE = re.compile(r"VERIFIED\s*:\s*(?P<ev>\S.*)$")
_MODEL_RE = re.compile(r"^\[velora\] using model '(?P<model>[^']+)'")
_FINDING_START_RE = re.compile(
    r"^(?P<n>\d+)\.\s+\[(?P<sev>[A-Z]+)\]\s+\S+\s+(?P<type>\S.*)$")
_CONF_RE = re.compile(r"^(?P<p>\d+)%$")
_TEXT_VERDICT_RE = re.compile(
    r"^(?P<mark>[✓✗])\s+(?P<status>EXPLOITED|NOT EXPLOITED)\s+\(steps=(?P<steps>\d+), "
    r"reason=(?P<reason>[^,)]+)")
_LEVEL_RE = re.compile(r"^(?:Error|Warning|fatal)\b.*$", re.I)


class LineParser:
    """Stateful line -> events converter (JSON blob + text-block aware)."""

    def __init__(self, kind: str = "exploit"):
        self.kind = kind
        self._json_lines: Optional[List[str]] = None
        self._text_findings: List[Dict[str, Any]] = []
        self._current: Optional[Dict[str, Any]] = None
        self.result: Optional[Dict[str, Any]] = None

    # ------------------------------------------------------------------
    def feed(self, line: str) -> List[Event]:
        raw = line.rstrip("\n")
        if self._json_lines is not None:
            if not raw.strip():
                return []
            return self._feed_json(raw)
        if self._current is not None:
            # blank line or ==== footer closes the block -- checked before the
            # early empty-line return below, which would otherwise swallow it
            if not raw.strip() or raw.startswith("=" * 10):
                self._close_text_finding()
                return self._flush_text_findings()
            self._absorb_text_line(raw)
            return []
        if not raw.strip():
            return []
        if raw.lstrip().startswith("{"):
            self._json_lines = [raw]
            return self._try_json()
        return self._match_simple(raw)

    def finish(self) -> List[Event]:
        """Flush state after EOF (remaining text finding / JSON buffer)."""
        events: List[Event] = []
        if self._json_lines:
            joined = "\n".join(self._json_lines)
            try:
                data = json.loads(joined)
                events.extend(self._result_events(data))
            except Exception:
                pass
            self._json_lines = None
        self._close_text_finding()
        events.extend(self._flush_text_findings())
        return events

    # ------------------------------------------------------------------
    def _feed_json(self, raw: str) -> List[Event]:
        self._json_lines.append(raw)
        return self._try_json()

    def _try_json(self) -> List[Event]:
        joined = "\n".join(self._json_lines)
        try:
            data, _ = json.JSONDecoder().raw_decode(joined.lstrip())
        except Exception:
            if len(self._json_lines) > 50000:
                self._json_lines = None
            return []
        self._json_lines = None
        return self._result_events(data)

    def _result_events(self, data: Any) -> List[Event]:
        if isinstance(data, list):
            findings = data
            summary: Dict[str, Any] = {}
        elif isinstance(data, dict):
            findings = _flatten_findings(data)
            summary = data.get("summary") if isinstance(data.get("summary"), dict) else {}
            if isinstance(data.get("target"), str) or "solved" in data:
                summary = {**data, **summary}
        else:
            return []
        events: List[Event] = [Event(kind=RESULT, text=_result_line(summary),
                                     meta={"result": summary})]
        self.result = summary
        self._text_findings = findings
        events.extend(self._finding_events())
        self._text_findings = []
        return events

    # ------------------------------------------------------------------
    def _match_simple(self, raw: str) -> List[Event]:
        m = _STEP_RE.match(raw)
        if m:
            meta: Dict[str, Any] = {
                "step": int(m.group("step")), "max": int(m.group("max"))}
            if m.group("deadline"):
                meta["deadline"] = int(m.group("deadline"))
                meta["attempts"] = int(m.group("attempts") or 0)
            return [Event(kind=PROGRESS, text=raw, meta=meta)]
        m = _HEARTBEAT_RE.search(raw)
        if m:
            return [Event(kind=PROGRESS, text=raw, meta={
                "heartbeat": True,
                "elapsed": int(m.group("elapsed")),
                "deadline": int(m.group("deadline"))})]
        m = _RETRY_RE.search(raw)
        if m:
            return [Event(kind=PROGRESS, text=raw, meta={
                "retry": int(m.group("n")), "attempts": int(m.group("total")),
                "error": m.group("err")})]
        if _NO_RESPONSE_RE.search(raw):
            return [Event(kind=PROGRESS, text=raw, meta={
                "transport": _NO_RESPONSE_RE.search(raw).group("what")})]
        m = _SUCCESS_RE.match(raw)
        if m:
            return [Event(kind=VERIFIED, text=f"success-check: {m.group('ev')}",
                          meta={"oracle": True, "evidence": m.group("ev")})]
        m = _VERIFIED_RE.search(raw)
        if m and raw.startswith("["):
            return [Event(kind=VERIFIED, text=f"VERIFIED: {m.group('ev')}",
                          meta={"claim": True, "evidence": m.group("ev")})]
        m = _MODEL_RE.match(raw)
        if m:
            return [Event(kind=PROGRESS, text=raw,
                          meta={"model": m.group("model")})]
        m = _TEXT_VERDICT_RE.match(raw.strip())
        if m:
            summary = {
                "solved": m.group("mark") == "✓",
                "steps": int(m.group("steps")),
                "reason": m.group("reason").strip(),
            }
            self.result = summary
            return [Event(kind=RESULT, text=raw.strip(),
                          meta={"result": summary})]
        m = _FINDING_START_RE.match(raw)
        if m and self.kind == "scan":
            self._current = {
                "severity": m.group("sev").lower(),
                "type": m.group("type").strip(),
                "line": None, "location": None, "column": None,
            }
            return []
        if _LEVEL_RE.match(raw):
            level = "error" if raw.lower().startswith("error") else "warning"
            return [Event(kind=PROGRESS, text=raw, meta={"level": level})]
        if raw.startswith("[Scanner]") or raw.startswith("[LLM]") \
                or raw.startswith("[exploit]") or raw.startswith("[llm]"):
            return [Event(kind=PROGRESS, text=raw)]
        if raw.startswith("[velora]"):
            return [Event(kind=PROGRESS, text=raw)]
        return [Event(kind=PROGRESS, text=raw)]

    # -- text-format scan blocks ----------------------------------------
    def _absorb_text_line(self, raw: str) -> None:
        cur = self._current
        assert cur is not None
        s = raw.strip()
        if s.startswith("Location:"):
            parts = s[len("Location:"):].strip().split(":")
            cur["location"] = parts[0] if parts else s
            if len(parts) >= 2 and parts[1].isdigit():
                cur["line"] = int(parts[1])
            if len(parts) >= 3 and parts[2].isdigit():
                cur["column"] = int(parts[2])
        elif s.startswith("Function:"):
            cur["procedure"] = s[len("Function:"):].strip()
        elif s.startswith("Description:"):
            cur["description"] = s[len("Description:"):].strip()
        elif s.startswith("CWE:"):
            cur["cwe_id"] = s[len("CWE:"):].strip()
        elif s.startswith("Source:"):
            cur["source_var"] = s[len("Source:"):].strip()
        elif s.startswith("Data flow:"):
            flow = s[len("Data flow:"):].strip()
            cur["data_flow"] = [x.strip() for x in flow.split("→")]
        elif s.startswith("Exploit witness:"):
            cur["witness"] = s[len("Exploit witness:"):].strip()
        elif s.startswith("Confidence:"):
            cm = _CONF_RE.match(s[len("Confidence:"):].strip())
            if cm:
                cur["confidence"] = int(cm.group("p")) / 100.0

    def _close_text_finding(self) -> None:
        if self._current:
            cur = self._current
            cur.setdefault("location", "-")
            if cur.get("line") is None and isinstance(cur.get("location"), str):
                bits = cur["location"].rsplit(":", 1)
                if len(bits) == 2 and bits[1].isdigit():
                    cur["location"], cur["line"] = bits[0], int(bits[1])
            self._text_findings.append(cur)
            self._current = None

    def _finding_events(self) -> List[Event]:
        return [event_from_finding(f, provenance="scan")
                for f in self._text_findings]

    def _flush_text_findings(self) -> List[Event]:
        """Emit accumulated text findings now (live highlight) and clear."""
        if not self._text_findings:
            return []
        events = self._finding_events()
        self._text_findings = []
        return events


def _flatten_findings(data: Any) -> List[Dict[str, Any]]:
    if isinstance(data, list):
        return [f for f in data if isinstance(f, dict)]
    if isinstance(data, dict):
        if isinstance(data.get("vulnerabilities"), list):
            return [f for f in data["vulnerabilities"] if isinstance(f, dict)]
        if isinstance(data.get("files"), list):
            out: List[Dict[str, Any]] = []
            for f in data["files"]:
                if isinstance(f, dict) and isinstance(f.get("vulnerabilities"), list):
                    out.extend(x for x in f["vulnerabilities"] if isinstance(x, dict))
            return out
    return []


def _result_line(summary: Dict[str, Any]) -> str:
    if "solved" in summary:
        verdict = "SOLVED" if summary.get("solved") else "not solved"
        return (f"{verdict} -- steps={summary.get('steps')}, "
                f"reason={summary.get('reason')}")
    if "total_vulnerabilities" in summary or "critical" in summary:
        return (f"scan complete -- {summary.get('total_vulnerabilities', '?')} "
                f"findings (crit={summary.get('critical', '?')}, "
                f"high={summary.get('high', '?')})")
    return "result ready"
