"""Shared event model for the velora TUI.

Every live thing the TUI displays -- child-process log lines, opencode session
activity, parsed findings, run results -- is normalized into an :class:`Event`
with a ``kind`` that determines which pane renders it.
"""

from __future__ import annotations

import re
import time
from dataclasses import dataclass, field
from typing import Any, Dict, Optional

# Panes ------------------------------------------------------------------
PANE_FEED = "feed"     # live agent activity (reasoning / commands / output)
PANE_PROGRESS = "progress"  # step banners, heartbeats, retries, results
PANE_FINDINGS = "findings"  # highlighted bugs / leads / verified events

# Event kinds ------------------------------------------------------------
FEED_REASONING = "feed_reasoning"
FEED_CMD = "feed_cmd"
FEED_OUT = "feed_out"
FEED_TEXT = "feed_text"
PROGRESS = "progress"
SYSTEM = "system"
FINDING = "finding"
VERIFIED = "verified"
RESULT = "result"

_PANE_BY_KIND: Dict[str, str] = {
    FEED_REASONING: PANE_FEED,
    FEED_CMD: PANE_FEED,
    FEED_OUT: PANE_FEED,
    FEED_TEXT: PANE_FEED,
    PROGRESS: PANE_PROGRESS,
    SYSTEM: PANE_PROGRESS,
    RESULT: PANE_PROGRESS,
    FINDING: PANE_FINDINGS,
    VERIFIED: PANE_FINDINGS,
}

SEVERITY_RANK: Dict[str, int] = {
    "critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0, "unknown": -1,
}


@dataclass
class Event:
    kind: str
    text: str
    ts: float = field(default_factory=time.time)
    meta: Dict[str, Any] = field(default_factory=dict)

    @property
    def pane(self) -> str:
        return _PANE_BY_KIND.get(self.kind, PANE_PROGRESS)


_ANSI_RE = re.compile(r"\x1b\[[0-9;?]*[A-Za-z]|\x1b\][^\x07\x1b]*(\x07|\x1b\\)|\r")
_CONTROL_RE = re.compile(r"[\x00-\x08\x0b-\x1f\x7f]")


def sanitize(text: str, limit: int = 0) -> str:
    """Strip ANSI escapes/control chars; optionally hard-truncate."""
    out = _ANSI_RE.sub("", text or "")
    out = _CONTROL_RE.sub("", out)
    if limit and len(out) > limit:
        out = out[: max(0, limit - 1)] + "…"
    return out


def severity_of(finding: Dict[str, Any]) -> str:
    return str(finding.get("severity") or "unknown").strip().lower()


def severity_rank(finding: Dict[str, Any]) -> int:
    return SEVERITY_RANK.get(severity_of(finding), -1)


def finding_title(finding: Dict[str, Any]) -> str:
    sev = severity_of(finding).upper()
    ftype = finding.get("type") or finding.get("title") or "finding"
    return f"[{sev}] {ftype}"


def finding_location(finding: Dict[str, Any]) -> str:
    loc = str(finding.get("location") or "")
    line = finding.get("line")
    return f"{loc}:{line}" if loc and line is not None else (loc or "-")


def event_from_finding(finding: Dict[str, Any], provenance: str = "",
                       ts: Optional[float] = None) -> Event:
    """Normalize any finding dict (scan JSON / guidance lead) to a FINDING event."""
    meta = {
        "finding": finding,
        "severity": severity_of(finding),
        "rank": severity_rank(finding),
        "provenance": provenance,
        "location": finding_location(finding),
        "cwe": finding.get("cwe_id") or finding.get("cwe") or "",
        "fresh": True,
    }
    return Event(
        kind=FINDING,
        text=f"{finding_title(finding)}  {meta['location']}",
        ts=ts if ts is not None else time.time(),
        meta=meta,
    )
