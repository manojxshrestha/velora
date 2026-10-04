"""Live agent feed: polls the opencode session API behind the velora bridge.

The bridge creates one opencode session per model turn and deletes it when the
turn ends, so the poller always follows the *newest* session and surfaces
rotations as SYSTEM events. All text is sanitized before it becomes an Event.

Functions take injected ``fetch_sessions`` / ``fetch_messages`` callables so
tests run without a live bridge.
"""

from __future__ import annotations

import json
import time
import urllib.request
from typing import Any, Callable, Dict, Iterable, List, Optional, Set, Tuple

from velora.tui.events import (
    Event, FEED_CMD, FEED_OUT, FEED_REASONING, FEED_TEXT, SYSTEM, sanitize,
)

DEFAULT_POLL_S = 1.5
DEFAULT_OC_PORT = 4599
MAX_TEXT = 4000
MAX_OUT_LINES = 80

Fetch = Callable[[str], Any]


def bridge_oc_port() -> int:
    """opencode serve port from the bridge state file (fallback: default)."""
    try:
        from velora import bridge_cli
        state = bridge_cli._read_state() or {}
        return int(state.get("oc_port") or DEFAULT_OC_PORT)
    except Exception:
        return DEFAULT_OC_PORT


def _http_json(url: str, timeout: float = 5.0) -> Any:
    with urllib.request.urlopen(url, timeout=timeout) as resp:
        return json.loads(resp.read())


def make_fetchers(port: Optional[int] = None) -> Tuple[Fetch, Fetch]:
    base = f"http://127.0.0.1:{port if port is not None else bridge_oc_port()}"

    def fetch_sessions() -> Any:
        return _http_json(f"{base}/session")

    def fetch_messages(sid: str) -> Any:
        return _http_json(f"{base}/session/{sid}/message")

    return fetch_sessions, fetch_messages


def _session_id(entry: Any) -> str:
    if isinstance(entry, dict):
        return str(entry.get("id") or "")
    return str(entry)


def pick_session(sessions: Iterable[Any]) -> Optional[str]:
    """Newest session by time.updated (dicts with numeric updated, or bare ids)."""
    best_id = None
    best_ts = -1.0
    for entry in sessions or []:
        sid = _session_id(entry)
        if not sid:
            continue
        ts = 0.0
        if isinstance(entry, dict):
            ts = float((entry.get("time") or {}).get("updated") or 0)
        if ts >= best_ts:
            best_ts, best_id = ts, sid
    return best_id


class SessionFeed:
    """Polls the session API and converts parts to Events (deduped)."""

    def __init__(self,
                 fetch_sessions: Optional[Fetch] = None,
                 fetch_messages: Optional[Fetch] = None,
                 poll_s: float = DEFAULT_POLL_S,
                 clock: Callable[[], float] = time.time):
        if fetch_sessions is None or fetch_messages is None:
            d_s, d_m = make_fetchers()
            fetch_sessions = fetch_sessions or d_s
            fetch_messages = fetch_messages or d_m
        self.fetch_sessions = fetch_sessions
        self.fetch_messages = fetch_messages
        self.poll_s = poll_s
        self.clock = clock
        self.current_sid: Optional[str] = None
        self.had_session = False
        self._seen: Set[Tuple[str, str]] = set()
        self._seen_ids: Set[str] = set()
        self._waiting_emitted = False
        self.sessions_seen: List[str] = []

    # -- one poll tick ----------------------------------------------------
    def poll_once(self) -> List[Event]:
        try:
            sessions = self.fetch_sessions()
        except Exception as exc:
            return self._system(f"session API unreachable ({exc.__class__.__name__})",
                                transient=True)
        if not isinstance(sessions, list):
            sessions = []
        sid = pick_session(sessions)
        if sid is None:
            if self.had_session and not self._waiting_emitted:
                self._waiting_emitted = True
                self.current_sid = None
                return self._system("model turn ended -- waiting for the next one…")
            return []
        self._waiting_emitted = False
        rotation: List[Event] = []
        if sid != self.current_sid:
            first = not self.had_session
            self.current_sid = sid
            self.had_session = True
            self._seen.clear()
            self._seen_ids.clear()
            if sid not in self.sessions_seen:
                self.sessions_seen.append(sid)
            if not first:
                rotation = self._system(
                    f"session rotated (#{len(self.sessions_seen)}) -- new model turn")
        try:
            messages = self.fetch_messages(sid)
        except Exception as exc:
            return rotation + self._system(
                f"message fetch failed ({exc.__class__.__name__})", transient=True)
        events: List[Event] = list(rotation)
        for msg in messages if isinstance(messages, list) else []:
            if not isinstance(msg, dict):
                continue
            data = msg.get("data") if isinstance(msg.get("data"), dict) else msg
            for idx, part in enumerate(data.get("parts") or []):
                events.extend(self._part_events(part, data.get("id", ""), idx))
        return events

    def _system(self, text: str, transient: bool = False) -> List[Event]:
        if transient and self.current_sid is None and not self.had_session:
            return []
        return [Event(kind=SYSTEM, text=text, ts=self.clock())]

    # -- part conversion --------------------------------------------------
    def _part_events(self, part: Any, message_id: str, idx: int) -> List[Event]:
        if not isinstance(part, dict):
            return []
        pid = str(part.get("id") or f"{message_id}:{idx}")
        ptype = part.get("type")
        now = self.clock()
        if ptype == "tool":
            state = part.get("state") or {}
            status = str(state.get("status") or "running")
            key = (pid, status)
            if key in self._seen:
                return []
            self._seen.add(key)
            cmd = sanitize(str((state.get("input") or {}).get("command") or ""), 300)
            if not cmd:
                return []
            if status == "completed":
                out_raw = str(state.get("output") or "")
                lines = out_raw.splitlines()
                body = "\n".join(lines[:MAX_OUT_LINES])
                if len(lines) > MAX_OUT_LINES:
                    body += f"\n… ({len(lines) - MAX_OUT_LINES} more lines)"
                events = [Event(kind=FEED_CMD, text=f"$ {cmd}", ts=now,
                                meta={"status": status})]
                if body.strip():
                    events.append(Event(kind=FEED_OUT, text=sanitize(body, MAX_TEXT),
                                        ts=now, meta={"cmd": cmd}))
                return events
            if status == "error":
                return [Event(kind=FEED_OUT,
                              text=f"ERROR: {sanitize(str(state.get('output') or ''), 800)}",
                              ts=now, meta={"error": True})]
            return [Event(kind=FEED_CMD, text=f"$ {cmd}  ⏳", ts=now,
                          meta={"status": "running"})]
        if ptype in ("reasoning", "text"):
            if pid in self._seen_ids:
                return []
            text = sanitize(str(part.get("text") or ""), MAX_TEXT).strip()
            if not text:
                return []
            self._seen_ids.add(pid)
            kind = FEED_REASONING if ptype == "reasoning" else FEED_TEXT
            return [Event(kind=kind, text=text, ts=now, meta={"part": pid})]
        return []


def drain(feed: SessionFeed, ticks: int) -> List[Event]:
    """Run ``ticks`` poll cycles (test helper)."""
    out: List[Event] = []
    for _ in range(ticks):
        out.extend(feed.poll_once())
    return out
