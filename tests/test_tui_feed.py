"""Tests for the opencode session feed poller."""

import pytest

from velora.tui.events import (
    FEED_CMD, FEED_OUT, FEED_REASONING, FEED_TEXT, SYSTEM, sanitize,
)
from velora.tui.feed import SessionFeed, pick_session


def _sessions(*ids_updated):
    return [{"id": i, "time": {"updated": u}} for i, u in ids_updated]


def _msg(mid, *parts):
    return {"id": mid, "role": "assistant", "parts": list(parts)}


def _tool(pid, cmd, status="running", output=""):
    return {"id": pid, "type": "tool", "state": {
        "status": status, "input": {"command": cmd}, "output": output}}


def _reason(pid, text):
    return {"id": pid, "type": "reasoning", "text": text}


class FakeAPI:
    def __init__(self, sessions_by_tick, messages):
        self.sessions_by_tick = list(sessions_by_tick)
        self.messages = messages
        self.ticks = 0

    def sessions(self):
        idx = min(self.ticks, len(self.sessions_by_tick) - 1)
        self.ticks += 1
        return self.sessions_by_tick[idx]

    def msgs(self, sid):
        return self.messages.get(sid, [])


def test_pick_session_newest_wins():
    assert pick_session(_sessions(("a", 10), ("b", 30), ("c", 20))) == "b"
    assert pick_session([]) is None
    assert pick_session(["bare-id"]) == "bare-id"


def test_sanitize_strips_ansi_and_controls():
    assert sanitize("\x1b[31mred\x1b[0m") == "red"
    assert sanitize("a\x07b") == "ab"
    assert sanitize("line1\nline2") == "line1\nline2"
    assert sanitize("abcdef", limit=4) == "abc…"
    assert sanitize(None) == ""


def test_tool_running_then_completed_then_dedupe():
    api = FakeAPI(
        [_sessions(("s1", 5))],
        {"s1": [_msg("m1", _tool("t1", "curl http://x"),
                     _reason("r1", "probing now"))]},
    )
    feed = SessionFeed(fetch_sessions=api.sessions, fetch_messages=api.msgs)

    events = feed.poll_once()          # first sight of s1: no rotation noise
    kinds = [e.kind for e in events]
    assert FEED_CMD in kinds and FEED_REASONING in kinds
    cmd = next(e for e in events if e.kind == FEED_CMD)
    assert cmd.text.endswith("⏳")
    assert feed.poll_once() == []      # identical parts deduped

    # tool completes -> cmd + output emitted once
    api.messages["s1"] = [_msg("m1", _tool("t1", "curl http://x", "completed",
                                           "HTTP/2 200\nbody"))]
    events = feed.poll_once()
    assert [e.kind for e in events] == [FEED_CMD, FEED_OUT]
    assert "HTTP/2 200" in events[1].text
    assert feed.poll_once() == []


def test_session_rotation_and_waiting_events():
    api = FakeAPI(
        [_sessions(("s1", 5)), _sessions(("s1", 5)),
         _sessions(("s2", 9)), _sessions(("s2", 9)), []],
        {"s1": [], "s2": []},
    )
    feed = SessionFeed(fetch_sessions=api.sessions, fetch_messages=api.msgs)
    assert feed.poll_once() == []          # first session: silent start
    assert feed.poll_once() == []
    ev = feed.poll_once()                  # s1 -> s2
    assert len(ev) == 1 and ev[0].kind == SYSTEM and "rotated" in ev[0].text
    assert feed.poll_once() == []
    ev = feed.poll_once()                  # sessions gone -> waiting
    assert len(ev) == 1 and ev[0].kind == SYSTEM and "waiting" in ev[0].text
    assert feed.poll_once() == []          # waiting message emitted once


def test_fetch_error_is_transient_system_event():
    def boom():
        raise ConnectionError("down")
    feed = SessionFeed(fetch_sessions=boom, fetch_messages=lambda s: [])
    assert feed.poll_once() == []          # before any session: silent
    feed.had_session = True
    events = feed.poll_once()
    assert events and events[0].kind == SYSTEM
    assert "unreachable" in events[0].text


def test_text_part_emitted_once_and_sanitized():
    api = FakeAPI(
        [_sessions(("s1", 5))],
        {"s1": [_msg("m1", {"id": "x1", "type": "text",
                            "text": "found \x1b[32mgold\x1b[0m"})]},
    )
    feed = SessionFeed(fetch_sessions=api.sessions, fetch_messages=api.msgs)
    events = feed.poll_once()
    assert [e.kind for e in events] == [FEED_TEXT]
    assert events[0].text == "found gold"
    assert feed.poll_once() == []
