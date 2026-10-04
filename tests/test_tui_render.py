"""Headless tests for the TUI render core (no curses needed)."""

from velora.tui.events import (
    FEED_CMD, FEED_OUT, FEED_REASONING, FINDING, RESULT, VERIFIED, Event,
)
from velora.tui.render import (
    PANES, TuiState, follow_offset, header_text, layout, pane_rows,
    pane_title, scroll_target, style_for_event, visible_rows, wrap_lines,
)


# -- wrap ---------------------------------------------------------------
def test_wrap_words_and_hard_split():
    assert wrap_lines("aa bb cc", 5) == ["aa bb", "cc"]
    assert wrap_lines("abcdefgh", 3) == ["abc", "def", "gh"]
    assert wrap_lines("a\n\nb", 10) == ["a", "", "b"]
    assert wrap_lines("", 10) == [""]
    assert wrap_lines("exact", 5) == ["exact"]


def test_pane_rows_keeps_style_per_entry():
    rows = pane_rows([("one two three", "cmd"), ("x", "out")], 7)
    assert rows == [("one two", "cmd"), ("three", "cmd"), ("x", "out")]


def test_visible_rows_clamps_offset():
    rows = [(str(i), "t") for i in range(10)]
    assert visible_rows(rows, 0, 3) == rows[0:3]
    assert visible_rows(rows, 99, 3) == rows[7:10]
    assert visible_rows(rows, -5, 3) == rows[0:3]
    assert visible_rows([], 0, 5) == []


# -- scroll -------------------------------------------------------------
def test_scroll_target_keys():
    assert scroll_target("up", 5, 100, 10) == 4
    assert scroll_target("down", 5, 100, 10) == 6
    assert scroll_target("pageup", 25, 100, 10) == 16   # page = h-1
    assert scroll_target("pagedown", 5, 100, 10) == 14
    assert scroll_target("home", 42, 100, 10) == 0
    assert scroll_target("end", 0, 100, 10) == 90       # clamped to total-h
    assert scroll_target("up", 0, 100, 10) == 0
    assert scroll_target("down", 95, 100, 10) == 90


def test_follow_offset():
    assert follow_offset(100, 20) == 80
    assert follow_offset(5, 20) == 0
    assert follow_offset(0, 20) == 0


# -- layout -------------------------------------------------------------
def test_layout_regions_tile_body():
    regions = layout(40, 120)
    assert regions["header"] == (0, 0, 1, 120)
    assert regions["footer"] == (39, 0, 1, 120)
    feed_y, feed_x, feed_h, feed_w = regions["feed"]
    prog = regions["progress"]
    find = regions["findings"]
    # right column stacks progress on findings
    assert prog[0] == feed_y and find[0] == prog[0] + prog[2]
    assert prog[2] + find[2] == feed_h
    assert prog[1] == find[1] == feed_w
    assert feed_x == 0 and feed_h == 38


def test_layout_narrow_stacks_vertically():
    regions = layout(40, 80)
    feed, prog, find = (regions["feed"], regions["progress"],
                        regions["findings"])
    assert feed[1] == prog[1] == find[1] == 0
    assert feed[0] + feed[2] + prog[2] == find[0]
    assert find[0] + find[2] == 39


def test_layout_tiny_terminal_keeps_header_and_feed():
    regions = layout(4, 30)
    assert regions["feed"][2] == 2
    assert "progress" not in regions and "findings" not in regions
    regions2 = layout(40, 15)
    assert regions2["feed"][2] == 38   # too narrow for column split


# -- header -------------------------------------------------------------
def test_header_running_and_findings():
    st = {"step": 3, "max_steps": 15, "elapsed": 62.0,
          "heartbeat": (30, 600), "model": "opencode/mimo", "child_alive": True}
    h = header_text("exploit", "https://t", st, 2, 200)
    assert "velora exploit" in h
    assert "step 3/15" in h
    assert "⏳ 30s/600s" in h
    assert "RUNNING" in h
    assert "2 findings" in h
    assert "mimo" in h


def test_header_done_and_truncation():
    st = {"step": 0, "max_steps": 0, "elapsed": 5.0, "heartbeat": None,
          "model": None, "child_alive": False, "returncode": 0}
    h = header_text("scan", "", st, 0, 200)
    assert "DONE" in h and "1 finding" not in h
    tiny = header_text("exploit", "https://example.com/x", st, 0, 12)
    assert len(tiny) <= 12


# -- styles -------------------------------------------------------------
def test_style_for_event():
    assert style_for_event(Event(FEED_CMD, "$ ls")) == "cmd"
    assert style_for_event(Event(FEED_OUT, "ok")) == "out"
    assert style_for_event(Event(FEED_REASONING, "thinking")) == "reason"
    assert style_for_event(Event(RESULT, "done", meta={"result": {}})) == "result"
    assert style_for_event(Event(VERIFIED, "VERIFIED: x")) == "verified"
    ev = Event(FINDING, "f", meta={"severity": "critical", "rank": 4})
    assert style_for_event(ev) == "critical"


# -- state --------------------------------------------------------------
def test_state_routes_events_and_tracks_step():
    st = TuiState(kind="exploit", subject="https://t")
    st.append(Event(FEED_CMD, "$ curl x"))
    st.append(Event(FEED_OUT, "200 OK"))
    st.append(Event("progress", "step 2/9", meta={"step": 2, "max": 9}))
    st.append(Event("progress", "hb", meta={"heartbeat": True, "elapsed": 30,
                                            "deadline": 600}))
    assert st.entries["feed"] == [("$ curl x", "cmd"), ("200 OK", "out")]
    assert st.status["step"] == 2 and st.status["max_steps"] == 9
    assert st.status["heartbeat"] == (30, 600)


def test_state_finding_events_dedicated_list_and_rows():
    st = TuiState(kind="scan")
    fev = Event(FINDING, "[CRITICAL] sql_injection  a.py:42",
                meta={"severity": "critical", "rank": 4,
                      "finding": {"type": "sql_injection"}})
    st.append(fev)
    assert st.finding_events == [fev]
    assert st.rows("findings", 80) == [("[CRITICAL] sql_injection  a.py:42",
                                        "critical")]
    st.append(Event(VERIFIED, "VERIFIED: solved"))
    assert len(st.rows("findings", 80)) == 2


def test_state_scroll_disables_then_reenables_follow():
    st = TuiState()
    for i in range(50):
        st.append(Event(FEED_OUT, f"line {i}"))
    st.anchor("feed", 50, 10)
    assert st.offset["feed"] == 40 and st.follow["feed"]
    st.focus = "feed"
    st.scroll("up", 10, 50)
    assert st.offset["feed"] == 39 and not st.follow["feed"]
    st.scroll("end", 10, 50)
    assert st.follow["feed"] is True


def test_state_ring_buffer_drops_oldest():
    from velora.tui.render import MAX_ROWS
    st = TuiState()
    for i in range(MAX_ROWS + 25):
        st.append(Event(FEED_OUT, f"l{i}"))
    assert len(st.entries["feed"]) == MAX_ROWS
    assert st.entries["feed"][0][0] == "l25"


def test_state_report_markdown_contains_findings_and_result():
    st = TuiState(kind="exploit", subject="https://t")
    st.append(Event(FINDING, "[HIGH] xss  web.py:9",
                    meta={"severity": "high", "rank": 3,
                          "finding": {"type": "xss", "severity": "high",
                                      "location": "web.py", "line": 9,
                                      "description": "d"}}))
    st.result = {"target": "https://t", "solved": True, "steps": 1,
                 "reason": "objective observed"}
    md = st.report_markdown(model="m")
    assert "# Velora Security Report" in md
    assert "[HIGH] xss" in md
    assert "✅ SOLVED" in md
    assert "**Subject:** `https://t`" in md


def test_pane_title_focus_and_follow():
    assert pane_title("feed", True, 0, False) == "[ feed ]"
    assert "(3)" in pane_title("findings", False, 3, False)
    assert "↓" in pane_title("feed", False, 0, True)
    assert list(PANES) == ["feed", "progress", "findings"]
