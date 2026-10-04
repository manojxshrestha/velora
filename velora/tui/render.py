"""Curses renderer for the velora live TUI.

Split into a pure, headless-testable core (wrapping, layout, scroll math,
state accumulation) and a thin curses shell (:func:`run_tui`) that drains the
:class:`~velora.tui.runner.TuiRunner` queue and paints panes.

Panes
-----
``feed``       live agent activity (commands, output, reasoning)
``progress``   step banners, heartbeats, retries, verdicts, system lines
``findings``   highlighted bugs (severity colored), VERIFIED claims

Keys: ``Tab`` focus, ``j/k/arrows/PgUp/PgDn/g/G`` scroll, ``f`` follow,
``r`` report overlay (``s`` saves), ``q`` quit (confirm while child alive).
"""

from __future__ import annotations

import time
from typing import Any, Dict, List, Optional, Tuple

from velora.tui.events import (
    FEED_CMD, FEED_OUT, FEED_REASONING, FEED_TEXT, FINDING, PROGRESS, RESULT,
    SYSTEM, VERIFIED, Event, severity_rank,
)
from velora.tui.report import build_report, default_report_name

Row = Tuple[str, str]                     # (text, style)
Region = Tuple[int, int, int, int]        # (y, x, h, w)

PANES = ("feed", "progress", "findings")
MAX_ROWS = 5000                           # per-pane ring bound


# -- pure: text ---------------------------------------------------------
def wrap_lines(text: str, width: int) -> List[str]:
    """Word-wrap ``text`` to ``width`` columns (hard-split overlong tokens)."""
    width = max(1, width)
    out: List[str] = []
    for raw in (text or "").split("\n"):
        if not raw:
            out.append("")
            continue
        line = ""
        for word in raw.split(" "):
            if not line:
                piece = word
            else:
                piece = f"{line} {word}"
            if len(piece) <= width:
                line = piece
                continue
            if line:
                out.append(line)
            # token longer than width: hard split
            while len(word) > width:
                out.append(word[:width])
                word = word[width:]
            line = word
        out.append(line)
    return out or [""]


def pane_rows(entries: List[Row], width: int) -> List[Row]:
    """Expand logical entries into display rows, wrapped to ``width``."""
    rows: List[Row] = []
    for text, style in entries:
        for ln in wrap_lines(text, width):
            rows.append((ln, style))
    return rows


def visible_rows(rows: List[Row], offset: int, height: int) -> List[Row]:
    offset = max(0, min(offset, max(0, len(rows) - max(1, height))))
    return rows[offset:offset + max(0, height)]


def scroll_target(key: str, offset: int, total: int, height: int) -> int:
    """Map a scroll key to a new row offset (pure; no curses constants)."""
    height = max(1, height)
    page = max(1, height - 1)
    if key == "up":
        offset -= 1
    elif key == "down":
        offset += 1
    elif key == "pageup":
        offset -= page
    elif key == "pagedown":
        offset += page
    elif key == "home":
        offset = 0
    elif key == "end":
        offset = total
    return max(0, min(offset, max(0, total - height)))


def follow_offset(total: int, height: int) -> int:
    return max(0, total - max(1, height))


# -- pure: layout -------------------------------------------------------
def layout(height: int, width: int) -> Dict[str, Region]:
    """Region map for header/footer + the three panes. Degrades gracefully."""
    regions: Dict[str, Region] = {}
    regions["header"] = (0, 0, 1, width)
    regions["footer"] = (max(0, height - 1), 0, 1, width)
    body_y, body_h = 1, max(1, height - 2)
    if body_h < 3 or width < 20:
        regions["feed"] = (body_y, 0, body_h, width)
        return regions
    if width >= 100:
        feed_w = max(40, width * 2 // 3)
        right_x, right_w = feed_w, width - feed_w
        prog_h = max(3, body_h // 3)
        regions["feed"] = (body_y, 0, body_h, feed_w)
        regions["progress"] = (body_y, right_x, prog_h, right_w)
        regions["findings"] = (body_y + prog_h, right_x,
                               body_h - prog_h, right_w)
    else:
        find_h = max(3, body_h * 3 // 10)
        prog_h = max(2, body_h * 2 // 10)
        feed_h = body_h - find_h - prog_h
        regions["feed"] = (body_y, 0, feed_h, width)
        regions["progress"] = (body_y + feed_h, 0, prog_h, width)
        regions["findings"] = (body_y + feed_h + prog_h, 0, find_h, width)
    return regions


def header_text(kind: str, subject: str, st: Dict[str, Any],
                n_findings: int, width: int) -> str:
    parts = [f"velora {kind}"]
    if subject:
        parts.append(subject)
    if st.get("step"):
        mx = st.get("max_steps") or "?"
        parts.append(f"step {st['step']}/{mx}")
    parts.append(f"{int(st.get('elapsed') or 0)}s")
    hb = st.get("heartbeat")
    if hb and hb[0] is not None:
        parts.append(f"⏳ {hb[0]}s/{hb[1] or '?'}s")
    if st.get("model"):
        parts.append(str(st["model"]).split("/")[-1])
    if st.get("child_alive"):
        parts.append("RUNNING")
    else:
        rc = st.get("returncode")
        parts.append("DONE" if rc == 0 else f"EXIT {rc}")
    if n_findings:
        parts.append(f"{n_findings} finding{'s' if n_findings != 1 else ''}")
    line = " │ ".join(parts)
    return line if len(line) <= width else line[:max(1, width - 1)] + "…"


def pane_title(name: str, focused: bool, count: int = 0,
               follow: bool = False) -> str:
    label = f" {name} "
    if count:
        label += f"({count}) "
    if follow:
        label += "↓ "
    return f"[{label}]" if focused else label


def style_for_event(ev: Event) -> str:
    if ev.kind == FEED_CMD:
        return "cmd"
    if ev.kind == FEED_OUT:
        return "out"
    if ev.kind == FEED_REASONING:
        return "reason"
    if ev.kind == FEED_TEXT:
        return "text"
    if ev.kind == SYSTEM:
        return "system"
    if ev.kind == RESULT:
        return "result"
    if ev.kind == VERIFIED:
        return "verified"
    if ev.kind == FINDING:
        return str(ev.meta.get("severity") or "unknown")
    return "progress"


# -- state --------------------------------------------------------------
class TuiState:
    """Accumulates events into pane entries + tracks scroll/focus/status."""

    def __init__(self, kind: str = "exploit", subject: str = ""):
        self.kind = kind
        self.subject = subject
        self.entries: Dict[str, List[Row]] = {p: [] for p in PANES}
        self.finding_events: List[Event] = []
        self.status: Dict[str, Any] = {
            "step": 0, "max_steps": 0, "heartbeat": None, "model": None,
            "child_alive": False, "returncode": None, "elapsed": 0.0,
        }
        self.result: Optional[Dict[str, Any]] = None
        self.offset: Dict[str, int] = {p: 0 for p in PANES}
        self.follow: Dict[str, bool] = {p: True for p in PANES}
        self.focus: str = "feed"
        self.confirm_quit = False
        self._quit = False
        self._report = False

    # -- event routing ---------------------------------------------------
    def append(self, ev: Event) -> None:
        m = ev.meta or {}
        if "step" in m:
            self.status["step"] = m.get("step", 0)
            self.status["max_steps"] = m.get("max", self.status["max_steps"])
        if m.get("heartbeat"):
            self.status["heartbeat"] = (m.get("elapsed"), m.get("deadline"))
        if m.get("model"):
            self.status["model"] = m["model"]
        if ev.kind == RESULT:
            self.result = m.get("result") if isinstance(m.get("result"), dict) else self.result
        if ev.kind in (FINDING, VERIFIED):
            self.finding_events.append(ev)
        if ev.pane == "findings":
            # rendered from finding_events directly (rows() below)
            return
        pane = ev.pane
        if pane in self.entries:
            self._push(pane, ev.text, style_for_event(ev))

    def _push(self, pane: str, text: str, style: str) -> None:
        buf = self.entries[pane]
        buf.append((text, style))
        if len(buf) > MAX_ROWS:
            drop = len(buf) - MAX_ROWS
            del buf[:drop]
            if self.follow[pane]:
                pass  # follow re-anchors anyway
            else:
                self.offset[pane] = max(0, self.offset[pane] - drop)

    def rows(self, pane: str, width: int) -> List[Row]:
        if pane == "findings":
            return pane_rows([(ev.text, style_for_event(ev))
                              for ev in self.finding_events], width)
        return pane_rows(self.entries[pane], width)

    def anchor(self, pane: str, n_rows: int, height: int) -> None:
        if self.follow[pane]:
            self.offset[pane] = follow_offset(n_rows, height)

    def scroll(self, key: str, height: int, n_rows: int) -> None:
        self.follow[self.focus] = False
        self.offset[self.focus] = scroll_target(
            key, self.offset[self.focus], n_rows, height)
        if self.offset[self.focus] >= max(0, n_rows - height):
            self.follow[self.focus] = True

    # -- report ----------------------------------------------------------
    def report_markdown(self, model: str = "") -> str:
        findings = [ev.meta.get("finding") for ev in self.finding_events
                    if isinstance(ev.meta.get("finding"), dict)]
        trace = None
        if self.result is not None:
            trace = {"model": model or self.status.get("model") or "",
                     "summary": dict(self.result)}
            if self.subject and "target" not in trace["summary"]:
                trace["summary"]["target"] = self.subject
        return build_report(findings, trace=trace,
                            meta={"subject": self.subject,
                                  "model": model or self.status.get("model") or ""})


# -- curses shell -------------------------------------------------------
_STYLE_NAMES = {
    "critical": 1, "high": 2, "medium": 3, "low": 4, "verified": 5,
    "cmd": 6, "error": 1,
}


def _init_colors(curses):
    try:
        curses.start_color()
        curses.use_default_colors()
        curses.init_pair(1, curses.COLOR_RED, -1)
        curses.init_pair(2, curses.COLOR_YELLOW, -1)
        curses.init_pair(3, curses.COLOR_CYAN, -1)
        curses.init_pair(4, curses.COLOR_BLUE, -1)
        curses.init_pair(5, curses.COLOR_GREEN, -1)
        curses.init_pair(6, curses.COLOR_MAGENTA, -1)
    except Exception:
        pass


def _attr(curses, style: str):
    pair = _STYLE_NAMES.get(style)
    base = 0
    if style in ("critical", "high", "verified", "cmd", "result", "error"):
        base = curses.A_BOLD
    if style in ("reason", "system", "out", "text", "progress", "info",
                 "unknown", "low"):
        base = curses.A_DIM if style in ("reason", "system") else 0
    if pair:
        try:
            return base | curses.color_pair(pair)
        except Exception:
            return base
    return base


def _draw_pane(screen, curses, region: Region, title: str, rows: List[Row],
               offset: int, focused: bool) -> int:
    y, x, h, w = region
    if h <= 0 or w <= 0:
        return 0
    inner_h = max(0, h - 1)
    tattr = curses.A_REVERSE if focused else curses.A_DIM
    try:
        screen.addnstr(y, x, title.ljust(w - 1), w - 1, tattr)
    except curses.error:
        pass
    visible = visible_rows(rows, offset, inner_h)
    for i, (text, style) in enumerate(visible):
        try:
            screen.addnstr(y + 1 + i, x, text[:w - 1].ljust(w - 1),
                           w - 1, _attr(curses, style))
        except curses.error:
            pass
    return inner_h


def run_tui(runner, kind: str = "exploit", subject: str = "") -> int:
    """Drive curses until quit; return the child's exit code (or 0)."""
    import curses

    runner.start()
    state = TuiState(kind=kind, subject=subject)
    report: Optional[List[Row]] = None
    report_offset = 0
    saved_to = ""
    start = time.time()

    def _main(screen):
        nonlocal report, report_offset, saved_to
        curses.curs_set(0)
        screen.keypad(True)
        screen.timeout(100)
        _init_colors(curses)
        while True:
            for ev in runner.drain():
                state.append(ev)
            st = runner.status()
            state.status.update(st)
            state.status["elapsed"] = time.time() - start
            height, width = screen.getmaxyx()
            regions = layout(height, width)
            screen.erase()

            if report is None:
                _draw(screen, curses, regions, state, width)
            else:
                _draw_report(screen, curses, height, width, report,
                             report_offset, saved_to)

            screen.refresh()
            key = screen.getch()
            if key == -1:
                if runner._eof.is_set() and runner.child_done() and report is None:
                    pass  # stay open: user reads the result, then presses q
                continue

            if report is not None:
                rows_visible = max(1, height - 2)   # title + footer rows
                keymap = {curses.KEY_UP: "up", curses.KEY_DOWN: "down",
                          curses.KEY_PPAGE: "pageup", curses.KEY_NPAGE: "pagedown",
                          curses.KEY_HOME: "home", curses.KEY_END: "end"}
                if key in (ord("q"), 27):
                    report = None
                    saved_to = ""
                elif key in (ord("j"), curses.KEY_DOWN):
                    report_offset = scroll_target(
                        "down", report_offset, len(report), rows_visible)
                elif key in (ord("k"), curses.KEY_UP):
                    report_offset = scroll_target(
                        "up", report_offset, len(report), rows_visible)
                elif key in keymap:
                    report_offset = scroll_target(
                        keymap[key], report_offset, len(report), rows_visible)
                elif key == ord("s"):
                    try:
                        name = default_report_name()
                        with open(name, "w", encoding="utf-8") as fh:
                            fh.write("\n".join(r[0] for r in report) + "\n")
                        saved_to = name
                    except Exception as exc:  # noqa: BLE001
                        saved_to = f"error: {exc}"
                continue

            _handle_key(key, curses, state, runner, regions)
            if state.confirm_quit:
                try:
                    screen.addnstr(
                        height - 1, 0,
                        " child still running -- quit stops it? [y/N] ".ljust(width - 1),
                        width - 1, curses.A_REVERSE | curses.A_BOLD)
                except curses.error:
                    pass
                screen.refresh()
                screen.timeout(-1)          # block until the user answers
                ans = screen.getch()
                screen.timeout(100)
                if ans in (ord("y"), ord("Y")):
                    runner.stop()
                    break
                state.confirm_quit = False
                continue
            if state._quit:
                break
            if state._report:
                state._report = False
                md = state.report_markdown()
                report = [(ln, "text") for ln in md.split("\n")]
                report_offset = 0
                saved_to = ""

    try:
        curses.wrapper(_main)
    except KeyboardInterrupt:
        pass
    if runner.child_done() is False:
        runner.stop()
    result = runner.finalize()
    return result.returncode if result.returncode is not None else 0


def _handle_key(key, curses, state: TuiState, runner, regions) -> None:
    order = list(PANES)
    if key == 9:  # Tab
        state.focus = order[(order.index(state.focus) + 1) % len(order)]
        return
    if key in (ord("q"), ord("Q")):
        if runner.child_done() is False:
            state.confirm_quit = True
        else:
            state._quit = True
        return
    if key == ord("f"):
        state.follow[state.focus] = not state.follow[state.focus]
        return
    if key == ord("r"):
        state._report = True
        return
    keymap = {curses.KEY_UP: "up", curses.KEY_DOWN: "down",
              curses.KEY_PPAGE: "pageup", curses.KEY_NPAGE: "pagedown",
              curses.KEY_HOME: "home", curses.KEY_END: "end",
              ord("j"): "down", ord("k"): "up", ord("g"): "home",
              ord("G"): "end"}
    if key in keymap:
        y, x, h, w = regions[state.focus]
        rows = state.rows(state.focus, max(10, w - 1))
        state.scroll(keymap[key], max(1, h - 1), len(rows))


def _draw(screen, curses, regions, state: TuiState, width: int) -> None:
    hy, hx, hh, hw = regions["header"]
    try:
        hdr = header_text(state.kind, state.subject, state.status,
                          len(state.finding_events), hw)
        screen.addnstr(hy, hx, hdr.ljust(hw - 1), hw - 1,
                       curses.A_REVERSE | curses.A_BOLD)
    except curses.error:
        pass
    for pane in PANES:
        if pane not in regions:
            continue
        region = regions[pane]
        y, x, h, w = region
        rows = state.rows(pane, max(10, w - 1))
        state.anchor(pane, len(rows), max(1, h - 1))
        title = pane_title(pane, state.focus == pane,
                           len(state.finding_events) if pane == "findings" else 0,
                           state.follow[pane])
        _draw_pane(screen, curses, region, title, rows,
                   state.offset[pane], state.focus == pane)
    fy, fx, fh, fw = regions["footer"]
    hint = (" Tab focus │ j/k/PgUp/PgDn/g/G scroll │ f follow │ "
            "r report │ q quit ")
    if state.focus != "feed":
        hint = f" focus: {state.focus} │" + hint
    try:
        screen.addnstr(fy, fx, hint.ljust(fw - 1), fw - 1, curses.A_DIM)
    except curses.error:
        pass


def _draw_report(screen, curses, height: int, width: int, report: List[Row],
                 offset: int, saved_to: str) -> None:
    title = " report preview -- j/k scroll, s save, q close "
    if saved_to:
        title += f"-- saved: {saved_to} "
    _draw_pane(screen, curses, (0, 0, max(3, height - 1), width), title,
               report, offset, True)
    fy = max(0, height - 1)
    try:
        screen.addnstr(fy, 0,
                       " j/k/PgUp/PgDn/g/G scroll │ s save to file │ q close "
                       .ljust(max(1, width - 1)), max(1, width - 1),
                       curses.A_DIM)
    except curses.error:
        pass


def preview_markdown(md: str) -> Optional[str]:
    """Standalone TTY preview for `velora report`. Returns saved filename or None."""
    import curses

    rows: List[Row] = [(ln, "text") for ln in md.split("\n")]
    state = {"offset": 0, "saved": ""}

    def _main(screen):
        curses.curs_set(0)
        screen.keypad(True)
        screen.timeout(-1)
        while True:
            height, width = screen.getmaxyx()
            screen.erase()
            _draw_report(screen, curses, height, width, rows, state["offset"],
                         state["saved"])
            screen.refresh()
            key = screen.getch()
            h = max(1, height - 2)     # title + footer rows
            keymap = {curses.KEY_UP: "up", curses.KEY_DOWN: "down",
                      curses.KEY_PPAGE: "pageup", curses.KEY_NPAGE: "pagedown",
                      curses.KEY_HOME: "home", curses.KEY_END: "end",
                      ord("k"): "up", ord("j"): "down", ord("g"): "home",
                      ord("G"): "end"}
            if key in (ord("q"), 27, ord("Q")):
                return
            if key == ord("s"):
                try:
                    name = default_report_name()
                    with open(name, "w", encoding="utf-8") as fh:
                        fh.write(md if md.endswith("\n") else md + "\n")
                    state["saved"] = name
                except Exception as exc:  # noqa: BLE001
                    state["saved"] = f"error: {exc}"
            elif key in keymap:
                state["offset"] = scroll_target(keymap[key], state["offset"],
                                                len(rows), h)

    try:
        curses.wrapper(_main)
    except Exception:
        pass
    return state["saved"] or None
