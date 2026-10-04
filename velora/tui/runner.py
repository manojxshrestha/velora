"""Runs a velora command as a child process and streams its output as events.

The TUI never modifies the child: it spawns today's `python -m velora exploit/
scan ...` with piped output, converts lines via :class:`LineParser`, and (for
exploit) attaches the opencode :class:`SessionFeed` poller.  Headless mode
:meth:`run_to_completion` powers tests and the non-curses fallback.
"""

from __future__ import annotations

import os
import queue
import signal
import subprocess
import sys
import threading
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from velora.tui.events import Event, FINDING, PROGRESS, RESULT, event_from_finding
from velora.tui.feed import DEFAULT_POLL_S, SessionFeed
from velora.tui.logparse import LineParser
from velora.tui.report import load_findings, load_trace

_SENTINEL = object()


@dataclass
class RunSpec:
    argv: List[str]
    kind: str = "exploit"                    # "exploit" | "scan"
    guidance_path: Optional[str] = None
    trace_out: Optional[str] = None
    findings_out: Optional[str] = None       # scan -o
    feed: bool = True                        # attach session poller
    subject: str = ""                        # target URL / scan path (header)
    env: Dict[str, str] = field(default_factory=dict)


@dataclass
class RunResult:
    events: List[Event] = field(default_factory=list)
    returncode: Optional[int] = None
    result: Optional[Dict[str, Any]] = None
    findings: List[Dict[str, Any]] = field(default_factory=list)
    model: Optional[str] = None
    subject: str = ""
    kind: str = "exploit"
    trace: Optional[Dict[str, Any]] = None


class TuiRunner:
    """Spawns the child, pumps lines+feed into a queue, tracks run status."""

    def __init__(self, spec: RunSpec,
                 feed: Optional[SessionFeed] = None,
                 poll_s: float = DEFAULT_POLL_S,
                 stdout=None):
        self.spec = spec
        self.queue: "queue.Queue[Any]" = queue.Queue()
        self.parser = LineParser(kind=spec.kind)
        self.poll_s = poll_s
        self._stdout = stdout
        self.proc: Optional[subprocess.Popen] = None
        self._threads: List[threading.Thread] = []
        self._stop = threading.Event()
        self.started_at = time.time()
        self.state: Dict[str, Any] = {
            "step": 0, "max_steps": 0, "heartbeat": None, "model": None,
            "child_alive": False, "returncode": None, "feed_up": False,
        }
        self._feed = feed
        self._need_feed = spec.feed and feed is None
        self._collected: List[Event] = []
        self._finalized = False
        self._eof = threading.Event()

    # -- lifecycle --------------------------------------------------------
    def start(self) -> None:
        env = dict(os.environ)
        env.update(self.spec.env)
        self.proc = subprocess.Popen(
            self.spec.argv, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            text=True, errors="replace", bufsize=1, env=env,
            start_new_session=True, cwd=None)
        self.state["child_alive"] = True
        self.started_at = time.time()
        t = threading.Thread(target=self._read_child, daemon=True,
                             name="tui-child-reader")
        t.start()
        self._threads.append(t)
        if self._need_feed:
            self._feed = SessionFeed(poll_s=self.poll_s)
        if self._feed is not None:
            t2 = threading.Thread(target=self._read_feed, daemon=True,
                                  name="tui-session-feed")
            t2.start()
            self._threads.append(t2)
        for ev in self._guidance_events():
            self._emit(ev)

    def _guidance_events(self) -> List[Event]:
        path = self.spec.guidance_path
        if not path or path == "-":
            return []
        try:
            findings = load_findings(path)
        except Exception:
            return []
        return [event_from_finding(f, provenance="guidance") for f in findings[:8]]

    # -- pumps ------------------------------------------------------------
    def _emit(self, ev: Event) -> None:
        self._track(ev)
        self._collected.append(ev)
        self.queue.put(ev)

    def _track(self, ev: Event) -> None:
        m = ev.meta or {}
        if "step" in m:
            self.state["step"] = m["step"]
            self.state["max_steps"] = m.get("max", self.state["max_steps"])
        if m.get("heartbeat"):
            self.state["heartbeat"] = (m.get("elapsed"), m.get("deadline"))
        if m.get("model"):
            self.state["model"] = m["model"]
        if ev.kind == RESULT:
            self.state["result"] = m.get("result")

    def _read_child(self) -> None:
        try:
            assert self.proc is not None and self.proc.stdout is not None
            stream = self._stdout if self._stdout is not None else self.proc.stdout
            for line in stream:
                for ev in self.parser.feed(line):
                    self._emit(ev)
        except Exception as exc:
            self._emit(Event(kind=PROGRESS,
                             text=f"[tui] reader error: {exc}"))
        finally:
            for ev in self.parser.finish():
                self._emit(ev)
            self.queue.put(_SENTINEL)
            self._eof.set()

    def _read_feed(self) -> None:
        assert self._feed is not None
        while not self._stop.is_set():
            try:
                events = self._feed.poll_once()
            except Exception as exc:
                events = [Event(kind=PROGRESS,
                                text=f"[tui] feed error: {exc}")]
            if events:
                self.state["feed_up"] = True
            for ev in events:
                self._emit(ev)
            self._stop.wait(self.poll_s)

    # -- consumption ------------------------------------------------------
    def drain(self, max_n: int = 0) -> List[Event]:
        out: List[Event] = []
        while True:
            try:
                item = self.queue.get_nowait()
            except queue.Empty:
                break
            if item is _SENTINEL:
                continue
            out.append(item)
            if max_n and len(out) >= max_n:
                break
        return out

    def child_done(self) -> bool:
        return self.proc is not None and self.proc.poll() is not None

    def status(self) -> Dict[str, Any]:
        st = dict(self.state)
        st["child_alive"] = self.child_done() is False
        st["returncode"] = self.proc.poll() if self.proc else None
        st["elapsed"] = time.time() - self.started_at
        return st

    def stop(self) -> None:
        """SIGINT the child's process group; escalate to SIGKILL after grace."""
        if self.proc is None or self.child_done():
            return
        try:
            os.killpg(os.getpgid(self.proc.pid), signal.SIGINT)
        except Exception:
            try:
                self.proc.send_signal(signal.SIGINT)
            except Exception:
                pass
        for _ in range(50):
            if self.child_done():
                return
            time.sleep(0.1)
        try:
            os.killpg(os.getpgid(self.proc.pid), signal.SIGKILL)
        except Exception:
            pass
        try:
            self.proc.wait(timeout=3)
        except Exception:
            pass

    def finalize(self, timeout: float = 10.0) -> RunResult:
        if self._finalized:
            return self._result()
        self._finalized = True
        if self.proc is not None:
            try:
                self.proc.wait(timeout=timeout)
            except Exception:
                self.stop()
            self.state["returncode"] = self.proc.poll()
        self._stop.set()
        for t in self._threads:
            t.join(timeout=2.0)
        # drain anything left (events already live in _collected via _emit)
        while self.drain():
            pass
        return self._result()

    def _result(self) -> RunResult:
        findings: List[Dict[str, Any]] = []
        result = self.state.get("result")
        trace = None
        # 1) scan -o findings file (authoritative)
        if self.spec.findings_out and os.path.exists(self.spec.findings_out):
            try:
                findings = load_findings(self.spec.findings_out)
            except Exception:
                findings = []
        # 2) exploit trace-out
        if self.spec.trace_out and os.path.exists(self.spec.trace_out):
            trace = load_trace(self.spec.trace_out)
            if trace.get("summary") and not result:
                result = trace["summary"]
        # 3) whatever the parser saw on stdout
        if not findings:
            for ev in self._collected:
                if ev.kind == FINDING and isinstance(ev.meta.get("finding"), dict):
                    findings.append(ev.meta["finding"])
        if not findings and self.parser._text_findings:
            findings = list(self.parser._text_findings)
        if not result and self.parser.result:
            result = self.parser.result
        return RunResult(
            events=list(self._collected), returncode=self.state.get("returncode"),
            result=result, findings=findings, model=self.state.get("model"),
            subject=self.spec.subject, kind=self.spec.kind, trace=trace)

    # -- headless (tests / no-curses) -------------------------------------
    def run_to_completion(self, timeout: float = 60.0) -> RunResult:
        self.start()
        deadline = time.time() + timeout
        while time.time() < deadline:
            self.drain()          # events land in _collected via _emit
            if self._eof.is_set() and self.child_done():
                break
            time.sleep(0.02)
        else:
            self.stop()
        return self.finalize()


def child_argv(raw_args: List[str],
               python: Optional[str] = None) -> List[str]:
    """argv for the wrapped child: `python -m velora <original args>`."""
    return [python or sys.executable, "-m", "velora", *raw_args]
