"""Tests for the interactive line interface (velora.ptui)."""

from __future__ import annotations

import io
import json
import os

import pytest
from rich.console import Console

from velora.cli import create_parser
from velora.ptui.menus import localTaskCompleter, mainTaskCompleter
from velora.ptui.menus import local_task_entry, main_task_entry
from velora.ptui.prompts import prompt_continuation
from velora.ptui.session import (
    _DISCUSS_PLACEHOLDER,
    _GOOGLE_PLACEHOLDER,
    _SEPARATOR,
    VeloraSession,
)
from velora.tui.events import Event, FINDING, PROGRESS, RESULT, VERIFIED
from velora.tui.runner import RunResult, RunSpec, TuiRunner


def _session(tmp_path, findings=None, result=None) -> VeloraSession:
    import velora.ptui.session as session_mod

    runner = TuiRunner(RunSpec(argv=["true"], kind="scan"))
    orig_console = session_mod.Console
    session_mod.Console = lambda **_kw: Console(file=io.StringIO(),
                                                force_terminal=False,
                                                width=100, markup=False)
    try:
        session = VeloraSession(runner, kind="scan",
                                subject="http://127.0.0.1:8080",
                                log_dir=str(tmp_path / "logs"))
    finally:
        session_mod.Console = orig_console
    if result is not None:
        session.result = result
    elif findings is not None:
        session.result = RunResult(findings=findings, returncode=0)
    return session


def _out(session: VeloraSession) -> str:
    return session.console.file.getvalue()


# -- menus -----------------------------------------------------------------
def test_main_menu_verbs_expected():
    assert mainTaskCompleter.tasks == [
        "next", "more", "todo", "discuss", "google", "help", "quit"]
    assert mainTaskCompleter().task_details.count("\n - ") >= 7
    assert "Velora" in str(mainTaskCompleter.task_meta["todo"])


def test_local_menu_verbs_expected():
    assert localTaskCompleter.tasks == [
        "discuss", "brainstorm", "help", "google", "continue"]


def test_main_task_entry_rejects_unknown_then_accepts(capsys, monkeypatch):
    answers = iter(["bogus", "help"])
    monkeypatch.setattr("velora.ptui.menus.prompt",
                        lambda *a, **k: next(answers))
    assert main_task_entry() == "help"
    assert "Invalid task, try again." in capsys.readouterr().out


def test_local_task_entry_rejects_unknown_then_accepts(capsys, monkeypatch):
    answers = iter(["nope", "continue"])
    monkeypatch.setattr("velora.ptui.menus.prompt",
                        lambda *a, **k: next(answers))
    assert local_task_entry() == "continue"
    assert "Invalid task, try again." in capsys.readouterr().out


# -- prompts ---------------------------------------------------------------
def test_prompt_continuation_gutter():
    hard = prompt_continuation(10, 0, 0)
    assert "- 1 - " in getattr(hard, "value", str(hard))
    assert prompt_continuation(10, 1, 1) == "       -> "


# -- session: banner & events ----------------------------------------------
def test_banner_shows_settings(tmp_path):
    session = _session(tmp_path)
    text = _out(session)
    assert "Welcome to Velora, an interactive security testing assistant." in text
    assert "The settings are:" in text
    assert "- workflow:      scan" in text
    assert "http://127.0.0.1:8080" in text


def test_print_event_styles(tmp_path):
    session = _session(tmp_path)
    session._print_event(Event(kind=PROGRESS, text="[step] scanning"))
    session._print_event(Event(kind=VERIFIED, text="success-check: pwned"))
    session._print_event(Event(kind=RESULT, text="done"))
    session._print_event(Event(kind=FINDING, text="[CRITICAL] sqli  a:1",
                               meta={"severity": "critical"}))
    session._print_event(Event(kind=PROGRESS, text="boom",
                               meta={"level": "error"}))
    text = _out(session)
    for expected in ("[step] scanning", "success-check: pwned", "done",
                     "[CRITICAL] sqli  a:1", "boom"):
        assert expected in text


def test_print_event_sanitizes_ansi(tmp_path):
    session = _session(tmp_path)
    session._print_event(Event(kind=PROGRESS, text="\x1b[31mred\x1b[0m"))
    assert "red" in _out(session)
    assert "\x1b" not in _out(session)


# -- session: existing-backend views ---------------------------------------
def test_tasks_text_lists_findings(tmp_path):
    findings = [{"severity": "high", "type": "xss", "location": "app.py",
                 "line": 12}]
    session = _session(tmp_path, findings=findings)
    tasks = session._tasks_text()
    assert "1. [HIGH] xss  (app.py:12)" in tasks


def test_tasks_text_empty(tmp_path):
    session = _session(tmp_path, findings=[])
    assert "No findings yet" in session._tasks_text()


def test_report_text_is_markdown(tmp_path):
    findings = [{"severity": "low", "type": "info-leak", "location": "x"}]
    session = _session(tmp_path, findings=findings)
    md = session._report_text()
    assert md.startswith("# ")
    assert "Velora Security Report" in md
    assert "info-leak" in md


# -- session: command dispatch ---------------------------------------------
def test_input_handler_quit(tmp_path, monkeypatch):
    session = _session(tmp_path)
    monkeypatch.setattr("velora.ptui.session.main_task_entry", lambda: "quit")
    assert session.input_handler() is False
    assert "Thank you for using Velora!" in _out(session)
    assert _SEPARATOR not in _out(session)   # separator is printed by main()


def test_input_handler_help_returns_details(tmp_path, monkeypatch, capsys):
    session = _session(tmp_path)
    monkeypatch.setattr("velora.ptui.session.main_task_entry", lambda: "help")
    result = session.input_handler()
    assert "next:" in result
    out = capsys.readouterr().out
    assert "Below are the available tasks:" in out
    assert "Please key in the correct options." not in out


def test_input_handler_google_placeholder(tmp_path, monkeypatch):
    session = _session(tmp_path)
    monkeypatch.setattr("velora.ptui.session.main_task_entry", lambda: "google")
    assert session.input_handler() == _GOOGLE_PLACEHOLDER
    text = _out(session)
    assert "Google integration is still under development." in text
    assert "still under development." in text


def test_input_handler_discuss_placeholder(tmp_path, monkeypatch):
    session = _session(tmp_path)
    order = iter(["discuss", "hello?"])
    monkeypatch.setattr("velora.ptui.session.main_task_entry",
                        lambda: next(order))
    monkeypatch.setattr("velora.ptui.session.prompt_ask",
                        lambda *a, **k: next(order))
    monkeypatch.setattr("velora.ptui.session.HTML", lambda v: v)
    assert session.input_handler() == _DISCUSS_PLACEHOLDER
    text = _out(session)
    assert "Velora:" in text
    assert _DISCUSS_PLACEHOLDER in text


def test_input_handler_next_uses_source_menu(tmp_path, monkeypatch):
    session = _session(tmp_path,
                       findings=[{"severity": "medium", "type": "path-traversal",
                                  "location": "dl.py", "line": 3}])
    order = iter(["next", "tool output here"])
    monkeypatch.setattr("velora.ptui.session.main_task_entry",
                        lambda: next(order))
    monkeypatch.setattr("velora.ptui.session.prompt_select",
                        lambda **k: 0)
    monkeypatch.setattr("velora.ptui.session.prompt_ask",
                        lambda *a, **k: next(order))
    response = session.input_handler()
    text = _out(session)
    assert "Please choose the source of the information." not in text  # title is menu-side
    assert "Your input: (End with <shift + right-arrow>)" in text
    assert "Based on the analysis, the following tasks are recommended:" in text
    assert "[MEDIUM] path-traversal" in response
    assert any("Source: tool" in t for _, t in session.history["user"])


def test_input_handler_todo_prints_report(tmp_path, monkeypatch):
    session = _session(tmp_path,
                       findings=[{"severity": "low", "type": "info", "location": "a"}])
    monkeypatch.setattr("velora.ptui.session.main_task_entry", lambda: "todo")
    session.input_handler()
    text = _out(session)
    assert "Based on the analysis, the following tasks are recommended:" in text
    assert "You can follow the instructions below to complete the tasks." in text
    assert "Velora Security Report" in text


def test_input_handler_more_enters_local_loop(tmp_path, monkeypatch):
    session = _session(tmp_path,
                       findings=[{"severity": "high", "type": "sqli",
                                  "location": "q.py", "description": "SQLi in id"}])
    main = iter(["more", "continue"])       # continue is issued by the local loop
    monkeypatch.setattr("velora.ptui.session.main_task_entry",
                        lambda: next(main))
    monkeypatch.setattr("velora.ptui.session.input", lambda: "",
                        raising=False)
    monkeypatch.setattr("velora.ptui.session.local_task_entry",
                        lambda: "continue")
    session.input_handler()
    text = _out(session)
    assert "Velora will generate more test details" in text
    assert "Below are the further details." in text
    assert "SQLi in id" in text


def test_input_handler_more_without_run_is_red(tmp_path, monkeypatch):
    session = _session(tmp_path)
    session.result = None
    monkeypatch.setattr("velora.ptui.session.main_task_entry", lambda: "more")
    msg = session.input_handler()
    assert "You have not initialized the task yet" in msg


# -- session: main loop / save ----------------------------------------------
def test_main_runs_quit_and_saves_session(tmp_path, monkeypatch):
    session = _session(tmp_path)
    monkeypatch.setattr(session, "initialize", lambda: None)
    monkeypatch.setattr(session, "input_handler", lambda: False)
    monkeypatch.setattr(session, "save_session", lambda: None)
    rc = session.main()
    assert rc == 0
    # separator printed after each command, history dump written
    assert _SEPARATOR in _out(session)
    logs = list((tmp_path / "logs").glob("velora_ptui_log_*.txt"))
    assert len(logs) == 1
    history = json.loads(logs[0].read_text())
    assert "user" in history and "velora" in history


def test_main_writes_session_file_on_quit(tmp_path, monkeypatch, tmp_path_factory):
    cwd = tmp_path_factory.mktemp("cwd")
    monkeypatch.chdir(cwd)
    session = _session(tmp_path)
    monkeypatch.setattr(session, "initialize", lambda: None)
    order = iter(["quit", ""])               # quit, then default save name
    monkeypatch.setattr("velora.ptui.session.main_task_entry",
                        lambda: next(order))
    monkeypatch.setattr("velora.ptui.session.prompt_ask",
                        lambda *a, **k: next(order))
    assert session.main() == 0
    saved = list((cwd / "velora_sessions").iterdir())
    assert len(saved) == 1
    payload = json.loads(saved[0].read_text())
    assert "task_log" in payload and "history" in payload


def test_main_survives_command_exception(tmp_path, monkeypatch):
    session = _session(tmp_path)
    monkeypatch.setattr(session, "initialize", lambda: None)

    def boom():
        raise RuntimeError("kaboom")

    monkeypatch.setattr(session, "input_handler", boom)
    monkeypatch.setattr(session, "save_session", lambda: None)
    rc = session.main()                      # red exception + guidance, no crash
    assert rc == 0
    assert "Exception: kaboom" in _out(session)


# -- CLI wiring --------------------------------------------------------------
def test_scan_and_exploit_have_curses_flag():
    parser = create_parser()
    for argv in (["scan", "x", "--curses"], ["exploit", "--target", "t", "--curses"]):
        args = parser.parse_args(argv)
        assert args.curses is True
    assert parser.parse_args(["scan", "x"]).curses is False


def test_run_ptui_importable():
    from velora.ptui import run_ptui
    assert callable(run_ptui)
