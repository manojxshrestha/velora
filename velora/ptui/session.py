"""PentestGPT-style interactive session for velora scan/exploit runs.

Recreates the PentestGPT (USENIX Security 2024) terminal experience: a green
settings banner, the workflow auto-started under a rich status spinner with
live output, then a line-oriented command loop with tab-completed verbs
(``next more todo discuss google help quit``), radio-list menus, multiline
input submitted with shift+right-arrow, styled replies, and save-on-quit.

The backend is untouched: the same child process + :class:`TuiRunner` the
curses view uses supplies every event printed here.
"""

from __future__ import annotations

import json
import os
import time
import traceback
from typing import Any, Dict, List, Optional

from rich.console import Console

from velora.ptui.menus import localTaskCompleter, local_task_entry
from velora.ptui.menus import mainTaskCompleter, main_task_entry
from velora.ptui.prompts import prompt_ask, prompt_select
from velora.tui.events import (
    FEED_CMD,
    FEED_REASONING,
    FINDING,
    PROGRESS,
    RESULT,
    SYSTEM,
    VERIFIED,
    Event,
    sanitize,
)
from velora.tui.report import build_report

try:
    from prompt_toolkit.formatted_text import HTML
except Exception:                                    # pragma: no cover
    HTML = None                                       # type: ignore[assignment]

_SEPARATOR = "-----------------------------------------"

_GOOGLE_PLACEHOLDER = "Google search results:\nstill under development."
_DISCUSS_PLACEHOLDER = "Velora discussion:\nstill under development."
_BRAINSTORM_PLACEHOLDER = "Velora brainstorming:\nstill under development."

# Rich equivalents of the curses palette in velora/tui/render.py.
_EVENT_STYLE: Dict[str, str] = {
    FEED_REASONING: "dim",
    FEED_CMD: "bold magenta",
    RESULT: "bold",
    VERIFIED: "bold green",
}
_SEVERITY_STYLE: Dict[str, str] = {
    "critical": "bold red",
    "high": "bold yellow",
    "medium": "cyan",
    "low": "blue",
    "verified": "bold green",
    "cmd": "bold magenta",
    "error": "bold red",
}


class VeloraSession:
    """One PentestGPT-style interactive session over a velora run."""

    postfix_options: Dict[str, str] = {
        "tool": "The input content is from a security testing tool. "
                "You need to list down all the points that are interesting to you; "
                "you should summarize it as if it is reporting to a senior penetration "
                "tester for further guidance.\n",
        "user-comments": "",
        "web": "The input content is from web pages. You need to summarize the "
               "readable-contents, and list down all the points that can be "
               "interesting for penetration testing.\n",
        "default": "The user did not specify the input source. You need to "
                   "summarize based on the contents.\n",
    }

    options_desc: Dict[str, str] = {
        "tool": " Paste the output of the security test tool used",
        "user-comments": "",
        "web": " Paste the relevant content of a web page",
        "default": " Write whatever you want, the tool will handle it",
    }

    def __init__(self, runner, kind: str = "exploit", subject: str = "",
                 log_dir: str = "logs") -> None:
        from velora.sil.model_config import active

        self.runner = runner
        self.kind = kind
        self.subject = subject
        self.log_dir = log_dir
        self.save_dir = "velora_sessions"
        # markup=False: log lines like "[step 3/10]" must print verbatim.
        self.console = Console(markup=False)
        self.chat_count = 0
        self.result = None                    # velora RunResult after finalize
        self.task_log: Dict[str, Any] = {
            "task description": subject,
            "workflow": kind,
        }
        self.history: Dict[str, List[tuple]] = {
            "user": [],
            "velora": [],
            "workflow": [],
            "exception": [],
        }
        try:
            cfg = active()
            model = (f"{cfg.get('provider')}/{cfg.get('model')}"
                     if cfg and cfg.get("model") else "-")
        except Exception:                     # noqa: BLE001
            model = "-"
        self.task_log["model"] = model

        self.console.print(
            "Welcome to Velora, an interactive security testing assistant.",
            style="bold green")
        self.console.print("The settings are: ")
        self.console.print(f" - workflow:      {kind}", style="bold green")
        self.console.print(f" - target:        {subject or '-'}", style="bold green")
        self.console.print(f" - model:         {model}", style="bold green")
        self.console.print(f" - log directory: {log_dir}", style="bold green")

    # -- logging ---------------------------------------------------------
    def log_conversation(self, source: str, text: str) -> None:
        if source not in self.history:
            source = "exception"
        self.history[source].append((time.time(), text))

    # -- workflow streaming ----------------------------------------------
    def _print_event(self, ev: Event) -> None:
        text = sanitize(ev.text)
        if not text:
            return
        if ev.kind == FINDING:
            sev = str((ev.meta or {}).get("severity") or "unknown").lower()
            style = _SEVERITY_STYLE.get(sev, "")
        elif ev.kind in (PROGRESS, SYSTEM) and \
                str((ev.meta or {}).get("level") or "").lower() in ("error", "err"):
            style = _SEVERITY_STYLE["error"]
        else:
            style = _EVENT_STYLE.get(ev.kind, "")
        if style:
            self.console.print(text, style=style)
        else:
            self.console.print(text)

    def _stream(self) -> None:
        """Drain runner events live; animate the status spinner while idle."""
        while True:
            events = self.runner.drain()
            if events:
                for ev in events:
                    self._print_event(ev)
                continue
            if self.runner._eof.is_set() and self.runner.child_done():
                break
            with self.console.status("[bold green] Velora Thinking..."):
                time.sleep(0.25)
        for ev in self.runner.drain():        # anything the loop raced past
            self._print_event(ev)

    def initialize(self) -> None:
        """Start the child and stream its run to completion (PentestGPT-style)."""
        with self.console.status("[bold green] Initializing workflow..."):
            self.runner.start()
        self._stream()
        self.result = self.runner.finalize()
        self.console.print(f"- {self.kind} workflow finished.", style="bold green")
        self.log_conversation("velora", f"- {self.kind} workflow finished.")

    # -- existing-backend views -------------------------------------------
    def _findings(self) -> List[Dict[str, Any]]:
        return list(self.result.findings) if self.result else []

    def _tasks_text(self) -> str:
        findings = self._findings()
        if not findings:
            return ("No findings yet. Use `next` to input tool output and "
                    "continue the analysis.")
        lines = []
        for i, f in enumerate(findings, 1):
            sev = str(f.get("severity") or "unknown").upper()
            title = f.get("type") or f.get("title") or "finding"
            loc = str(f.get("location") or "-")
            line = f.get("line")
            where = f"{loc}:{line}" if line is not None and loc != "-" else loc
            lines.append(f"{i}. [{sev}] {title}  ({where})")
        return "\n".join(lines)

    def _details_text(self) -> str:
        findings = self._findings()
        if not findings:
            return "No detailed findings are available yet."
        parts = []
        for i, f in enumerate(findings, 1):
            sev = str(f.get("severity") or "unknown").upper()
            title = f.get("type") or f.get("title") or "finding"
            loc = str(f.get("location") or "-")
            desc = str(f.get("description") or f.get("detail") or "").strip()
            head = f"{i}. [{sev}] {title}  ({loc})"
            parts.append(f"{head}\n   {desc}" if desc else head)
        return "\n\n".join(parts)

    def _report_text(self) -> str:
        res = self.result
        return build_report(
            self._findings(),
            trace=getattr(res, "trace", None),
            meta={"subject": self.subject,
                  "model": getattr(res, "model", None) or ""},
        )

    # -- main command dispatch ---------------------------------------------
    def local_input_handler(self) -> str:
        """Sub-task loop after ``more``: discuss / brainstorm / google / continue."""
        local_task_response = ""
        self.chat_count += 1
        local_request_option = local_task_entry()
        self.log_conversation("user", local_request_option)

        if local_request_option == "help":
            print(localTaskCompleter().task_details)

        elif local_request_option == "discuss":
            self.console.print("Please share your findings and questions with Velora.")
            self.log_conversation(
                "velora",
                "Please share your findings and questions with Velora. "
                "(End with <shift + right-arrow>)",
            )
            user_input = prompt_ask("Your input: ", multiline=True)
            self.log_conversation("user", user_input)
            with self.console.status("[bold green] Velora Thinking..."):
                local_task_response = _DISCUSS_PLACEHOLDER
            self.console.print("Velora:\n", style="bold green")
            self.console.print(local_task_response + "\n", style="yellow")
            self.log_conversation("velora", local_task_response)

        elif local_request_option == "brainstorm":
            self.console.print("Please share your concerns and questions with Velora.")
            self.log_conversation(
                "velora",
                "Please share your concerns and questions with Velora. "
                "(End with <shift + right-arrow>)",
            )
            user_input = prompt_ask("Your input: ", multiline=True)
            self.log_conversation("user", user_input)
            with self.console.status("[bold green] Velora Thinking..."):
                local_task_response = _BRAINSTORM_PLACEHOLDER
            self.console.print("Velora:\n", style="bold green")
            self.console.print(local_task_response + "\n", style="yellow")
            self.log_conversation("velora", local_task_response)

        elif local_request_option == "google":
            self.console.print("Google integration is still under development.",
                               style="bold green")
            self.log_conversation("velora", _GOOGLE_PLACEHOLDER)
            self.console.print(_GOOGLE_PLACEHOLDER + "\n", style="yellow")
            return _GOOGLE_PLACEHOLDER

        elif local_request_option == "continue":
            self.console.print("Exit the local task and continue the main task.",
                               style="bold green")
            self.log_conversation("velora",
                                  "Exit the local task and continue the main task.")
            local_task_response = "continue"

        return local_task_response

    def input_handler(self) -> Any:
        """Main REPL dispatch: next / more / todo / discuss / google / help / quit."""
        self.chat_count += 1

        request_option = main_task_entry()
        self.log_conversation("user", request_option)

        if request_option == "help":
            print(mainTaskCompleter().task_details)
            return mainTaskCompleter().task_details

        if request_option == "next":
            options = list(self.postfix_options.keys())
            opt_desc = list(self.options_desc.values())
            value_list = [
                (i, HTML(
                    f'<style fg="cyan">{options[i]}</style>'
                    f'<style fg="LightSeaGreen">{opt_desc[i]}</style>'))
                for i in range(len(options))
            ]
            source = prompt_select(
                title="Please choose the source of the information.", values=value_list)
            self.console.print("Your input: (End with <shift + right-arrow>)",
                               style="bold green")
            user_input = prompt_ask("> ", multiline=True)
            self.log_conversation("user",
                                  f"Source: {options[int(source)]}" + "\n" + user_input)
            with self.console.status("[bold green] Velora Thinking..."):
                tasks_text = self._tasks_text()
            self.console.print(
                "Based on the analysis, the following tasks are recommended:",
                style="bold green")
            self.console.print(tasks_text + "\n")
            self.log_conversation(
                "velora",
                "Based on the analysis, the following tasks are recommended:"
                + tasks_text)
            response = tasks_text

        elif request_option == "more":
            self.log_conversation("user", "more")
            if not self.result:
                msg = ("You have not initialized the task yet. Please perform the "
                       "basic testing following `next` option.")
                self.console.print(msg, style="bold red")
                self.log_conversation("velora", msg)
                return msg
            self.console.print(
                "Velora will generate more test details, and enter the sub-task "
                "generation mode. (Pressing Enter to continue)", style="bold green")
            self.log_conversation(
                "velora",
                "Velora will generate more test details, and enter the sub-task "
                "generation mode.")
            input()
            with self.console.status("[bold green] Velora Thinking..."):
                generation_response = self._details_text()
            self.console.print("Below are the further details.", style="bold green")
            self.console.print(generation_response + "\n")
            self.log_conversation("velora", generation_response)
            response = generation_response

            while True:
                local_task_response = self.local_input_handler()
                if local_task_response == "continue":
                    break

        elif request_option == "todo":
            self.log_conversation("user", "todo")
            with self.console.status("[bold green] Velora Thinking..."):
                tasks_text = self._tasks_text()
                report_text = self._report_text()
            self.console.print(
                "Based on the analysis, the following tasks are recommended:",
                style="bold green")
            self.console.print(tasks_text + "\n")
            self.log_conversation(
                "velora",
                "Based on the analysis, the following tasks are recommended:"
                + tasks_text)
            self.console.print(
                "You can follow the instructions below to complete the tasks.",
                style="bold green")
            self.console.print(report_text + "\n")
            self.log_conversation("velora", report_text)
            response = tasks_text

        elif request_option == "discuss":
            self.console.print(
                "Please share your thoughts/questions with Velora. "
                "(End with <shift + right-arrow>) ")
            self.log_conversation(
                "velora", "Please share your thoughts/questions with Velora.")
            user_input = prompt_ask("Your input: ", multiline=True)
            self.log_conversation("user", user_input)
            with self.console.status("[bold green] Velora Thinking..."):
                response = _DISCUSS_PLACEHOLDER
            self.console.print("Velora:\n", style="bold green")
            self.console.print(response + "\n", style="yellow")
            self.log_conversation("velora", response)

        elif request_option == "google":
            self.console.print("Google integration is still under development.",
                               style="bold green")
            self.log_conversation("velora", _GOOGLE_PLACEHOLDER)
            self.console.print(_GOOGLE_PLACEHOLDER + "\n", style="yellow")
            return _GOOGLE_PLACEHOLDER

        elif request_option == "quit":
            response = False
            self.console.print("Thank you for using Velora!", style="bold green")
            self.log_conversation("velora", "Thank you for using Velora!")

        else:
            self.console.print("Please key in the correct options.", style="bold red")
            self.log_conversation("velora", "Please key in the correct options.")
            response = "Please key in the correct options."
        return response

    # -- session end --------------------------------------------------------
    def save_session(self) -> None:
        self.console.print(
            "Before you quit, you may want to save the current session.",
            style="bold green")
        save_name = prompt_ask(
            "Please enter the name of the current session. "
            "(Default with current timestamp)\n> ",
            multiline=False,
        )
        if save_name == "":
            save_name = str(time.time())
        save_root = os.path.join(os.getcwd(), self.save_dir)
        os.makedirs(save_root, exist_ok=True)
        with open(os.path.join(save_root, save_name), "w") as f:
            json.dump({"task_log": self.task_log, "history": self.history}, f)
        self.console.print(f"The current session is saved as {save_name}",
                           style="bold green")

    def main(self) -> int:
        """Run the interactive session; return the child's exit code."""
        interrupted = False
        try:
            try:
                self.initialize()
            except KeyboardInterrupt:
                interrupted = True
                self.console.print("Workflow interrupted.", style="bold red")
                self.log_conversation("exception", "KeyboardInterrupt during workflow")
            while not interrupted:
                try:
                    result = self.input_handler()
                    self.console.print(_SEPARATOR, style="bold white")
                    if not result:                 # end of the session
                        break
                except KeyboardInterrupt:
                    interrupted = True
                    break
                except Exception as e:             # noqa: BLE001
                    self.log_conversation("exception", str(e))
                    self.console.print(f"Exception: {e!s}", style="bold red")
                    self.console.print(
                        "Exception details are below. You may submit an issue on "
                        "GitHub and paste the error trace.", style="bold green")
                    traceback.print_exc()
                    break
        finally:
            if self.runner.child_done() is False:
                self.runner.stop()
            if self.result is None:
                try:
                    self.result = self.runner.finalize()
                except Exception:                 # noqa: BLE001
                    self.result = None
            try:
                os.makedirs(self.log_dir, exist_ok=True)
                log_path = os.path.join(
                    self.log_dir, f"velora_ptui_log_{time.time()}.txt")
                with open(log_path, "w") as f:
                    json.dump(self.history, f)
            except Exception:                     # noqa: BLE001
                pass
            if not interrupted:
                try:
                    self.save_session()
                except (KeyboardInterrupt, Exception):    # noqa: BLE001
                    pass

        rc = getattr(self.result, "returncode", None)
        return rc if rc is not None else 0


def run_ptui(runner, kind: str = "exploit", subject: str = "") -> int:
    """Open the PentestGPT-style interface over ``runner``; return its exit code."""
    session = VeloraSession(runner, kind=kind, subject=subject)
    return session.main()
