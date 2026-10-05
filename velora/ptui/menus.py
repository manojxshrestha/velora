"""Tab-completed command menus for the PentestGPT-style interface.

Mirrors PentestGPT's ``utils/task_handler.py``: a main-task verb prompt and a
local (sub-task) verb prompt, both with per-verb rich descriptions, an
``Invalid task, try again.`` re-prompt loop, and a printable help page.
Verbs are PentestGPT's exact set; semantics map onto velora's existing
workflow (see ``velora.ptui.session``).
"""

from __future__ import annotations

from typing import ClassVar

from prompt_toolkit.completion import Completer, Completion
from prompt_toolkit.formatted_text import HTML
from prompt_toolkit.shortcuts import prompt


class localTaskCompleter(Completer):
    tasks: ClassVar[list] = [
        "discuss",    # discuss with Velora on the local task
        "brainstorm", # let Velora brainstorm on the local task
        "help",       # show the help page (for this local task)
        "google",     # search on Google
        "continue",   # quit the local task and continue the main task
    ]

    task_meta: ClassVar[dict] = {
        "discuss": HTML("Discuss with <b>Velora</b> about this local task."),
        "brainstorm": HTML(
            "Let <b>Velora</b> brainstorm on the local task for all the possible solutions."
        ),
        "help": HTML("Show the help page for this local task."),
        "google": HTML("Search on Google."),
        "continue": HTML("Quit the local task and continue the previous testing."),
    }

    task_details = """
Below are the available tasks:
    - discuss: Discuss with Velora about this local task.
    - brainstorm: Let Velora brainstorm on the local task for all the possible solutions.
    - help: Show the help page for this local task.
    - google: Search on Google.
    - quit: Quit the local task and continue the testing."""

    def get_completions(self, document, complete_event):
        word = document.get_word_before_cursor()
        for task in self.tasks:
            if task.startswith(word):
                yield Completion(
                    task,
                    start_position=-len(word),
                    display=task,
                    display_meta=self.task_meta.get(task),
                )


class mainTaskCompleter(Completer):
    tasks: ClassVar[list] = [
        "next",
        "more",
        "todo",
        "discuss",
        "google",
        "help",
        "quit",
    ]

    task_meta: ClassVar[dict] = {
        "next": HTML("Go to the next step."),
        "more": HTML("Explain the task with more details."),
        "todo": HTML("Ask <b>Velora</b> for todos."),
        "discuss": HTML("Discuss with <b>Velora</b>."),
        "google": HTML("Search on Google."),
        "help": HTML("Show the help page."),
        "quit": HTML("End the current session."),
    }

    task_details = """
Below are the available tasks:
 - next: Continue to the next step by inputting the test results.
 - more: Explain the previous given task with more details.
 - todo: Ask Velora for the task list and what to do next.
 - discuss: Discuss with Velora. You can ask for help, discuss the task, or give any feedbacks.
 - google: Search your question on Google. The results are automatically parsed by Google.
 - help: Show this help page.
 - quit: End the current session."""

    def get_completions(self, document, complete_event):
        word = document.get_word_before_cursor()
        for task in self.tasks:
            if task.startswith(word):
                yield Completion(
                    task,
                    start_position=-len(word),
                    display=task,
                    display_meta=self.task_meta.get(task),
                )


def main_task_entry(text: str = "> ") -> str:
    """Command prompt with tab-completion; re-prompts on unknown verbs."""
    task_completer = mainTaskCompleter()
    while True:
        result = prompt(text, completer=task_completer)
        if result not in task_completer.tasks:
            print("Invalid task, try again.")
        else:
            return result


def local_task_entry(text: str = "> ") -> str:
    """Sub-task prompt (after ``more``) with tab-completion."""
    task_completer = localTaskCompleter()
    while True:
        result = prompt(text, completer=task_completer)
        if result not in task_completer.tasks:
            print("Invalid task, try again.")
        else:
            return result
