"""Prompt-layer helpers for the PentestGPT-style interface.

Mirrors PentestGPT's ``utils/prompt_select.py`` (GreyDGL/PentestGPT, MIT):
radio-list selection menus, multiline input where Enter inserts a newline and
shift+right-arrow submits, and the ``- N -`` / ``->`` continuation gutter.
"""

from __future__ import annotations

from typing import Any, List, Optional, Tuple

from prompt_toolkit.application import Application
from prompt_toolkit.formatted_text import HTML
from prompt_toolkit.key_binding.defaults import load_key_bindings
from prompt_toolkit.key_binding.key_bindings import KeyBindings, merge_key_bindings
from prompt_toolkit.layout import Layout
from prompt_toolkit.layout.containers import HSplit
from prompt_toolkit.shortcuts import prompt
from prompt_toolkit.widgets import Label, RadioList


def prompt_continuation(width: int, line_number: int, wrap_count: int) -> Any:
    """Continuation gutter: ``->`` before soft wraps, ``- N -`` for hard lines."""
    if wrap_count > 0:
        return " " * (width - 3) + "-> "
    text = f"- {line_number + 1} - ".rjust(width)
    return HTML("<strong>%s</strong>") % text


def prompt_select(title: str = "", values: Optional[List[Tuple[Any, Any]]] = None,
                  style: Any = None, async_: bool = False) -> Any:
    """Radio-list menu: arrows move, shift+right-arrow accepts, Ctrl-D exits."""
    bindings = KeyBindings()

    @bindings.add("c-d")
    def exit_(event):
        event.app.exit()

    @bindings.add("s-right")
    def exit_with_value(event):
        event.app.exit(result=radio_list.current_value)

    radio_list = RadioList(values or [])
    application = Application(
        layout=Layout(HSplit([Label(title), radio_list])),
        key_bindings=merge_key_bindings([load_key_bindings(), bindings]),
        mouse_support=True,
        style=style,
        full_screen=False,
    )

    return application.run_async() if async_ else application.run()


def prompt_ask(text: str, multiline: bool = True) -> str:
    """Prompt where shift+right-arrow always submits.

    Single line: Enter or shift+right-arrow submits.  Multiline: Enter inserts
    a newline and only shift+right-arrow submits.
    """
    kb = KeyBindings()
    if multiline:

        @kb.add("enter")
        def _(event):
            event.current_buffer.insert_text("\n")

    @kb.add("s-right")
    def _(event):
        event.current_buffer.validate_and_handle()

    return prompt(
        text,
        multiline=multiline,
        prompt_continuation=prompt_continuation,
        key_bindings=kb,
    )
