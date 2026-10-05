"""PentestGPT-style line REPL for velora scan/exploit runs.

Opened by default on a TTY (see ``_run_tui_wrap`` in ``velora.cli``); the
classic curses view stays available via ``--curses``.
"""

from velora.ptui.session import VeloraSession, run_ptui

__all__ = ["VeloraSession", "run_ptui"]
