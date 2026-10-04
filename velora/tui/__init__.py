"""
Live curses TUI for scan / exploit runs.

`run_tui` renders the full-screen view around a `TuiRunner` child process;
`RunSpec` describes what to run. Pure render/parse logic lives in
`render.py` (`TuiState`, `pane_rows`, ...) and `logparse.py`.
"""

from velora.tui.render import run_tui
from velora.tui.runner import RunResult, RunSpec, TuiRunner

__all__ = ["run_tui", "RunSpec", "RunResult", "TuiRunner"]
