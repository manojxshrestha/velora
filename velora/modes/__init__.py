"""Three-mode framework: whitebox / blackbox / bughunt stage pipelines."""

from velora.modes.common import (
    CANONICAL_ORDER,
    EXIT_FINDINGS,
    EXIT_INTERRUPT,
    EXIT_IO,
    EXIT_OK,
    EXIT_USAGE,
    Capability,
    GrammarError,
    MODE_SPECS,
    ModeContext,
    ModeSpec,
    StageSelection,
    StageSpec,
    build_mode_specs,
    format_modes_overview,
    select_stages,
)

MODE_IDS = ("whitebox", "blackbox", "bughunt")


def run_mode(mode_id: str, args) -> int:
    if mode_id == "whitebox":
        from velora.modes.whitebox import run
    elif mode_id == "blackbox":
        from velora.modes.blackbox import run
    elif mode_id == "bughunt":
        from velora.modes.bughunt import run
    else:
        print(f"velora: error: unknown mode '{mode_id}'", flush=True)
        return EXIT_USAGE
    return run(args)


__all__ = [
    "EXIT_OK",
    "EXIT_FINDINGS",
    "EXIT_USAGE",
    "EXIT_IO",
    "EXIT_INTERRUPT",
    "Capability",
    "CANONICAL_ORDER",
    "MODE_IDS",
    "MODE_SPECS",
    "StageSpec",
    "ModeSpec",
    "ModeContext",
    "StageSelection",
    "GrammarError",
    "build_mode_specs",
    "select_stages",
    "format_modes_overview",
    "run_mode",
]
