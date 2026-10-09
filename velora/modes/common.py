"""Stage framework shared by the three modes: registry, grammar, context.

Registry is the single source of truth (finalplan §8.3): stage flags,
--help text, --dry-run output, membership, capability refusals, and graph
defaults are all generated from it. Grammar rules 1-6 (§8.2) are enforced
in select_stages().
"""

from __future__ import annotations

import json
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Sequence, Set, Tuple

EXIT_OK = 0
EXIT_FINDINGS = 1
EXIT_USAGE = 2
EXIT_IO = 3
EXIT_INTERRUPT = 130

_SEVERITY_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


class Capability:
    FULL = "full"
    PARTIAL = "partial"
    UNAVAILABLE = "unavailable"


GUARD_STAGES = ("scope",)

FLAG_BY_STAGE: Dict[str, str] = {
    "static-scan": "scan",
    "dataflow": "dataflow",
}
for _sid in (
    "scope", "auth", "intel", "osint", "ingest", "recon", "asset-model",
    "asset-discovery", "code-model", "surface", "enumerate",
    "service-mapping", "hunt", "hypothesize", "triage", "deepthink",
    "plan", "verify", "exploit", "fix", "rescan", "capture", "validate",
    "search", "report",
):
    FLAG_BY_STAGE.setdefault(_sid, _sid)

LABEL_BY_STAGE: Dict[str, str] = {
    "static-scan": "STATIC SCAN",
    "dataflow": "DATAFLOW / CONTROLFLOW",
    "asset-model": "ASSET MODEL",
    "code-model": "CODE MODEL",
    "asset-discovery": "ASSET DISCOVERY",
    "service-mapping": "SERVICE MAPPING",
    "enumerate": "ENUMERATION",
}
for _sid in FLAG_BY_STAGE:
    LABEL_BY_STAGE.setdefault(_sid, _sid.upper())

ASSET_KIND_BY_STAGE: Dict[str, str] = {
    "ingest": "code", "code-model": "code", "static-scan": "code",
    "dataflow": "code", "fix": "code", "rescan": "code",
    "auth": "network", "intel": "network", "osint": "network",
    "recon": "network", "asset-discovery": "network",
    "service-mapping": "network", "enumerate": "network",
    "exploit": "network", "capture": "network",
}

INPUT_DEP_BY_STAGE: Dict[str, str] = {
    "ingest": "source",
    "asset-model": "source|target",
    "code-model": "source",
    "static-scan": "source",
    "dataflow": "source",
    "auth": "target",
    "intel": "target",
    "osint": "target",
    "recon": "target",
    "asset-discovery": "target",
    "service-mapping": "target",
    "surface": "source|target",
    "enumerate": "source|target",
    "hunt": "source|target",
    "hypothesize": "source|target",
    "plan": "source|target",
    "exploit": "target",
    "fix": "findings",
    "rescan": "findings",
    "validate": "findings",
}

FINDINGS_GATED_STAGES = frozenset({"fix", "rescan", "validate"})

CANONICAL_ORDER: Tuple[str, ...] = (
    "scope", "auth", "intel", "osint", "ingest", "recon", "asset-model",
    "asset-discovery", "code-model", "static-scan", "dataflow", "surface",
    "enumerate", "service-mapping", "hunt", "hypothesize", "triage",
    "deepthink", "plan", "verify", "exploit", "fix", "rescan", "capture",
    "validate", "search", "report",
)
_STAGE_POS: Dict[str, int] = {s: i for i, s in enumerate(CANONICAL_ORDER)}
_STAGE_IDS: Set[str] = set(CANONICAL_ORDER)
_FLAG_TO_STAGE: Dict[str, str] = {f: s for s, f in FLAG_BY_STAGE.items()}

PIPELINES: Dict[str, Tuple[str, ...]] = {
    "whitebox": (
        "scope", "ingest", "asset-model", "code-model", "static-scan",
        "dataflow", "hypothesize", "triage", "plan", "verify", "exploit",
        "fix", "rescan", "validate", "report",
    ),
    "blackbox": (
        "scope", "auth", "recon", "asset-discovery", "surface", "enumerate",
        "service-mapping", "hunt", "triage", "verify", "exploit", "capture",
        "validate", "report",
    ),
    "bughunt": (
        "scope", "auth", "intel", "osint", "recon", "asset-model", "surface",
        "hunt", "triage", "deepthink", "verify", "exploit", "capture",
        "validate", "search", "report",
    ),
}

MATRIX: Dict[str, Dict[str, str]] = {
    "scope": {"whitebox": "yes", "blackbox": "yes", "bughunt": "yes"},
    "auth": {"whitebox": "no", "blackbox": "yes", "bughunt": "yes"},
    "intel": {"whitebox": "no", "blackbox": "optional", "bughunt": "yes"},
    "osint": {"whitebox": "no", "blackbox": "optional", "bughunt": "yes"},
    "ingest": {"whitebox": "yes", "blackbox": "no", "bughunt": "optional"},
    "asset-model": {"whitebox": "yes", "blackbox": "yes", "bughunt": "yes"},
    "code-model": {"whitebox": "yes", "blackbox": "no", "bughunt": "optional"},
    "static-scan": {"whitebox": "yes", "blackbox": "no", "bughunt": "optional"},
    "dataflow": {"whitebox": "yes", "blackbox": "no", "bughunt": "optional"},
    "recon": {"whitebox": "yes", "blackbox": "yes", "bughunt": "yes"},
    "surface": {"whitebox": "yes", "blackbox": "yes", "bughunt": "yes"},
    "enumerate": {"whitebox": "yes", "blackbox": "yes", "bughunt": "optional"},
    "hunt": {"whitebox": "yes", "blackbox": "yes", "bughunt": "yes"},
    "hypothesize": {"whitebox": "yes", "blackbox": "yes", "bughunt": "yes"},
    "triage": {"whitebox": "yes", "blackbox": "yes", "bughunt": "yes"},
    "deepthink": {"whitebox": "yes", "blackbox": "yes", "bughunt": "emph"},
    "plan": {"whitebox": "yes", "blackbox": "yes", "bughunt": "yes"},
    "verify": {"whitebox": "yes", "blackbox": "yes", "bughunt": "yes"},
    "exploit": {"whitebox": "yes", "blackbox": "yes", "bughunt": "yes"},
    "fix": {"whitebox": "emph", "blackbox": "optional", "bughunt": "optional"},
    "rescan": {"whitebox": "emph", "blackbox": "optional", "bughunt": "optional"},
    "capture": {"whitebox": "yes", "blackbox": "yes", "bughunt": "yes"},
    "validate": {"whitebox": "yes", "blackbox": "yes", "bughunt": "emph"},
    "search": {"whitebox": "optional", "blackbox": "optional", "bughunt": "emph"},
    "report": {"whitebox": "yes", "blackbox": "yes", "bughunt": "yes"},
}

EXPLICIT_UNAVAILABLE: Dict[str, Tuple[str, ...]] = {
    "whitebox": (),
    "blackbox": (),
    "bughunt": ("asset-discovery", "service-mapping"),
}

MODE_INPUT_DEP: Dict[str, str] = {
    "whitebox": "source",
    "blackbox": "target",
    "bughunt": "source|target",
}


class GrammarError(Exception):
    def __init__(self, code: int, message: str):
        super().__init__(message)
        self.code = code
        self.message = message


@dataclass(frozen=True)
class StageSpec:
    id: str
    flag: str
    label: str
    asset_kind: str

    @property
    def dest(self) -> str:
        return "stage_" + self.id.replace("-", "_")

    @property
    def dest_no(self) -> str:
        return "nostage_" + self.id.replace("-", "_")

    @property
    def dest_with(self) -> str:
        return "withstage_" + self.id.replace("-", "_")


@dataclass
class ModeSpec:
    id: str
    label: str
    pipeline: Tuple[str, ...]
    membership: Dict[str, str]
    unavailable: Tuple[str, ...]
    stages: Tuple[str, ...]
    mode_input_dep: str

    def stage_spec(self, stage_id: str) -> StageSpec:
        return StageSpec(
            id=stage_id,
            flag=FLAG_BY_STAGE[stage_id],
            label=LABEL_BY_STAGE[stage_id],
            asset_kind=ASSET_KIND_BY_STAGE.get(stage_id, "either"),
        )

    @property
    def guard(self) -> str:
        return "scope"

    @property
    def default_stages(self) -> Tuple[str, ...]:
        return self.pipeline

    def is_flag_selectable(self, stage_id: str) -> bool:
        return stage_id in self.membership

    def valid_stage_list(self) -> str:
        return ", ".join(
            FLAG_BY_STAGE[s] for s in CANONICAL_ORDER if s in self.membership
        )

    def unavailable_stage_list(self) -> str:
        return ", ".join(FLAG_BY_STAGE[s] for s in self.unavailable)


@dataclass
class InputState:
    source: Optional[str] = None
    target: Optional[str] = None
    findings: Optional[int] = None

    @property
    def has_source(self) -> bool:
        return bool(self.source)

    @property
    def has_target(self) -> bool:
        return bool(self.target)


@dataclass
class GrammarOptions:
    positive: Tuple[str, ...] = ()
    only: Optional[Tuple[str, ...]] = None
    until: Optional[str] = None
    from_: Optional[str] = None
    skip: Tuple[str, ...] = ()
    with_: Tuple[str, ...] = ()
    no: Tuple[str, ...] = ()


@dataclass
class StageSelection:
    plan: List[str]
    na: List[str] = field(default_factory=list)
    conditional: List[str] = field(default_factory=list)
    explicit: List[str] = field(default_factory=list)
    shaped: bool = False


def build_mode_specs() -> Dict[str, ModeSpec]:
    specs: Dict[str, ModeSpec] = {}
    for mode, pipeline in PIPELINES.items():
        membership: Dict[str, str] = {}
        unavailable: List[str] = []
        for stage in CANONICAL_ORDER:
            if stage in GUARD_STAGES:
                if stage in pipeline:
                    membership[stage] = "default"
                continue
            if stage in pipeline:
                membership[stage] = "default"
                continue
            cell = MATRIX.get(stage, {}).get(mode)
            if cell is None:
                if stage in EXPLICIT_UNAVAILABLE[mode]:
                    unavailable.append(stage)
                    membership[stage] = "unavailable"
                continue
            if cell == "no":
                unavailable.append(stage)
                membership[stage] = "unavailable"
            else:
                membership[stage] = "off"
        specs[mode] = ModeSpec(
            id=mode,
            label=mode.upper(),
            pipeline=pipeline,
            membership=membership,
            unavailable=tuple(unavailable),
            stages=tuple(s for s in CANONICAL_ORDER if s in membership),
            mode_input_dep=MODE_INPUT_DEP[mode],
        )
    return specs


MODE_SPECS: Dict[str, ModeSpec] = build_mode_specs()


def _missing_inputs(stage: str, inputs: InputState, known: bool) -> List[str]:
    dep = INPUT_DEP_BY_STAGE.get(stage)
    if not dep:
        return []
    missing: List[str] = []
    alternatives = dep.split("|")
    satisfied = False
    for alt in alternatives:
        if alt == "source" and inputs.has_source:
            satisfied = True
        elif alt == "target" and inputs.has_target:
            satisfied = True
        elif alt == "findings":
            if not known:
                satisfied = True
            elif inputs.findings:
                satisfied = True
    if not satisfied:
        missing.extend(alternatives)
    return missing


def _input_hint(alt: str) -> str:
    if alt == "source":
        return "--source"
    if alt == "target":
        return "a target (positional or --target)"
    return "findings"


def _resolve_stage_token(token: str) -> str:
    if token in _STAGE_IDS:
        return token
    return _FLAG_TO_STAGE.get(token, token)


def _reject_invalid(mode: ModeSpec, stages: Sequence[str], referring: str) -> None:
    for stage in stages:
        if stage in GUARD_STAGES:
            raise GrammarError(
                EXIT_USAGE,
                f"'{FLAG_BY_STAGE[stage]}' is a guard stage — it always runs "
                f"first and is not stage-selectable",
            )
        if stage not in mode.membership:
            raise GrammarError(
                EXIT_USAGE,
                f"'{FLAG_BY_STAGE.get(stage, stage)}' is not a stage of "
                f"mode '{mode.id}' (from {referring}) — valid stages: "
                f"{mode.valid_stage_list()}",
            )


def _resolve_or_rule2(stage: str, session_ok: bool) -> None:
    if not session_ok:
        raise GrammarError(
            EXIT_FINDINGS,
            f"--from {FLAG_BY_STAGE.get(stage, stage)}: no prior session "
            f"artifacts for this stage — run --dry-run to see the plan / "
            f"run without --from first",
        )


def select_stages(
    mode: ModeSpec,
    opts: GrammarOptions,
    inputs: InputState,
    session_ok: bool = False,
    ignore_na: bool = False,
) -> StageSelection:
    opts = GrammarOptions(
        positive=tuple(_resolve_stage_token(t) for t in opts.positive),
        only=(
            tuple(_resolve_stage_token(t) for t in opts.only)
            if opts.only is not None else None
        ),
        until=_resolve_stage_token(opts.until) if opts.until else None,
        from_=_resolve_stage_token(opts.from_) if opts.from_ else None,
        skip=tuple(_resolve_stage_token(t) for t in opts.skip),
        with_=tuple(_resolve_stage_token(t) for t in opts.with_),
        no=tuple(_resolve_stage_token(t) for t in opts.no),
    )
    explicit: List[str] = []
    shaped = bool(
        opts.only is not None
        or opts.until is not None
        or opts.from_ is not None
        or opts.skip
        or opts.with_
    )

    for stage in opts.positive:
        if stage not in mode.membership:
            _reject_invalid(mode, [stage], "--" + FLAG_BY_STAGE.get(stage, stage))
    if opts.positive and (
        opts.only is not None
        or opts.until is not None
        or opts.from_ is not None
        or opts.skip
        or opts.with_
    ):
        raise GrammarError(
            EXIT_USAGE,
            "positive stage flags form an exact list and cannot combine with "
            "--only/--until/--from/--skip/--with-* (shape the default graph "
            "instead, or add/drop stages in the list itself)",
        )

    if opts.only is not None:
        _reject_invalid(mode, opts.only, "--only")
        plan = [s for s in CANONICAL_ORDER if s in set(opts.only)]
        explicit.extend(plan)
        selection = StageSelection(plan=plan, explicit=list(dict.fromkeys(explicit)), shaped=True)
    elif opts.positive:
        plan = [s for s in CANONICAL_ORDER if s in set(opts.positive)]
        explicit.extend(plan)
        selection = StageSelection(plan=plan, explicit=list(dict.fromkeys(explicit)))
    else:
        _reject_invalid(mode, opts.skip, "--skip/--no-*")
        _reject_invalid(mode, opts.with_, "--with-*")
        if opts.until is not None:
            _reject_invalid(mode, [opts.until], "--until")
        if opts.from_ is not None:
            _reject_invalid(mode, [opts.from_], "--from")
            _resolve_or_rule2(opts.from_, session_ok)

        base: List[str] = list(mode.pipeline)
        if opts.from_ is not None:
            cut = _STAGE_POS[opts.from_]
            base = [s for s in base if _STAGE_POS[s] >= cut]
        if opts.until is not None:
            cap = _STAGE_POS[opts.until]
            base = [s for s in base if _STAGE_POS[s] <= cap]
        if opts.with_:
            base.extend(s for s in opts.with_ if s not in base)
            base.sort(key=lambda s: _STAGE_POS[s])
            explicit.extend(opts.with_)
        drop = set(opts.skip) | set(opts.no)
        plan = [s for s in base if s not in drop]
        selection = StageSelection(plan=plan, explicit=list(dict.fromkeys(explicit)), shaped=shaped)

    _reject_invalid(
        mode,
        [s for s in selection.explicit if s not in set(opts.skip)],
        "stage flag",
    )

    for stage in selection.explicit:
        if mode.membership.get(stage) == "unavailable":
            raise GrammarError(
                EXIT_USAGE,
                f"stage '{FLAG_BY_STAGE[stage]}' is not available for mode "
                f"'{mode.id}': engine/adapter unavailable for asset kind "
                f"'{ASSET_KIND_BY_STAGE.get(stage, 'either')}'"
                + (
                    f" (unavailable stages: {mode.unavailable_stage_list()})"
                    if mode.unavailable
                    else ""
                ),
            )
        missing = _missing_inputs(stage, inputs, known=False)
        hard_missing = [m for m in missing if m != "findings"]
        if hard_missing:
            raise GrammarError(
                EXIT_FINDINGS,
                f"stage '{FLAG_BY_STAGE[stage]}' requires "
                + " or ".join(_input_hint(m) for m in hard_missing),
            )

    na: List[str] = []
    conditional: List[str] = []
    explicit_set = set(selection.explicit)
    kept: List[str] = []
    for stage in selection.plan:
        if stage in explicit_set or stage in GUARD_STAGES:
            kept.append(stage)
            continue
        dep = INPUT_DEP_BY_STAGE.get(stage, "")
        if "findings" in dep.split("|") and dep == "findings":
            conditional.append(stage)
            kept.append(stage)
            continue
        if ignore_na:
            kept.append(stage)
            continue
        missing = _missing_inputs(stage, inputs, known=False)
        if missing:
            na.append(stage)
            continue
        kept.append(stage)
    selection.plan = kept
    selection.na = na
    selection.conditional = conditional
    return selection


def check_dynamic_inputs(
    mode: ModeSpec, selection: StageSelection, inputs: InputState
) -> None:
    if inputs.findings:
        return
    for stage in selection.plan:
        if stage in FINDINGS_GATED_STAGES and stage in selection.explicit:
            raise GrammarError(
                EXIT_FINDINGS,
                f"stage '{FLAG_BY_STAGE[stage]}' requires findings — none "
                f"produced so far",
            )


def _registered_options(parser) -> Set[str]:
    return set(getattr(parser, "_option_string_actions", {}))


def add_stage_flags(parser, mode: ModeSpec) -> None:
    taken = _registered_options(parser)
    group = parser.add_argument_group(
        "stage selection",
        "Three-level grammar (§8.2): ranges shape the default graph; "
        "positive flags form an exact list; --with-* adds off-default stages.",
    )
    group.add_argument("--until", metavar="STAGE", default=None,
                       help="run up to and including STAGE")
    group.add_argument("--from", dest="from_", metavar="STAGE", default=None,
                       help="resume from STAGE; earlier artifacts loaded from session")
    group.add_argument("--only", metavar="STAGE[,…]", default=None,
                       help="exactly these stages, in canonical graph order")
    group.add_argument("--skip", metavar="STAGE[,…]", default=None,
                       help="default graph minus these stages")
    group.add_argument("--dry-run", action="store_true",
                       help="print the resolved plan (with n/a) and exit 0")
    group.add_argument("--list-stages", action="store_true",
                       help="list this mode's stages with membership and exit 0")
    ui = parser.add_argument_group(
        "ui",
        "Interactive views open on a TTY by default; pipes stay batch "
        "(§8.7). VELORA_TUI=0 also disables.",
    )
    if "--no-tui" not in taken:
        ui.add_argument("--no-tui", action="store_true",
                        help="Run plain even on a terminal (TTY default: live "
                             "interactive view; pipes/redirects always stay "
                             "plain). VELORA_TUI=0 also disables.")
    if "--curses" not in taken:
        ui.add_argument("--curses", action="store_true",
                        help="Open the classic curses TUI instead of the "
                             "default interactive line interface (TTY only)")
    if "--progress" not in taken:
        ui.add_argument("--progress", default=None, choices=["json"],
                        metavar="json",
                        help="Machine-readable NDJSON stage events on stderr "
                             "(stage_start/stage_end/stage_skip)")
    for stage in CANONICAL_ORDER:
        if stage in GUARD_STAGES:
            continue
        spec = mode.stage_spec(stage)
        if spec.id not in mode.membership:
            continue
        for option, dest, help_text in (
            (f"--{spec.flag}", spec.dest, f"run {spec.label}"),
            (f"--no-{spec.flag}", spec.dest_no, f"drop {spec.label} from the default graph"),
            (f"--with-{spec.flag}", spec.dest_with, f"default graph plus {spec.label} (off-default)"),
        ):
            if option in taken:
                continue
            if option.startswith("--no-"):
                help_text += " (use --skip to drop when the name is inherited)"
            group.add_argument(option, dest=dest, action="store_true", help=help_text)


def grammar_options_from_ns(ns, mode: ModeSpec) -> GrammarOptions:
    def split(value) -> Optional[Tuple[str, ...]]:
        if value is None:
            return None
        parts = tuple(p.strip() for p in str(value).split(",") if p.strip())
        return parts or tuple()

    positive: List[str] = []
    no: List[str] = []
    with_: List[str] = []
    for stage in CANONICAL_ORDER:
        if stage in GUARD_STAGES:
            continue
        spec = mode.stage_spec(stage)
        if getattr(ns, spec.dest, False):
            positive.append(stage)
        if getattr(ns, spec.dest_no, False):
            no.append(stage)
        if getattr(ns, spec.dest_with, False):
            with_.append(stage)
    return GrammarOptions(
        positive=tuple(positive),
        only=(
            tuple(_resolve_stage_token(p) for p in only_parts)
            if (only_parts := split(getattr(ns, "only", None))) is not None
            else None
        ),
        until=(
            _resolve_stage_token(ns.until) if getattr(ns, "until", None) else None
        ),
        from_=(
            _resolve_stage_token(ns.from_) if getattr(ns, "from_", None) else None
        ),
        skip=tuple(_resolve_stage_token(p) for p in (split(getattr(ns, "skip", None)) or tuple())),
        with_=tuple(with_),
        no=tuple(no),
    )


def resolve_severity_flags(args) -> None:
    severity = getattr(args, "severity", None)
    if severity:
        if getattr(args, "min_severity", None) is None:
            args.min_severity = severity
        if getattr(args, "fail_on", None) is None:
            args.fail_on = severity
    if getattr(args, "fail_on", None) is None:
        args.fail_on = "high"


def severity_rank(name: str) -> int:
    return _SEVERITY_RANK.get((name or "").lower(), -1)


def gate_exit_code(findings, fail_on: Optional[str]) -> int:
    if not fail_on:
        return EXIT_OK
    threshold = severity_rank(fail_on)
    if threshold < 0:
        return EXIT_OK
    for finding in findings or ():
        sev = getattr(finding, "severity", None) or (
            finding.get("severity") if isinstance(finding, dict) else None
        )
        if sev is not None and severity_rank(str(sev)) >= threshold:
            return EXIT_FINDINGS
    return EXIT_OK


# ---------------------------------------------------------------------------
# Shared stage-loop machinery (all three mode executors)
# ---------------------------------------------------------------------------

DEFAULT_GOAL = (
    "Compromise the target: read a protected secret, execute a command, or "
    "modify server state -- and prove it with observed output."
)


class _NaSentinel:
    __slots__ = ()


NA = _NaSentinel()


def flag_of(stage: str) -> str:
    return FLAG_BY_STAGE.get(stage, stage)


def runtime_na(ctx, stage: str, reason: str) -> None:
    """Announce a run-time n/a and persist it in the session (§8.5)."""
    ctx.eprint(f"[velora] n/a: {LABEL_BY_STAGE.get(stage, stage)} ({reason})")
    if ctx.session is not None:
        existing = list(ctx.session.data.get("na") or [])
        if stage not in existing:
            existing.append(stage)
            ctx.session.record_na(ctx.mode, ctx.inputs, existing)


def ai_enabled(ctx) -> bool:
    return bool(getattr(ctx.args, "ai", False))


def llm_configured():
    from velora.sil.llm_client import LLMConfig

    config = LLMConfig.from_env()
    if config.base_url and config.model:
        return config
    return None


def working_set(ctx) -> List[dict]:
    """Triage-ranked findings when available, else everything recorded."""
    if ctx.session is not None:
        triage = ctx.session.read_json("triage.json", None)
        if isinstance(triage, dict) and isinstance(triage.get("findings"), list):
            return list(triage["findings"])
    return [f for f in ctx.findings if isinstance(f, dict)]


def run_oracle(command: str) -> Dict[str, object]:
    import subprocess

    try:
        proc = subprocess.run(
            command, shell=True, timeout=60, capture_output=True,
            text=True, errors="replace",
        )
    except subprocess.TimeoutExpired:
        return {"command": command, "rc": None, "error": "timeout"}
    except OSError as exc:
        return {"command": command, "rc": None, "error": str(exc)}
    evidence = (proc.stdout or proc.stderr or "").strip()[:120]
    return {"command": command, "rc": proc.returncode, "evidence": evidence}


def preload_findings(ctx, producer_stage: str) -> bool:
    """Load stored findings when `producer_stage` will not run this time.

    Returns whether the producer will run (findings then arrive live instead).
    """
    plan = list(ctx.selection.plan) if ctx.selection is not None else []
    rerun = bool(getattr(ctx.args, "from_", None))
    committed = (
        set(ctx.session.completed_stages()) if ctx.session is not None else set()
    )
    will_run = producer_stage in plan and (
        rerun or producer_stage not in committed
    )
    if not will_run and ctx.session is not None:
        stored = ctx.session.read_json("findings.json", [])
        if isinstance(stored, list) and stored:
            ctx.findings.extend(stored)
    return will_run


def run_stage_once(ctx, stage: str, runners: Dict[str, object], *,
                   after_stage=None) -> str:
    """Gate + run + commit one stage: no banner, no resume-skip logic.

    Findings-gated stages without explicit selection run n/a when zero
    findings; an unknown stage commits an empty artifact (loud in modes
    listing via the engine-status column). Callers own banners and the
    `--from`/committed-stage skip decisions. Returns the stage status
    ("ok" | "na") for machine-readable progress events.
    """
    explicit = set(ctx.selection.explicit) if ctx.selection else set()
    if (
        stage in FINDINGS_GATED_STAGES
        and stage not in explicit
        and not ctx.inputs.findings
    ):
        runtime_na(ctx, stage, "missing findings")
        return "na"
    runner = runners.get(stage)
    if runner is None:
        ctx.commit_stage(stage)
        return "ok"
    artifacts = runner(ctx)
    ctx.inputs.findings = len(ctx.findings)
    status = "na"
    if artifacts is not NA:
        ctx.commit_stage(stage, artifacts if isinstance(artifacts, dict) else None)
        status = "ok"
    if after_stage is not None:
        after_stage(ctx, stage)
    return status


def execute_stage_loop(ctx, runners: Dict[str, object], *, after_stage=None,
                       stages: Optional[Sequence[str]] = None) -> None:
    """Run the resolved plan: banners, findings-gating, commit-per-stage.

    `runners` maps stage id → callable(ctx) returning artifact payloads (a
    dict of filename → object), `NA` (skip commit; n/a already announced), or
    None. `after_stage(ctx, stage)` fires after each commit (e.g. the
    findings-input re-check after the producing stage). `stages` overrides
    the plan (used by the bughunt loop driver); default is ctx.selection.plan.
    """
    plan = (
        list(stages)
        if stages is not None
        else (list(ctx.selection.plan) if ctx.selection is not None else [])
    )
    rerun = bool(getattr(ctx.args, "from_", None))
    committed_before = (
        set(ctx.session.completed_stages()) if ctx.session is not None else set()
    )
    ctx.inputs.findings = len(ctx.findings)
    total = len(plan)
    progress_json = getattr(ctx.args, "progress", None) == "json"

    def _progress_event(payload: Dict[str, object]) -> None:
        ctx.eprint(json.dumps(payload, separators=(",", ":"), default=str))

    for index, stage in enumerate(plan, 1):
        if stage in committed_before and not rerun and stage != "report":
            if progress_json:
                _progress_event({"event": "stage_skip", "stage": stage,
                                 "reason": "already committed"})
            elif stage == "scope":
                ctx.eprint(
                    f"[velora] stage {index}/{total}: {LABEL_BY_STAGE.get(stage, stage)} "
                    "-- already committed (guard stage; start a fresh "
                    "session to re-run it)"
                )
            else:
                ctx.eprint(
                    f"[velora] stage {index}/{total}: {LABEL_BY_STAGE.get(stage, stage)} "
                    f"-- already committed, skipping (re-run with --from "
                    f"{flag_of(stage)})"
                )
            if stage not in ctx.completed:
                ctx.completed.append(stage)
            continue
        if progress_json:
            _progress_event({"event": "stage_start", "stage": stage,
                             "label": LABEL_BY_STAGE.get(stage, stage),
                             "index": index, "total": total})
        else:
            ctx.eprint(
                f"[velora] stage {index}/{total}: {LABEL_BY_STAGE.get(stage, stage)}"
            )
        started = time.monotonic()
        try:
            status = run_stage_once(ctx, stage, runners,
                                    after_stage=after_stage)
        except BaseException:
            if progress_json:
                _progress_event({
                    "event": "stage_end", "stage": stage, "status": "error",
                    "seconds": round(time.monotonic() - started, 3),
                })
            raise
        if progress_json:
            _progress_event({
                "event": "stage_end", "stage": stage, "status": status,
                "seconds": round(time.monotonic() - started, 3),
            })


def stage_exploit(ctx) -> object:
    """Shared EXPLOIT runner: LLM agent over guidance, gated on --ai."""
    if not ai_enabled(ctx):
        runtime_na(ctx, "exploit", "AI stage disabled (pass --ai)")
        return NA
    config = llm_configured()
    if config is None:
        raise GrammarError(
            EXIT_FINDINGS,
            "exploit: set VELORA_LLM_BASE_URL and VELORA_LLM_MODEL (LLM "
            "endpoint not configured)",
        )
    from velora.cli import _select_findings
    from velora.sil.llm_exploit import (
        exploit_agentic,
        guidance_from_finding,
        local_exec_tool,
        target_hosts,
    )

    target = ctx.inputs.target or ""
    goal = getattr(ctx.args, "goal", None) or DEFAULT_GOAL
    selected = _select_findings(working_set(ctx))
    leads = [guidance_from_finding(f) for f in selected]
    guidance = None
    if leads:
        provenance = (
            "symbolic"
            if any(l.get("provenance") == "symbolic" for l in leads)
            else "llm"
        )
        guidance = {"leads": leads, "provenance": provenance}
    is_solved = None
    success_check = getattr(ctx.args, "success_check", None)
    if success_check:
        def is_solved() -> bool:
            return run_oracle(success_check).get("rc") == 0
    max_steps = getattr(ctx.args, "max_steps", None) or 40
    config.exploit_max_steps = max_steps
    exec_timeout = getattr(ctx.args, "exec_timeout", None) or 120
    exec_tool = local_exec_tool(
        timeout=exec_timeout, allow_hosts=target_hosts(target)
    )
    result = exploit_agentic(
        f"Target: {target}\n\nObjective: {goal}",
        config,
        exec_tool=exec_tool,
        guidance=guidance,
        is_solved=is_solved,
        max_steps=max_steps,
    )
    summary = {
        "target": target,
        "solved": bool(result.solved),
        "steps": result.steps,
        "reason": result.reason,
        "guided": guidance is not None,
        "provenance": (guidance or {}).get("provenance"),
        "leads": len(leads),
    }
    trace = {
        "model": config.model,
        "summary": summary,
        "transcript": result.transcript,
    }
    trace_out = getattr(ctx.args, "trace_out", None)
    if trace_out:
        try:
            Path(trace_out).write_text(json.dumps(trace, indent=2, default=str))
        except OSError as exc:
            raise GrammarError(
                EXIT_FINDINGS, f"--trace-out: cannot write {trace_out}: {exc}"
            ) from exc
    return {"exploit.json": summary, "trace.json": trace}


def stage_triage(ctx) -> Dict[str, object]:
    """Rank by (severity, confidence), de-duplicate, keep the best of each."""

    def rank(finding: dict):
        return (
            severity_rank(str(finding.get("severity") or "")),
            float(finding.get("confidence") or 0),
        )

    ranked = sorted(
        (f for f in ctx.findings if isinstance(f, dict)),
        key=rank, reverse=True,
    )
    seen = set()
    kept: List[dict] = []
    duplicates = 0
    for finding in ranked:
        key = (
            finding.get("cwe_id") or finding.get("cwe"),
            finding.get("type"),
            str(finding.get("location")),
            finding.get("line"),
        )
        if key in seen:
            duplicates += 1
            continue
        seen.add(key)
        kept.append(finding)
    return {
        "triage.json": {
            "kept": len(kept),
            "duplicates": duplicates,
            "findings": kept,
        }
    }


@dataclass
class ModeContext:
    mode: ModeSpec
    args: object
    inputs: InputState = field(default_factory=InputState)
    session_dir: Optional[str] = None
    selection: Optional[StageSelection] = None
    findings: List[object] = field(default_factory=list)
    completed: List[str] = field(default_factory=list)
    session: Optional["Session"] = None

    def commit_stage(self, stage: str, artifacts: Optional[Dict[str, object]] = None) -> None:
        if self.session is not None:
            self.session.commit_stage(self.mode, self.inputs, stage, artifacts)
        if stage not in self.completed:
            self.completed.append(stage)

    def add_findings(self, findings: List[object]) -> None:
        self.findings.extend(findings)
        if self.session is not None:
            self.session.append_findings(list(findings))

    def eprint(self, message: str) -> None:
        print(message, file=sys.stderr)

    def announce_na(self) -> None:
        if self.selection is None:
            return
        for stage in self.selection.na:
            self.eprint(
                f"[velora] n/a: {LABEL_BY_STAGE[stage]} (missing "
                f"{_input_hint(INPUT_DEP_BY_STAGE.get(stage, 'input').split('|')[0])})"
            )

    def exit_code(self) -> int:
        resolve_severity_flags(self.args)
        return gate_exit_code(self.findings, getattr(self.args, "fail_on", None))


ENGINE_STATUS_BY_STAGE: Dict[str, str] = {
    "scope": "exists (scope object, target allowlist)",
    "auth": "exists (active/session.py: refs-only jars + scripted flows)",
    "intel": "partial (header/DNS fingerprint)",
    "osint": "partial (TLS certificate + DNS; no CT/search feeds)",
    "ingest": "exists (frontends, literals, deps + IaC manifests)",
    "asset-model": "exists (assets/graph.py)",
    "code-model": "exists (SIL program)",
    "static-scan": "exists (sil/scanner.py)",
    "dataflow": "exists (analyzers + branch conditions)",
    "recon": "exists (active/recon.py: bounded crawl)",
    "asset-discovery": "exists (recon-derived assets)",
    "surface": "exists (assets/surface.py view)",
    "enumerate": "exists (active/probe.py: OPTIONS/GET)",
    "service-mapping": "full (connect scan + banner + TLS + HEAD probe)",
    "hunt": "partial (static detectors + active/probe.py ≥2 repro)",
    "hypothesize": "partial (candidate engine from static leads)",
    "triage": "exists (severity/confidence ranking)",
    "deepthink": "exists (falsifiable hypotheses + elimination memory)",
    "plan": "new (source-slice guidance enrichment)",
    "verify": "exists (Z3 + probe recheck + --success-check)",
    "exploit": "exists (exploit_agentic)",
    "fix": "exists (llm_fix)",
    "rescan": "exists (verify_fixes)",
    "capture": "full (evidence{}, trace.json -> report timeline)",
    "validate": "exists (independent re-check)",
    "search": "exists (gap analysis + convergence)",
    "report": "exists (markdown/SARIF/bounty + action timeline)",
}

BUDGET_UNIT_BY_MODE: Dict[str, str] = {
    "whitebox": "LLM steps for AI stages (static work free)",
    "blackbox": "HTTP requests (default cap)",
    "bughunt": "LLM steps (default 100)",
}
BUDGET_DEFAULT_BY_MODE: Dict[str, Optional[int]] = {
    "whitebox": None,
    "blackbox": 500,
    "bughunt": 100,
}

DEFAULT_SESSION_SUBDIR = ".velora"


def resolve_inputs(
    mode: ModeSpec,
    args,
    session_inputs: Optional[InputState] = None,
) -> InputState:
    session_inputs = session_inputs or InputState()
    source = getattr(args, "source", None) or session_inputs.source
    target = (
        getattr(args, "target_alias", None)
        or getattr(args, "target", None)
        or session_inputs.target
    )
    return InputState(source=source, target=target)


def check_mode_inputs(mode: ModeSpec, inputs: InputState) -> None:
    dep = mode.mode_input_dep
    if dep == "source" and not inputs.has_source:
        raise GrammarError(
            EXIT_FINDINGS,
            "missing required input: --source PATH (resolves CLI → session "
            "→ exit 1)",
        )
    if dep == "target" and not inputs.has_target:
        raise GrammarError(
            EXIT_FINDINGS,
            "missing required input: TARGET or --target URL (resolves CLI "
            "→ session → exit 1)",
        )
    if dep == "source|target" and not (inputs.has_source or inputs.has_target):
        raise GrammarError(
            EXIT_FINDINGS,
            "missing required input: --source PATH and/or TARGET (resolves "
            "CLI → session → exit 1)",
        )


def format_plan(
    mode: ModeSpec,
    selection: StageSelection,
    inputs: InputState,
    args,
    session_dir: Optional[str] = None,
    na_evaluated: bool = True,
) -> str:
    arrow = " → ".join(LABEL_BY_STAGE[s] for s in selection.plan) or "(empty)"
    lines = [
        f"plan: {mode.id} — {len(selection.plan)} stage(s)",
        f"  session:  {session_dir or f'{DEFAULT_SESSION_SUBDIR}/{mode.id}-<hash>'}",
    ]
    source_disp = inputs.source or "(missing)"
    target_disp = inputs.target or "(none)"
    lines.append(f"  inputs:   source={source_disp}  target={target_disp}")
    if not na_evaluated:
        lines.append(
            "  note:     required input missing — rule-6 n/a gating not "
            "evaluated (full default graph shown; run time resolves "
            "CLI → session → exit 1)"
        )
    budget = getattr(args, "budget", None)
    if budget is None:
        budget_disp = BUDGET_UNIT_BY_MODE[mode.id]
    else:
        budget_disp = f"{budget} {BUDGET_UNIT_BY_MODE[mode.id]}"
    lines.append(f"  budget:   {budget_disp}")
    lines.append(f"  stages:   {arrow}")
    if selection.na:
        for stage in selection.na:
            dep = INPUT_DEP_BY_STAGE.get(stage, "input")
            hint = _input_hint(dep.split("|")[0])
            lines.append(f"  n/a:      {LABEL_BY_STAGE[stage]} (missing {hint})")
    if selection.conditional:
        names = ", ".join(LABEL_BY_STAGE[s] for s in selection.conditional)
        lines.append(f"  conditional (n/a if zero findings): {names}")
    unavailable_default = [
        s for s in selection.plan if mode.membership.get(s) == "unavailable"
    ]
    if unavailable_default:
        lines.append(
            "  capability: BLOCKED — default stages unavailable: "
            + ", ".join(FLAG_BY_STAGE[s] for s in unavailable_default)
        )
    else:
        lines.append("  capability: all planned stages available (full/partial)")
    lines.append(
        "  run nothing (dry-run): stage banners would print on stderr; "
        "artifacts on stdout"
    )
    return "\n".join(lines)


def format_stage_list(mode: ModeSpec, as_json: bool = False) -> str:
    if as_json:
        import json

        payload = {
            "mode": mode.id,
            "default": list(mode.pipeline),
            "stages": [
                {
                    "id": s,
                    "flag": FLAG_BY_STAGE[s],
                    "label": LABEL_BY_STAGE[s],
                    "membership": mode.membership[s],
                    "engine": ENGINE_STATUS_BY_STAGE.get(s, ""),
                }
                for s in CANONICAL_ORDER
                if s in mode.membership
            ],
        }
        return json.dumps(payload, indent=2)
    lines = [f"stages: {mode.id} (default ●, off-default ○, unavailable –)"]
    for stage in CANONICAL_ORDER:
        if stage not in mode.membership:
            continue
        mark = {"default": "●", "off": "○", "unavailable": "–"}[mode.membership[stage]]
        lines.append(
            f"  {mark} {FLAG_BY_STAGE[stage]:<18} {LABEL_BY_STAGE[stage]:<24} "
            f"{ENGINE_STATUS_BY_STAGE.get(stage, '')}"
        )
    return "\n".join(lines)


def format_modes_overview(as_json: bool = False) -> str:
    order = list(PIPELINES)
    if as_json:
        import json

        payload = {
            mode: [
                {
                    "id": s,
                    "label": LABEL_BY_STAGE[s],
                    "membership": spec.membership[s],
                    "engine": ENGINE_STATUS_BY_STAGE.get(s, ""),
                }
                for s in CANONICAL_ORDER
                if s in spec.membership
            ]
            for mode, spec in MODE_SPECS.items()
        }
        return json.dumps(payload, indent=2)
    header = f"{'stage':<24}" + "".join(f"{m:>10}" for m in order) + "  engine"
    lines = [
        "velora mode graphs (● default, ○ off-default, – unavailable, "
        "· not in this mode)",
        header,
    ]
    for stage in CANONICAL_ORDER:
        cells = ""
        known = False
        for mode in order:
            membership = MODE_SPECS[mode].membership.get(stage)
            if membership is None:
                cells += f"{'·':>10}"
            else:
                known = True
                mark = {"default": "●", "off": "○", "unavailable": "–"}[membership]
                cells += f"{mark:>10}"
        if not known:
            continue
        lines.append(f"{LABEL_BY_STAGE[stage]:<24}{cells}  {ENGINE_STATUS_BY_STAGE.get(stage, '')}")
    return "\n".join(lines)


def mode_help_epilog(mode: ModeSpec) -> str:
    lines = [f"stage graph for {mode.id} (default ●, off ○, unavailable –):"]
    for stage in CANONICAL_ORDER:
        if stage not in mode.membership:
            continue
        mark = {"default": "●", "off": "○", "unavailable": "–"}[mode.membership[stage]]
        lines.append(
            f"  {mark} {FLAG_BY_STAGE[stage]:<18} {ENGINE_STATUS_BY_STAGE.get(stage, '')}"
        )
    lines.append("")
    lines.append("levels: no stage flags = default graph · --until/--from/--only = ranges")
    lines.append("        --scan… positive flags = exact list · --with-* adds off-default")
    return "\n".join(lines)


def run_mode_shell(mode_id: str, args, executor=None) -> int:
    from velora.modes.session import Session, resolve_session_path

    mode = MODE_SPECS[mode_id]
    if getattr(args, "list_stages", False):
        print(format_stage_list(mode, as_json=getattr(args, "format", None) == "json"))
        return EXIT_OK
    session: Optional[Session] = None
    try:
        resolve_severity_flags(args)
        dry = bool(getattr(args, "dry_run", False))
        scope = list(getattr(args, "scope", None) or [])
        inputs = resolve_inputs(mode, args)
        session_path = resolve_session_path(args, mode, inputs, scope)
        session = Session.open(session_path)
        if session is not None and session.exists:
            inputs = session.merge_inputs(inputs)
        opts = grammar_options_from_ns(args, mode)
        mode_input_ok = True
        try:
            check_mode_inputs(mode, inputs)
        except GrammarError:
            mode_input_ok = False
        selection = select_stages(
            mode,
            opts,
            inputs,
            session_ok=bool(session and session.has_completed()),
            ignore_na=dry and not mode_input_ok,
        )
        if not dry and not mode_input_ok:
            check_mode_inputs(mode, inputs)
    except GrammarError as exc:
        print(f"velora: error: {exc.message}", file=sys.stderr)
        return exc.code
    if dry:
        print(
            format_plan(
                mode,
                selection,
                inputs,
                args,
                str(session.path) if session is not None else None,
                na_evaluated=mode_input_ok,
            )
        )
        return EXIT_OK
    if executor is None:
        print(
            "velora: error: stage engines not wired yet (Phase 1e)",
            file=sys.stderr,
        )
        return EXIT_USAGE
    ctx = ModeContext(
        mode=mode,
        args=args,
        inputs=inputs,
        session_dir=str(session.path) if session is not None else None,
        selection=selection,
        session=session,
    )
    try:
        if session is not None:
            session.acquire_lock()
            session.record_inputs(mode, inputs)
            session.record_na(mode, inputs, selection.na)
        ctx.announce_na()
        executor(ctx)
    except GrammarError as exc:
        print(f"velora: error: {exc.message}", file=sys.stderr)
        return exc.code
    except KeyboardInterrupt:
        completed = ctx.completed or [selection.plan[0]]
        resume_from = _next_stage_after(selection.plan, completed)
        print(
            "\ninterrupted -- completed stages stay committed; continue with "
            f"--from {FLAG_BY_STAGE.get(resume_from, resume_from)} (exit 130)",
            file=sys.stderr,
        )
        return EXIT_INTERRUPT
    finally:
        if session is not None:
            session.release_lock()
    floor_rank = severity_rank(getattr(args, "min_severity", None) or "low")
    gated = []
    for finding in ctx.findings:
        sev = getattr(finding, "severity", None) or (
            finding.get("severity") if isinstance(finding, dict) else None
        )
        if severity_rank(str(sev or "")) >= floor_rank:
            gated.append(finding)
    code = gate_exit_code(gated, getattr(args, "fail_on", None))
    if code == EXIT_OK and getattr(ctx, "no_patch", False):
        return EXIT_FINDINGS
    if code == EXIT_OK and getattr(ctx, "scan_errors", None):
        return EXIT_IO
    return code


def _next_stage_after(plan: Sequence[str], completed: Sequence[str]) -> str:
    for stage in plan:
        if stage not in completed:
            return stage
    return plan[-1] if plan else "report"
