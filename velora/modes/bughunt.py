"""BUGHUNT orchestrator: §4 16-stage default loop graph (Phase 3).

Prefix stages (SCOPE → … → SURFACE) run once through the shared
stage loop; the loop window (HUNT → TRIAGE → DEEPTHINK → VERIFY →
EXPLOIT → CAPTURE → VALIDATE → SEARCH, plus any canonical interlopers
the user added, e.g. --with-plan) iterates until SEARCH converges or a
cap fires (budget / time / max-loop — all normal endings, exit 0 after
the gate); REPORT always runs last.

The hypothesis ledger (``hypotheses.json``) is the loop memory: falsifiable
claims only (``velora.sil.hypotheses``), verdicts recorded after VERIFY,
fingerprints preventing re-derivation of eliminated claims. Subcommands:
``velora bughunt ledger|gaps|resume`` inspect a committed session.
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from typing import Dict, List, Optional

from velora.modes.common import (
    CANONICAL_ORDER,
    EXIT_FINDINGS,
    EXIT_USAGE,
    LABEL_BY_STAGE,
    NA,
    GrammarError,
    ModeContext,
    ai_enabled,
    check_dynamic_inputs,
    execute_stage_loop,
    llm_configured,
    preload_findings,
    run_mode_shell,
    runtime_na,
    run_stage_once,
    stage_exploit,
    stage_triage,
    working_set,
)
from velora.modes.loop import (
    load_ledger,
    loop_iteration_reason,
    loop_record,
    loop_start_reason,
    mark_loop_start,
    reconcile_verdicts,
    seed_ledger,
    stage_deepthink,
    stage_search,
)

# `--budget` in bughunt counts LLM steps (§8.4); HTTP probing rides its own
# fixed request cap so one number never means two units in one run.
HTTP_BUDGET = 500

_POS = {stage: index for index, stage in enumerate(CANONICAL_ORDER)}
_HUNT_POS = _POS["hunt"]
_SEARCH_POS = _POS["search"]


def run(args) -> int:
    if getattr(args, "http_budget", None) is None:
        args.http_budget = HTTP_BUDGET
    return run_mode_shell("bughunt", args, executor=execute)


# ---------------------------------------------------------------------------
# Executor: prefix once → loop window ↺ → REPORT
# ---------------------------------------------------------------------------

def execute(ctx: ModeContext) -> None:
    plan = list(ctx.selection.plan) if ctx.selection is not None else []
    preload_findings(ctx, "hunt")
    ctx.inputs.findings = len(ctx.findings)
    if "hunt" not in plan:
        check_dynamic_inputs(ctx.mode, ctx.selection, ctx.inputs)
    seed_ledger(ctx)

    def after_stage(c: ModeContext, stage: str) -> None:
        if stage == "hunt":
            check_dynamic_inputs(c.mode, c.selection, c.inputs)

    prefix = [s for s in plan if _POS[s] < _HUNT_POS]
    loop_window = [s for s in plan if _HUNT_POS <= _POS[s] <= _SEARCH_POS]
    want_report = "report" in plan

    execute_stage_loop(ctx, _STAGE_RUNNERS, after_stage=after_stage,
                       stages=prefix)

    mark_loop_start(ctx)
    iterations = 0
    has_search = "search" in loop_window
    reason = loop_start_reason(ctx) if loop_window else None
    if reason is None and loop_window:
        while True:
            iterations += 1
            ctx.loop_iteration = iterations
            total = len(loop_window)
            for offset, stage in enumerate(loop_window, 1):
                ctx.eprint(
                    f"[velora] loop iteration {iterations}: "
                    f"{LABEL_BY_STAGE.get(stage, stage)} ({offset}/{total})"
                )
                run_stage_once(ctx, stage, _STAGE_RUNNERS,
                               after_stage=after_stage)
            reason = loop_iteration_reason(ctx, iterations)
            if reason is not None:
                break
            if not has_search and getattr(ctx.args, "max_loop", None) is None:
                # No SEARCH to converge on and no user cap: one honest pass.
                reason = "no-search"
                break

    if reason is not None or iterations > 0:
        record = loop_record(ctx, iterations, reason or "converged",
                             ctx.loop_started_at)
        ctx.loop_summary = record
        if "search" in plan:
            ctx.commit_stage("search", {"loop.json": record})
        ctx.eprint(
            f"[velora] loop: {iterations} iteration(s), "
            f"reason={record['reason']}"
        )

    if want_report:
        execute_stage_loop(ctx, _STAGE_RUNNERS, stages=["report"])


# ---------------------------------------------------------------------------
# Stage wrappers (shared runners + bughunt-specific behavior)
# ---------------------------------------------------------------------------

def _delegate(module: str, stage_id: str):
    """Lazy import of a runner owned by whitebox/blackbox (no cycles)."""

    def runner(ctx: ModeContext):
        if module == "blackbox":
            from velora.modes import blackbox as owner
        else:
            from velora.modes import whitebox as owner
        return getattr(owner, "_stage_" + stage_id.replace("-", "_"))(ctx)

    runner.__name__ = "_stage_" + stage_id.replace("-", "_")
    return runner


def _stage_scope(ctx: ModeContext) -> Dict[str, object]:
    """Guard stage: source-only runs pin an empty probe scope, not an error."""
    from velora.modes.blackbox import _scope_hosts

    hosts = _scope_hosts(ctx)
    if not hosts and not ctx.inputs.has_source:
        raise GrammarError(
            EXIT_FINDINGS, "no in-scope hosts (pass TARGET and/or --scope)"
        )
    return {
        "scope.json": {
            "source": ctx.inputs.source,
            "target": ctx.inputs.target,
            "hosts": hosts,
            "policy": "same-origin default; --scope widens; off-list refused",
        }
    }


def _stage_osint(ctx: ModeContext) -> object:
    """Public-source identifiers (TLS cert + DNS) for in-scope hosts."""
    from velora.active.osint import collect_osint
    from velora.modes.blackbox import _osint_ports, _scope_hosts

    hosts = _scope_hosts(ctx)
    if not hosts:
        runtime_na(ctx, "osint", "no in-scope hosts")
        return NA
    return {"osint.json": collect_osint(hosts, cert_ports=_osint_ports(ctx))}


def _stage_asset_model(ctx: ModeContext) -> Dict[str, object]:
    if ctx.inputs.has_source:
        return _delegate("whitebox", "asset-model")(ctx)
    from velora.modes.blackbox import _recon

    recon = _recon(ctx)
    if recon is None:
        runtime_na(ctx, "asset-model", "recon results unavailable")
        return NA
    from velora.assets.surface import recon_to_graph

    graph = recon_to_graph(recon, recon.get("origins") or [])
    return {"assets.json": graph.to_dict()}


def _stage_triage(ctx: ModeContext) -> Dict[str, object]:
    """Rank + dedupe, then annotate novelty against the ledger (§10 rubric)."""
    from velora.sil.hypotheses import derive_from_finding

    payload = stage_triage(ctx)
    ledger = load_ledger(ctx)
    known = {
        str(entry.get("fingerprint") or "")
        for entry in ledger.get("hypotheses") or []
    }
    triage = payload.get("triage.json") or {}
    for finding in triage.get("findings") or ():
        if not isinstance(finding, dict):
            continue
        derived = derive_from_finding(finding, 0)
        finding["novelty"] = (
            "known" if derived["fingerprint"] in known else "new"
        )
    return payload


def _stage_verify(ctx: ModeContext) -> Dict[str, object]:
    """Live recheck when scoping allows it; analytic verdicts otherwise."""
    from velora.modes.blackbox import _scope_hosts, _stage_verify as live_verify

    if _scope_hosts(ctx):
        payload = live_verify(ctx)["verify.json"]
    else:
        proofs: List[Dict[str, object]] = []
        for finding in working_set(ctx):
            if not isinstance(finding, dict):
                continue
            entry: Dict[str, object] = {
                "title": finding.get("title"),
                "detector": finding.get("detector"),
                "location": finding.get("location"),
                "cwe_id": finding.get("cwe_id") or finding.get("cwe"),
                "type": finding.get("type"),
                "confidence": finding.get("confidence"),
                "ok": None,
                "reason": (
                    "no detector (not re-runnable)" if not finding.get("detector")
                    else "no in-scope hosts (not re-runnable)"
                ),
            }
            proofs.append(entry)
        if not proofs:
            runtime_na(ctx, "verify", "no in-scope hosts and no findings")
            return NA
        payload = {
            "checked": len(proofs),
            "reproduced": 0,
            "proofs": proofs,
            "success_check": None,
        }
    ledger = reconcile_verdicts(ctx, payload.get("proofs") or [])
    from velora.modes.loop import ledger_artifact

    return {"verify.json": payload, **ledger_artifact(ledger)}


def _stage_exploit(ctx: ModeContext) -> object:
    """Budgeted AI stage: n/a (never a hard error) until an endpoint exists."""
    if ai_enabled(ctx) and llm_configured() is None:
        runtime_na(
            ctx, "exploit",
            "AI requested but no LLM endpoint configured "
            "(VELORA_LLM_BASE_URL/MODEL)",
        )
        return NA
    result = stage_exploit(ctx)
    if result is not NA and result is not None:
        ctx.budget_spent = getattr(ctx, "budget_spent", 0) + 1
    return result


def _stage_validate(ctx: ModeContext) -> object:
    from velora.modes.blackbox import _scope_hosts, _stage_validate as live_validate

    if not _scope_hosts(ctx):
        runtime_na(ctx, "validate", "no in-scope hosts (static-only run)")
        return NA
    return live_validate(ctx)


def _stage_report(ctx: ModeContext) -> Optional[Dict[str, str]]:
    from velora.tui.report import (
        build_bounty_report,
        render_findings_json,
        render_findings_sarif,
    )

    floor_name = getattr(ctx.args, "min_severity", None) or "low"
    from velora.modes.common import severity_rank

    floor_rank = severity_rank(floor_name)
    fmt = getattr(ctx.args, "format", "text") or "text"
    # working_set = triage-ranked, de-duplicated (the loop re-hunts, so the
    # raw ctx.findings list can hold the same detector hit more than once).
    recorded = [
        f for f in working_set(ctx)
        if isinstance(f, dict)
        and severity_rank(str(f.get("severity") or "")) >= floor_rank
    ]
    if fmt == "json":
        rendered = render_findings_json(recorded, mode="bughunt")
    elif fmt == "sarif":
        rendered = render_findings_sarif(recorded, mode="bughunt")
    else:
        ledger = load_ledger(ctx)
        evidence = None
        if ctx.session is not None:
            stored_ev = ctx.session.read_json("evidence.json", None)
            if isinstance(stored_ev, dict):
                evidence = stored_ev.get("evidence") or None
        meta = {
            "subject": ctx.inputs.target or ctx.inputs.source or "",
            "loop": getattr(ctx, "loop_summary", None) or {},
        }
        rendered = build_bounty_report(
            recorded, ledger=ledger, meta=meta, evidence=evidence)
    output = getattr(ctx.args, "output", None)
    if output:
        try:
            Path(output).write_text(rendered)
        except OSError as exc:
            raise GrammarError(
                EXIT_FINDINGS, f"-o: cannot write {output}: {exc}"
            ) from exc
    else:
        sys.stdout.write(rendered if rendered.endswith("\n") else rendered + "\n")
    return {"report.md": rendered}


_STAGE_RUNNERS: Dict[str, object] = {
    "scope": _stage_scope,
    "auth": _delegate("blackbox", "auth"),
    "intel": _delegate("blackbox", "intel"),
    "osint": _stage_osint,
    "recon": _delegate("blackbox", "recon"),
    "asset-model": _stage_asset_model,
    "ingest": _delegate("whitebox", "ingest"),
    "code-model": _delegate("whitebox", "code-model"),
    "static-scan": _delegate("whitebox", "static-scan"),
    "dataflow": _delegate("whitebox", "dataflow"),
    "surface": _delegate("blackbox", "surface"),
    "enumerate": _delegate("blackbox", "enumerate"),
    "hunt": _delegate("blackbox", "hunt"),
    "hypothesize": _delegate("whitebox", "hypothesize"),
    "triage": _stage_triage,
    "deepthink": stage_deepthink,
    "plan": _delegate("blackbox", "plan"),
    "verify": _stage_verify,
    "exploit": _stage_exploit,
    "fix": _delegate("whitebox", "fix"),
    "rescan": _delegate("whitebox", "rescan"),
    "capture": _delegate("blackbox", "capture"),
    "validate": _stage_validate,
    "search": stage_search,
    "report": _stage_report,
}


# ---------------------------------------------------------------------------
# Subcommands: ledger | gaps | resume (§8.5)
# ---------------------------------------------------------------------------

def _open_session(args, name: str):
    session_dir = getattr(args, "session", None) or os.environ.get(
        "VELORA_SESSION"
    )
    if not session_dir:
        raise GrammarError(
            EXIT_FINDINGS,
            f"bughunt {name}: pass --session DIR (or set VELORA_SESSION) — "
            "refusing to guess which session you meant",
        )
    from velora.modes.session import Session

    session = Session.open(Path(session_dir))
    if not session.exists:
        raise GrammarError(
            EXIT_FINDINGS,
            f"bughunt {name}: {session_dir} is not a session "
            "(no session.json)",
        )
    return session


def run_subcommand(name: str, args) -> int:
    fmt = getattr(args, "format", "text") or "text"
    try:
        session = _open_session(args, name)
        if name == "ledger":
            return _cmd_ledger(session, fmt)
        if name == "gaps":
            return _cmd_gaps(session, fmt)
        if name == "resume":
            return _cmd_resume(session, fmt)
        print(f"velora: error: unknown bughunt subcommand {name!r}",
              file=sys.stderr)
        return EXIT_USAGE
    except GrammarError as exc:
        print(f"velora: error: {exc.message}", file=sys.stderr)
        return exc.code


def _cmd_ledger(session, fmt: str) -> int:
    payload = session.read_json("hypotheses.json", None)
    if payload is None:
        raise GrammarError(
            EXIT_FINDINGS,
            "bughunt ledger: no hypotheses.json in this session "
            "(run the loop first, or pass --hypotheses FILE)",
        )
    if fmt == "json":
        print(json.dumps(payload, indent=2, default=str))
        return 0
    counts = payload.get("counts") or {}
    print(f"ledger: {session.path}")
    print(
        f"  open: {counts.get('open', 0)} · "
        f"proven: {counts.get('proven', 0)} · "
        f"eliminated: {counts.get('eliminated', 0)}"
    )
    for entry in payload.get("hypotheses") or []:
        status = str(entry.get("status") or "open")
        ident = str(entry.get("id") or entry.get("fingerprint") or "?")
        claim = str(entry.get("claim") or "")
        print(f"  {ident} [{status}] {claim}")
    return 0


def _cmd_gaps(session, fmt: str) -> int:
    search = session.read_json("search.json", None)
    if search is None:
        raise GrammarError(
            EXIT_FINDINGS,
            "bughunt gaps: no search.json in this session (run the loop "
            "first)",
        )
    loop = session.read_json("loop.json", None) or {}
    if fmt == "json":
        print(json.dumps(
            {"loop": loop, "search": search}, indent=2, default=str
        ))
        return 0
    print(f"session: {session.path}")
    if loop:
        print(
            f"  loop: {loop.get('iterations', 0)} iteration(s), "
            f"reason={loop.get('reason')}"
        )
    print(f"  search iteration: {search.get('iteration')}")
    print(f"  converged: {search.get('converged')}")
    gaps = search.get("gaps") or []
    if gaps:
        print("  gaps:")
        for gap in gaps:
            print(f"    - {gap}")
    else:
        print("  gaps: (none — no actionable gap recorded)")
    return 0


def _cmd_resume(session, fmt: str) -> int:
    command = (
        f"velora bughunt --from hunt --session {session.path}"
    )
    if fmt == "json":
        print(json.dumps({
            "resume": command,
            "session": str(session.path),
            "completed": session.completed_stages(),
        }, indent=2, default=str))
        return 0
    print(f"session: {session.path}")
    completed = session.completed_stages()
    print(f"  completed: {', '.join(completed) if completed else '(none)'}")
    print(f"  resume: {command}")
    print("  inputs (source/target) restore from the session — no re-entry "
          "needed")
    return 0
