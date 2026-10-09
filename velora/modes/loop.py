"""BUGHUNT loop engines: ledger I/O, DEEPTHINK, SEARCH, gap analysis.

Shared by bughunt (default graph) and blackbox (`--with-deepthink` /
`--with-search`). Hypothesis semantics live in ``velora.sil.hypotheses``;
this module wires them to the stage protocol and the loop state on
``ModeContext`` (``loop_iteration``, ``loop_reason``, ``loop_gaps_seen``,
``budget_spent``).

Termination (§4): every ending proceeds to REPORT — converged (SEARCH finds
no new actionable gap) · budget (LLM steps) · time · max-loop · interrupt.
Budget/time/max-loop/convergence are normal endings (exit 0 after the gate).
"""

from __future__ import annotations

import json
import re
import time
from typing import Dict, List, Optional, Set, Tuple

from velora.modes.common import (
    ModeContext,
    ai_enabled,
    llm_configured,
    working_set,
)

LOOP_STAGES: Tuple[str, ...] = (
    "hunt", "triage", "deepthink", "verify", "exploit", "capture",
    "validate", "search",
)


# ---------------------------------------------------------------------------
# Ledger I/O
# ---------------------------------------------------------------------------

def load_ledger(ctx: ModeContext) -> Dict:
    from velora.sil.hypotheses import empty_ledger, normalize_ledger

    cached = getattr(ctx, "loop_ledger", None)
    if isinstance(cached, dict):
        return cached
    if ctx.session is None:
        return empty_ledger()
    payload = ctx.session.read_json("hypotheses.json", None)
    if payload is None:
        return empty_ledger()
    ledger = normalize_ledger(payload)
    ctx.loop_ledger = ledger
    return ledger


def ledger_artifact(ledger: Dict) -> Dict[str, object]:
    from velora.sil.hypotheses import recount

    return {"hypotheses.json": recount(ledger)}


def seed_ledger(ctx: ModeContext) -> Tuple[Dict, List[Tuple[Dict, List[str]]]]:
    """Session ledger + --hypotheses seed file (validated, deduped)."""
    from velora.sil.hypotheses import load_seed_file, merge_entries

    ledger = load_ledger(ctx)
    rejected: List[Tuple[Dict, List[str]]] = []
    seed_path = getattr(ctx.args, "hypotheses", None)
    if seed_path:
        try:
            seeds = load_seed_file(seed_path)
        except (OSError, ValueError) as exc:
            from velora.modes.common import EXIT_FINDINGS, GrammarError

            raise GrammarError(
                EXIT_FINDINGS, f"--hypotheses: cannot read {seed_path}: {exc}"
            ) from exc
        ledger, _added, _skipped, rejected = merge_entries(ledger, seeds)
        for candidate, errors in rejected:
            claim = str(candidate.get("claim") or candidate)[:80]
            ctx.eprint(
                f"[velora] hypotheses: rejected (not falsifiable): "
                f"{claim!r} — {'; '.join(errors)}"
            )
    ctx.loop_ledger = ledger
    return ledger, rejected


# ---------------------------------------------------------------------------
# Coverage helpers
# ---------------------------------------------------------------------------

def _endpoint_key(url: str) -> str:
    from urllib.parse import urlsplit

    parts = urlsplit(str(url))
    return f"{parts.scheme}://{parts.netloc}{parts.path}"


def _location_path(loc: str) -> str:
    from urllib.parse import urlsplit

    return (urlsplit(str(loc)).path or "").rstrip("/") or "/"


def _location_netloc(loc: str) -> str:
    from urllib.parse import urlsplit

    return urlsplit(str(loc)).netloc.lower()


def _same_endpoint(a: str, b: str) -> bool:
    """Match full URLs to each other and to bare subjects (`/search`).

    A seed ledger says `GET /search?... at /search` while a detector finding
    carries `http://host:port/search` — same endpoint, one has no host.
    """
    a, b = str(a or "").strip(), str(b or "").strip()
    if not a or not b:
        return False
    if _endpoint_key(a) == _endpoint_key(b):
        return True
    if _location_path(a) != _location_path(b):
        return False
    netloc_a, netloc_b = _location_netloc(a), _location_netloc(b)
    return not netloc_a or not netloc_b or netloc_a == netloc_b


def covered_locations(ctx: ModeContext) -> Set[str]:
    """Locations already exercised by findings + captured evidence."""
    covered: Set[str] = set()
    for finding in working_set(ctx):
        loc = finding.get("location")
        if loc:
            covered.add(_endpoint_key(str(loc)))
    client = getattr(ctx, "_bb_client", None)
    if client is not None:
        for entry in client.export_evidence():
            if entry.get("url"):
                covered.add(_endpoint_key(str(entry["url"])))
    return covered


def surface_endpoints(ctx: ModeContext) -> List[str]:
    from velora.modes.blackbox import _surface

    surface = _surface(ctx) or {}
    return list((surface or {}).get("endpoints") or {})


def _class_gap_tokens(ctx: ModeContext) -> List[str]:
    raw = getattr(ctx.args, "classes", None)
    if not raw:
        return []
    return [part.strip().lower() for part in str(raw).split(",") if part.strip()]


def _finding_blob(ctx: ModeContext) -> str:
    chunks = []
    for finding in working_set(ctx):
        chunks.append(
            " ".join(
                str(finding.get(key) or "")
                for key in ("type", "cwe_id", "cwe", "title", "description")
            )
        )
    return " ".join(chunks).lower()


def compute_gaps(ctx: ModeContext, ledger: Dict) -> List[str]:
    """Actionable gap ids: uncovered endpoints, open hypotheses, missing classes."""
    covered = covered_locations(ctx)
    gaps: List[str] = []
    for url in surface_endpoints(ctx):
        if _endpoint_key(url) not in covered:
            gaps.append(f"uncovered endpoint {url}")
    for entry in ledger.get("hypotheses") or []:
        if entry.get("status") == "open":
            claim = str(entry.get("claim") or "")[:100]
            gaps.append(f"open hypothesis {entry.get('id') or '?'}: {claim}")
    blob = _finding_blob(ctx)
    for token in _class_gap_tokens(ctx):
        if token not in blob:
            gaps.append(f"uncovered bug class {token}")
    return gaps


# ---------------------------------------------------------------------------
# DEEPTHINK
# ---------------------------------------------------------------------------

_DEEPTHINK_SYSTEM = (
    "You are a vulnerability researcher. From the findings, propose "
    "falsifiable hypotheses: each has a concrete subject (endpoint/"
    "parameter/location), a mechanism-level claim, and a falsifier "
    "(the observation that would refute it). Reply with ONLY a JSON array "
    "of {\"claim\", \"subject\", \"falsifier\"} objects. No vague suspicions."
)


def _llm_hypothesis_candidates(ctx: ModeContext, findings: List[Dict]) -> List[Dict]:
    config = llm_configured()
    if config is None:
        return []
    from velora.sil.llm_client import LLMClient

    payload = [
        {
            "type": f.get("type"),
            "location": f.get("location"),
            "parameter": f.get("parameter"),
            "cwe_id": f.get("cwe_id") or f.get("cwe"),
            "description": str(f.get("description") or "")[:400],
        }
        for f in findings[:20]
    ]
    messages = [
        {"role": "system", "content": _DEEPTHINK_SYSTEM},
        {"role": "user", "content": json.dumps(payload)},
    ]
    # One model attempt = one spent step, success or not (§8.4 wallet).
    ctx.budget_spent = getattr(ctx, "budget_spent", 0) + 1
    try:
        reply = LLMClient(config).chat_raw(messages)
    except Exception:
        return []
    if not reply:
        return []
    content = reply.get("content") if isinstance(reply, dict) else None
    if not isinstance(content, str):
        return []
    match = re.search(r"\[.*\]", content, re.DOTALL)
    if not match:
        return []
    try:
        items = json.loads(match.group(0))
    except ValueError:
        return []
    return [
        item for item in items
        if isinstance(item, dict) and item.get("claim")
    ][:10]


def stage_deepthink(ctx: ModeContext) -> Dict[str, object]:
    """Reason over evidence chains → falsifiable hypotheses in the ledger."""
    ledger = load_ledger(ctx)
    rejected: List[Tuple[Dict, List[str]]] = []
    findings = [f for f in working_set(ctx) if isinstance(f, dict)]
    from velora.sil.hypotheses import derive_from_finding, merge_entries

    # Ids are assigned by merge_entries (collision-free); derivation only
    # needs a stable fingerprint, which comes from claim+subject.
    candidates: List[Dict] = [
        derive_from_finding(finding, 0) for finding in findings
    ]
    for candidate in candidates:
        candidate.pop("id", None)
    ai_path = ai_enabled(ctx) and llm_configured() is not None
    llm_note = None
    if ai_enabled(ctx):
        if llm_configured() is None:
            llm_note = "AI requested but no endpoint configured — deriving from evidence only"
        else:
            candidates.extend(_llm_hypothesis_candidates(ctx, findings))
    else:
        llm_note = "AI disabled — deriving falsifiable candidates from evidence"
    ledger, added, skipped, deep_rejected = merge_entries(ledger, candidates)
    rejected = list(rejected) + list(deep_rejected)
    ctx.loop_ledger = ledger
    if llm_note:
        ctx.eprint(f"[velora] deepthink: {llm_note}")
    counts = ledger.get("counts") or {}
    return {
        "deepthink.json": {
            "iteration": getattr(ctx, "loop_iteration", 0),
            "derived": len(candidates),
            "added": len(added),
            "skipped_known": len(skipped),
            "rejected_vague": len(rejected),
            "open": counts.get("open", 0),
            "proven": counts.get("proven", 0),
            "eliminated": counts.get("eliminated", 0),
            "ai": bool(ai_path),
        },
        **ledger_artifact(ledger),
    }


# ---------------------------------------------------------------------------
# Hypothesis verdicts after VERIFY
# ---------------------------------------------------------------------------

def reconcile_verdicts(ctx: ModeContext, proofs: List[Dict]) -> Dict[str, object]:
    """Move open hypotheses → proven/eliminated from verify/validate proof.

    Rules (§4): a hypothesis that neither proves nor reproduces is
    eliminated; the loop never re-derives it (fingerprint dedupe).
    """
    from velora.sil.hypotheses import set_verdicts

    ledger = load_ledger(ctx)
    findings = [f for f in working_set(ctx) if isinstance(f, dict)]
    proof_by_loc: List[Tuple[str, Dict]] = []
    for proof in proofs or []:
        loc = str(proof.get("location") or "")
        if loc:
            proof_by_loc.append((loc, proof))

    proven: List[str] = []
    eliminated: List[str] = []
    for entry in ledger.get("hypotheses") or []:
        if entry.get("status") != "open":
            continue
        locs: List[str] = []
        for candidate in (
            (entry.get("based_on") or {}).get("location"),
            entry.get("location"),
            str(entry.get("subject") or "").split(" (")[0],
        ):
            text = str(candidate or "").strip()
            if text and text not in locs:
                locs.append(text)
        # 1) proof records from VERIFY/VALIDATE win
        verdict = None
        for loc in locs:
            for proof_loc, proof in proof_by_loc:
                if not _same_endpoint(loc, proof_loc):
                    continue
                if proof.get("ok") is True or proof.get("reproduced") is True:
                    verdict = "proven"
                elif proof.get("ok") is False or proof.get("reproduced") is False:
                    verdict = "eliminated"
        # 2) no proof record: a supporting finding stands only if it is an
        #    analytic (detector-less) finding; otherwise nothing reproduced.
        if verdict is None:
            supporting = next(
                (
                    f for f in findings
                    if any(
                        _same_endpoint(loc, str(f.get("location") or ""))
                        for loc in locs
                    )
                ),
                None,
            )
            if supporting is None:
                verdict = "eliminated"
            elif not supporting.get("detector"):
                verdict = "proven"
        if verdict == "proven":
            proven.append(entry["fingerprint"])
        elif verdict == "eliminated":
            eliminated.append(entry["fingerprint"])
    set_verdicts(ledger, proven, eliminated)
    ctx.loop_ledger = ledger
    return ledger


# ---------------------------------------------------------------------------
# SEARCH
# ---------------------------------------------------------------------------

def stage_search(ctx: ModeContext) -> Dict[str, object]:
    """Gap analysis → next angles, or convergence (no new actionable gap)."""
    ledger = load_ledger(ctx)
    gaps = compute_gaps(ctx, ledger)
    seen: Set[str] = set(getattr(ctx, "loop_gaps_seen", None) or set())
    new_gaps = [g for g in gaps if g not in seen]
    seen.update(gaps)
    ctx.loop_gaps_seen = seen
    converged = not new_gaps
    if converged:
        ctx.loop_reason = ctx.loop_reason or "converged"
    counts = ledger.get("counts") or {}
    payload = {
        "iteration": getattr(ctx, "loop_iteration", 0),
        "gaps": gaps,
        "new_gaps": new_gaps,
        "converged": converged,
        "open_hypotheses": counts.get("open", 0),
        "eliminated_hypotheses": counts.get("eliminated", 0),
        "proven_hypotheses": counts.get("proven", 0),
        "coverage": {
            "surface_endpoints": len(surface_endpoints(ctx)),
            "covered_locations": len(covered_locations(ctx)),
            "findings": len([f for f in working_set(ctx) if isinstance(f, dict)]),
        },
        "loop_reason": ctx.loop_reason,
    }
    return {"search.json": payload}


# ---------------------------------------------------------------------------
# Termination checks
# ---------------------------------------------------------------------------

def loop_start_reason(ctx: ModeContext) -> Optional[str]:
    """Pre-iteration termination: budget/time/max-loop already exhausted."""
    budget = getattr(ctx.args, "budget", None)
    if budget is not None and getattr(ctx, "budget_spent", 0) >= budget:
        return "budget"
    minutes = getattr(ctx.args, "time_budget", None)
    if minutes is not None and _elapsed_minutes(ctx) >= float(minutes):
        return "time"
    max_loop = getattr(ctx.args, "max_loop", None)
    if max_loop is not None and max_loop <= 0:
        return "max-loop"
    return None


def loop_iteration_reason(ctx: ModeContext, iteration: int) -> Optional[str]:
    """Post-iteration termination: caps win, then SEARCH convergence."""
    budget = getattr(ctx.args, "budget", None)
    if budget is not None and getattr(ctx, "budget_spent", 0) >= budget:
        return "budget"
    minutes = getattr(ctx.args, "time_budget", None)
    if minutes is not None and _elapsed_minutes(ctx) >= float(minutes):
        return "time"
    max_loop = getattr(ctx.args, "max_loop", None)
    if max_loop is not None and iteration >= max_loop:
        return "max-loop"
    if getattr(ctx, "loop_reason", None):
        return str(ctx.loop_reason)
    return None


def _elapsed_minutes(ctx: ModeContext) -> float:
    started = getattr(ctx, "loop_started_at", None)
    if started is None:
        started = time.monotonic()
        ctx.loop_started_at = started
    return (time.monotonic() - started) / 60.0


def mark_loop_start(ctx: ModeContext) -> None:
    ctx.loop_started_at = time.monotonic()
    ctx.loop_iteration = 0
    ctx.loop_reason = None
    ctx.loop_gaps_seen = set()
    ctx.budget_spent = getattr(ctx, "budget_spent", 0)


def loop_record(ctx: ModeContext, iterations: int, reason: str,
                started_at: float) -> Dict[str, object]:
    return {
        "iterations": iterations,
        "reason": reason,
        "budget_spent": getattr(ctx, "budget_spent", 0),
        "budget": getattr(ctx.args, "budget", None),
        "elapsed_s": round(max(0.0, time.monotonic() - started_at), 3),
        "ended_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }
