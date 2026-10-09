"""WHITEBOX orchestrator: the §4 15-stage default graph (Phase 1e).

Static-first run order: SCOPE → INGEST → ASSET MODEL → CODE MODEL →
STATIC SCAN → DATAFLOW → HYPOTHESIZE → TRIAGE → PLAN → VERIFY → EXPLOIT →
FIX → RESCAN → VALIDATE → REPORT.

Symbolic stages always run. LLM-backed stages (EXPLOIT, FIX) run only with
--ai and are announced n/a otherwise; findings-gated stages (FIX/RESCAN/
VALIDATE) are announced n/a when no findings exist. Every stage commits its
artifacts to the session before the next stage starts (crash-safe, §8.5).
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Dict, List, Optional

from velora.modes.common import (
    EXIT_FINDINGS,
    EXIT_IO,
    NA,
    GrammarError,
    ModeContext,
    ai_enabled,
    check_dynamic_inputs,
    execute_stage_loop,
    llm_configured,
    preload_findings,
    run_mode_shell,
    run_oracle,
    runtime_na,
    stage_exploit,
    stage_triage,
    working_set,
)


def run(args) -> int:
    return run_mode_shell("whitebox", args, executor=execute)


def execute(ctx: ModeContext) -> None:
    """Run the resolved whitebox plan; run_mode_shell owns grammar, interrupts,
    and the severity gate around this."""
    plan = list(ctx.selection.plan) if ctx.selection is not None else []
    preload_findings(ctx, "static-scan")
    ctx.inputs.findings = len(ctx.findings)
    if "static-scan" not in plan:
        check_dynamic_inputs(ctx.mode, ctx.selection, ctx.inputs)

    def after_stage(c: ModeContext, stage: str) -> None:
        if stage == "static-scan":
            check_dynamic_inputs(c.mode, c.selection, c.inputs)

    execute_stage_loop(ctx, _STAGE_RUNNERS, after_stage=after_stage)


def _iter_files(ctx: ModeContext) -> List[Path]:
    from velora.sil.scanner import DEFAULT_EXCLUDED_SCAN_DIRS, VeloraScanner

    source = Path(ctx.inputs.source or ".")
    pattern = getattr(ctx.args, "pattern", None) or "**/*.py"
    excluded = (
        [] if getattr(ctx.args, "no_default_excludes", False)
        else DEFAULT_EXCLUDED_SCAN_DIRS
    )
    if source.is_file():
        return [source]
    return [
        p for p in sorted(source.glob(pattern))
        if p.is_file()
        and not VeloraScanner._is_excluded_dir_member(p, source, excluded)
    ]


def _read_text(path: Path) -> str:
    return path.read_text(encoding="utf-8-sig", errors="replace")


# ---------------------------------------------------------------------------
# Stage runners — each returns artifact payloads (committed by execute) or NA.
# ---------------------------------------------------------------------------

def _stage_scope(ctx: ModeContext) -> Dict[str, object]:
    inputs = ctx.inputs
    if inputs.source is not None and not Path(inputs.source).exists():
        raise GrammarError(
            EXIT_FINDINGS, f"--source: path not found: {inputs.source}"
        )
    hosts: List[str] = list(getattr(ctx.args, "scope", None) or [])
    scope_file = getattr(ctx.args, "scope_file", None)
    if scope_file:
        try:
            text = sys.stdin.read() if scope_file == "-" else Path(scope_file).read_text()
        except OSError as exc:
            raise GrammarError(
                EXIT_FINDINGS, f"--scope-file: cannot read {scope_file}: {exc}"
            ) from exc
        hosts.extend(
            line.strip() for line in text.splitlines()
            if line.strip() and not line.lstrip().startswith("#")
        )
    ordered = list(dict.fromkeys(hosts))
    return {
        "scope.json": {
            "source": inputs.source,
            "target": inputs.target,
            "hosts": ordered,
        }
    }


def _stage_ingest(ctx: ModeContext) -> Dict[str, object]:
    from velora.assets.graph import AssetGraph

    files = _iter_files(ctx)
    if not files:
        raise GrammarError(
            EXIT_FINDINGS,
            "No files found to scan (pattern "
            f"{getattr(ctx.args, 'pattern', None) or '**/*.py'!r} under "
            f"{ctx.inputs.source})",
        )
    source = Path(ctx.inputs.source or ".")
    base = source.parent if source.is_file() else source
    graph = AssetGraph()
    for path in files:
        rel = str(path.relative_to(base)) if path.is_relative_to(base) else str(path)
        graph.add_node("file", rel, path=str(path))
    from velora.assets.ingest import absorb, discover_manifest_assets

    found = discover_manifest_assets(base)
    absorb(graph, found["graph"])
    stats = found.get("stats") or {}
    if stats:
        ctx.eprint(
            "[velora] ingest: "
            + ", ".join(f"{k}={v}" for k, v in sorted(stats.items()))
        )
    return {"assets.json": graph.to_dict()}


def _stage_asset_model(ctx: ModeContext) -> Dict[str, object]:
    from velora.assets.graph import AssetGraph, discover_code_assets

    existing: Dict = {}
    if ctx.session is not None:
        stored = ctx.session.read_json("assets.json", {})
        if isinstance(stored, dict):
            existing = stored
    graph = AssetGraph.from_dict(existing)
    source = Path(ctx.inputs.source or ".")
    fresh = discover_code_assets(source, files=_iter_files(ctx))
    for node in fresh:
        graph.add_node(node.kind, node.label, **node.props)
    for edge in fresh.edges:
        graph.add_edge(edge.src, edge.dst, edge.kind, **edge.props)
    return {"assets.json": graph.to_dict()}


def _stage_code_model(ctx: ModeContext) -> Dict[str, object]:
    from velora.cli import _lang_for
    from velora.sil.scanner import VeloraScanner

    frontends: Dict[str, object] = {}
    files_parsed = procedures = parse_errors = skipped = 0
    errors: List[Dict[str, str]] = []
    for path in _iter_files(ctx):
        lang = _lang_for(str(path))
        frontend = frontends.get(lang)
        if frontend is None and lang not in frontends:
            frontend = VeloraScanner(language=lang, verify=False).frontend
            frontends[lang] = frontend
        if frontend is None:
            skipped += 1
            continue
        try:
            program = frontend.translate(_read_text(path), str(path))
        except Exception as exc:
            parse_errors += 1
            if len(errors) < 20:
                errors.append({"file": str(path), "error": str(exc)})
            continue
        files_parsed += 1
        procedures += len(getattr(program, "procedures", ()) or ())
    return {
        "code-model.json": {
            "files_parsed": files_parsed,
            "files_skipped_language": skipped,
            "parse_errors": parse_errors,
            "procedures": procedures,
            "errors": errors,
        }
    }


def _stage_static_scan(ctx: ModeContext) -> Dict[str, object]:
    from velora.sil.scanner import VeloraScanner

    args = ctx.args
    ai = bool(getattr(args, "ai", False))
    llm_detect = ai or bool(getattr(args, "llm_detect", False))
    llm_triage = ai or bool(getattr(args, "llm_triage", False))
    if llm_detect or llm_triage:
        if llm_configured() is None:
            ctx.eprint(
                "Note: AI layer requested (--ai/--llm-*) but no endpoint/model "
                "is configured (VELORA_LLM_BASE_URL / VELORA_LLM_MODEL); "
                "running without the LLM tier -- see docs/ai-models.md."
            )
    scanner = VeloraScanner(
        language=getattr(args, "language", None) or "python",
        verify=not getattr(args, "no_verify", False),
        timeout=getattr(args, "timeout", None) or 5000,
        verbose=bool(getattr(args, "verbose", False)),
        llm_detect=llm_detect,
        llm_triage=llm_triage,
        llm_repo_scale=bool(getattr(args, "repo_scale", False)),
    )
    source = Path(ctx.inputs.source or ".")
    pattern = getattr(args, "pattern", None) or "**/*.py"
    excluded = [] if getattr(args, "no_default_excludes", False) else None
    try:
        if source.is_file():
            results = [scanner.scan_file(str(source))]
        else:
            results = scanner.scan_directory(
                str(source), pattern, exclude_dirs=excluded
            )
    except OSError as exc:
        raise GrammarError(EXIT_IO, f"scan: {exc}") from exc
    if not results:
        raise GrammarError(EXIT_FINDINGS, "No files found to scan.")
    scan_errors: List[str] = []
    for result in results:
        for err in result.errors:
            ctx.eprint(f"Scan error: {err}")
            scan_errors.append(str(err))
    ctx.scan_errors = scan_errors
    ctx.scan_results = results
    vulns: List[Dict[str, object]] = []
    for result in results:
        for v in result.vulnerabilities:
            item = v.to_dict()
            # §7.1 finding contract (additive): static provenance + code asset.
            item.setdefault("mode", "whitebox")
            item.setdefault("provenance", "static")
            item.setdefault(
                "asset",
                {"kind": "code", "id": str(item.get("location") or "")},
            )
            vulns.append(item)
    ctx.add_findings(vulns)
    ctx.inputs.findings = len(ctx.findings)
    return {"scan-results.json": {"files": [r.to_dict() for r in results]}}


def _stage_dataflow(ctx: ModeContext) -> Dict[str, object]:
    flows: List[Dict[str, object]] = []
    for finding in ctx.findings:
        if not isinstance(finding, dict):
            continue
        if not (finding.get("data_flow") or finding.get("source_var")
                or finding.get("sink_type")):
            continue
        flows.append({
            key: finding.get(key)
            for key in (
                "location", "line", "procedure", "source_var",
                "source_location", "sink_type", "data_flow", "cwe_id", "type",
            )
        })
    return {
        "dataflow.json": {
            "flows": flows,
            "findings_with_taint": len(flows),
        }
    }


def _stage_hypothesize(ctx: ModeContext) -> Dict[str, object]:
    hypotheses = []
    for index, finding in enumerate(working_set(ctx), 1):
        hypotheses.append({
            "id": f"H{index}",
            "claim": (
                f"{finding.get('type')} at {finding.get('location')}:"
                f"{finding.get('line')} is reproducible and exploitable as "
                "described"
            ),
            "based_on": {
                "location": finding.get("location"),
                "line": finding.get("line"),
                "type": finding.get("type"),
                "cwe_id": finding.get("cwe_id") or finding.get("cwe"),
            },
            "status": "open",
        })
    return {
        "hypotheses.json": {
            "goal": getattr(ctx.args, "goal", None),
            "count": len(hypotheses),
            "hypotheses": hypotheses,
        }
    }


def _stage_plan(ctx: ModeContext) -> Dict[str, object]:
    from velora.cli import _resolve_finding_file
    from velora.sil.llm_exploit import guidance_from_finding
    from velora.sil.llm_triage import _context_snippet

    context_lines = getattr(ctx.args, "context_lines", None) or 20
    source = ctx.inputs.source or "."
    leads: List[Dict[str, object]] = []
    for finding in working_set(ctx):
        lead: Dict[str, object] = dict(guidance_from_finding(finding))
        slices: List[Dict[str, object]] = []
        resolved = _resolve_finding_file(finding.get("location"), source)
        if resolved:
            try:
                lines = _read_text(Path(resolved)).splitlines()
            except OSError:
                lines = []
            if lines:
                centers = [finding.get("line")]
                source_location = str(finding.get("source_location") or "")
                if ":" in source_location:
                    tail = source_location.rsplit(":", 1)[-1].strip()
                    if tail.isdigit():
                        centers.append(int(tail))
                for center in dict.fromkeys(
                    c for c in centers if isinstance(c, int) and c
                ):
                    if 1 <= center <= len(lines):
                        slices.append({
                            "file": resolved,
                            "center_line": center,
                            "text": _context_snippet(
                                lines, center, context_lines
                            ),
                        })
        lead["source_slices"] = slices
        leads.append(lead)
    provenance = (
        "symbolic"
        if any(lead.get("provenance") == "symbolic" for lead in leads)
        else "llm"
    )
    return {
        "guidance.json": {
            "leads": leads,
            "provenance": provenance,
            "goal": getattr(ctx.args, "goal", None),
        }
    }


def _stage_verify(ctx: ModeContext) -> Dict[str, object]:
    proofs: List[Dict[str, object]] = []
    for finding in ctx.findings:
        if not isinstance(finding, dict):
            continue
        if finding.get("witness"):
            proof = "z3-witness"
        elif finding.get("data_flow"):
            proof = "taint-proven"
        else:
            proof = "pending"
        proofs.append({
            "location": finding.get("location"),
            "line": finding.get("line"),
            "cwe_id": finding.get("cwe_id") or finding.get("cwe"),
            "type": finding.get("type"),
            "proof": proof,
            "confidence": finding.get("confidence"),
        })
    oracle = None
    success_check = getattr(ctx.args, "success_check", None)
    if success_check:
        oracle = run_oracle(success_check)
    return {"verify.json": {"proofs": proofs, "success_check": oracle}}


def _stage_fix(ctx: ModeContext) -> object:
    if not ai_enabled(ctx):
        runtime_na(ctx, "fix", "AI stage disabled (pass --ai)")
        return NA
    config = llm_configured()
    if config is None:
        raise GrammarError(
            EXIT_FINDINGS,
            "fix: set VELORA_LLM_BASE_URL and VELORA_LLM_MODEL (LLM endpoint "
            "not configured)",
        )
    from velora.cli import _lang_for, _resolve_finding_file
    from velora.sil.llm_fix import apply_fix, generate_fix, make_diff, verify_fixes

    source = ctx.inputs.source or "."
    groups: Dict[str, List[dict]] = {}
    unresolvable = 0
    for finding in ctx.findings:
        if not isinstance(finding, dict):
            continue
        resolved = _resolve_finding_file(finding.get("location"), source)
        if resolved is None:
            unresolvable += 1
            continue
        groups.setdefault(resolved, []).append(finding)
    if not groups:
        raise GrammarError(
            EXIT_FINDINGS,
            "fix: no findings resolve to a file inside --source "
            f"({unresolvable} finding(s) skipped)",
        )
    in_place = bool(getattr(ctx.args, "in_place", False))
    with_diff = bool(getattr(ctx.args, "diff", False))
    fmt = getattr(ctx.args, "format", "text") or "text"
    no_verify = bool(getattr(ctx.args, "no_verify", False))
    rows: List[Dict[str, object]] = []
    applied_total = 0
    verified_total = 0
    for path_str, findings in groups.items():
        path = Path(path_str)
        try:
            original = path.read_text()
        except OSError as exc:
            raise GrammarError(EXIT_IO, f"fix: cannot read {path_str}: {exc}") from exc
        lang = _lang_for(path_str)
        patched = original
        applied_rows: List[dict] = []
        for finding in findings:
            patch = generate_fix(finding, patched, config)
            patched, applied = apply_fix(patched, patch)
            row = {
                "file": path_str,
                "cwe": str(
                    finding.get("cwe_id") or finding.get("cwe") or ""
                ),
                "line": finding.get("line") or 0,
                "applied": applied,
                "verified": None,
                "rationale": (patch or {}).get("rationale", ""),
            }
            rows.append(row)
            if applied:
                applied_rows.append(row)
                applied_total += 1
        if applied_rows and patched != original and not no_verify:
            verdicts = iter(
                verify_fixes(
                    patched,
                    lang,
                    path.name,
                    [f for f in findings],
                    config,
                )
            )
            for row in applied_rows:
                row["verified"] = next(verdicts, None)
                if row["verified"]:
                    verified_total += 1
        if patched != original:
            if in_place:
                try:
                    path.write_text(patched)
                except OSError as exc:
                    raise GrammarError(
                        EXIT_IO, f"fix: cannot write {path_str}: {exc}"
                    ) from exc
                if with_diff and fmt != "json":
                    print(make_diff(path_str, original, patched))
            elif fmt != "json":
                print(make_diff(path_str, original, patched))
    if applied_total == 0:
        ctx.no_patch = True
        ctx.eprint("fix: no patch applied")
    return {
        "fix.json": {
            "results": rows,
            "applied": applied_total,
            "verified": verified_total,
            "unresolvable_findings": unresolvable,
            "in_place": in_place,
        }
    }


def _stage_rescan(ctx: ModeContext) -> object:
    from velora.sil.scanner import VeloraScanner

    fix_data = None
    if ctx.session is not None:
        stored = ctx.session.read_json("fix.json", None)
        if isinstance(stored, dict):
            fix_data = stored
    patched_files = sorted({
        row.get("file")
        for row in (fix_data or {}).get("results", [])
        if row.get("applied") and row.get("file")
    })
    if not patched_files or not (fix_data or {}).get("in_place"):
        runtime_na(
            ctx, "rescan",
            "no applied in-place patches to re-check (run FIX with --in-place)",
        )
        return NA
    scanner = VeloraScanner(
        language=getattr(ctx.args, "language", None) or "python",
        verify=not getattr(ctx.args, "no_verify", False),
        timeout=getattr(ctx.args, "timeout", None) or 5000,
    )
    still_detected: List[Dict[str, object]] = []
    rescan_rows: List[Dict[str, object]] = []
    for file_path in patched_files:
        path = Path(file_path)
        if not path.is_file():
            continue
        try:
            result = scanner.scan_file(str(path))
        except OSError as exc:
            raise GrammarError(EXIT_IO, f"rescan: {exc}") from exc
        found_keys = {
            (v.type.value, v.cwe_id, v.line) for v in result.vulnerabilities
        }
        for row in (fix_data or {}).get("results", []):
            if row.get("file") != file_path or not row.get("applied"):
                continue
            hits = [
                key for key in found_keys
                if (row.get("cwe") in (None, "", key[1])
                    or key[0] == row.get("cwe"))
                and abs((key[2] or 0) - (row.get("line") or 0)) <= 5
            ]
            entry = {
                "file": file_path,
                "cwe": row.get("cwe"),
                "line": row.get("line"),
                "still_detected": bool(hits),
            }
            rescan_rows.append(entry)
            if hits:
                still_detected.append(entry)
    return {
        "rescan.json": {
            "files": patched_files,
            "rows": rescan_rows,
            "fixed": sum(
                1 for r in rescan_rows if not r["still_detected"]
            ),
            "still_detected": still_detected,
        }
    }


def _stage_validate(ctx: ModeContext) -> Dict[str, object]:
    from velora.cli import _resolve_finding_file
    from velora.sil.scanner import VeloraScanner

    source = ctx.inputs.source or "."
    groups: Dict[str, List[dict]] = {}
    unresolvable = 0
    for finding in ctx.findings:
        if not isinstance(finding, dict):
            continue
        resolved = _resolve_finding_file(finding.get("location"), source)
        if resolved is None:
            unresolvable += 1
            continue
        groups.setdefault(resolved, []).append(finding)
    scanner = VeloraScanner(
        language=getattr(ctx.args, "language", None) or "python",
        verify=not getattr(ctx.args, "no_verify", False),
        timeout=getattr(ctx.args, "timeout", None) or 5000,
    )
    results: List[Dict[str, object]] = []
    reproduced = 0
    for path_str, findings in groups.items():
        path = Path(path_str)
        if not path.is_file():
            for finding in findings:
                results.append({
                    "location": finding.get("location"),
                    "line": finding.get("line"),
                    "type": finding.get("type"),
                    "reproduced": False,
                    "reason": "file missing",
                })
            continue
        try:
            scan = scanner.scan_file(str(path))
        except OSError as exc:
            raise GrammarError(EXIT_IO, f"validate: {exc}") from exc
        seen = [
            (v.type.value, v.cwe_id, v.line) for v in scan.vulnerabilities
        ]
        for finding in findings:
            match = any(
                (finding.get("cwe_id") or finding.get("cwe") or None) in (None, cwe)
                or typ == finding.get("type")
                for typ, cwe, line in seen
                if abs((line or 0) - (finding.get("line") or 0)) <= 2
            )
            results.append({
                "location": finding.get("location"),
                "line": finding.get("line"),
                "type": finding.get("type"),
                "reproduced": bool(match),
            })
            if match:
                reproduced += 1
    goal_check = None
    success_check = getattr(ctx.args, "success_check", None)
    if success_check:
        goal_check = run_oracle(success_check)
    return {
        "validate.json": {
            "checked": len(results),
            "reproduced": reproduced,
            "unresolvable_findings": unresolvable,
            "results": results,
            "success_check": goal_check,
        }
    }


def _rebuild_results(payload) -> Optional[list]:
    from velora.sil.scanner import ScanResult, Severity, Vulnerability
    from velora.sil.translator import VulnType

    entries = payload.get("files") if isinstance(payload, dict) else payload
    if not isinstance(entries, list):
        return None
    results = []
    for file_data in entries:
        if not isinstance(file_data, dict):
            continue
        result = ScanResult(
            filename=str(file_data.get("filename") or ""),
            errors=list(file_data.get("errors") or []),
            warnings=list(file_data.get("warnings") or []),
            scan_time_ms=float(file_data.get("scan_time_ms") or 0),
            lines_scanned=int(file_data.get("lines_scanned") or 0),
            procedures_analyzed=int(file_data.get("procedures_analyzed") or 0),
        )
        for vuln_data in file_data.get("vulnerabilities") or []:
            if not isinstance(vuln_data, dict):
                continue
            data = dict(vuln_data)
            try:
                data["type"] = VulnType(data["type"])
                data["severity"] = Severity(data["severity"])
                result.vulnerabilities.append(Vulnerability(**data))
            except (KeyError, ValueError):
                print(
                    f"Warning: skipping finding with unknown type/severity "
                    f"in {result.filename}:{vuln_data.get('line')}",
                    file=sys.stderr,
                )
        results.append(result)
    return results


def _stage_report(ctx: ModeContext) -> Optional[Dict[str, str]]:
    from velora.modes.common import severity_rank
    from velora.sil.cli import (
        filter_min_severity,
        format_json_result,
        format_sarif_result,
        format_text_result,
        parse_severity,
    )
    from velora.tui.report import build_report

    floor_name = getattr(ctx.args, "min_severity", None) or "low"
    floor = parse_severity(floor_name)
    floor_rank = severity_rank(floor_name)
    fmt = getattr(ctx.args, "format", "text") or "text"
    results = getattr(ctx, "scan_results", None)
    if not results and ctx.session is not None:
        stored_results = ctx.session.read_json("scan-results.json", None)
        if stored_results:
            results = _rebuild_results(stored_results)
    output = getattr(ctx.args, "output", None)
    rendered: Optional[str] = None
    if results:
        filtered = [filter_min_severity(r, floor) for r in results]
        if fmt == "json":
            rendered = format_json_result(filtered)
        elif fmt == "sarif":
            rendered = format_sarif_result(filtered)
        else:
            rendered = "".join(
                format_text_result(r, floor) for r in filtered
            )
    elif fmt != "text":
        ctx.eprint(
            f"[velora] report: -f {fmt} needs the scan stage in this run "
            "(session findings are findings-only); printing markdown from "
            "the session instead"
        )
    recorded = [
        f for f in ctx.findings
        if isinstance(f, dict)
        and severity_rank(str(f.get("severity") or "")) >= floor_rank
    ]
    trace = None
    evidence = None
    if ctx.session is not None:
        stored = ctx.session.read_json("trace.json", None)
        if isinstance(stored, dict):
            trace = stored
        stored_ev = ctx.session.read_json("evidence.json", None)
        if isinstance(stored_ev, dict):
            evidence = stored_ev.get("evidence") or None
    markdown = build_report(
        recorded,
        trace=trace,
        evidence=evidence,
        meta={
            "subject": getattr(ctx.args, "target", None)
            or ctx.inputs.source or "",
            "model": (trace or {}).get("model", ""),
        },
    )
    if rendered is None:
        rendered = markdown
    if output:
        try:
            Path(output).write_text(rendered)
        except OSError as exc:
            raise GrammarError(
                EXIT_FINDINGS, f"-o: cannot write {output}: {exc}"
            ) from exc
    else:
        sys.stdout.write(rendered if rendered.endswith("\n") else rendered + "\n")
    return {"report.md": markdown}


_STAGE_RUNNERS = {
    "scope": _stage_scope,
    "ingest": _stage_ingest,
    "asset-model": _stage_asset_model,
    "code-model": _stage_code_model,
    "static-scan": _stage_static_scan,
    "dataflow": _stage_dataflow,
    "hypothesize": _stage_hypothesize,
    "triage": stage_triage,
    "plan": _stage_plan,
    "verify": _stage_verify,
    "exploit": stage_exploit,
    "fix": _stage_fix,
    "rescan": _stage_rescan,
    "validate": _stage_validate,
    "report": _stage_report,
}
