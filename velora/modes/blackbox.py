"""BLACKBOX orchestrator: the §4 14-stage active graph (Phase 2).

Target-first run order: SCOPE → AUTH → RECON → ASSET DISCOVERY → SURFACE →
ENUMERATION → SERVICE MAPPING → HUNT → TRIAGE → VERIFY → EXPLOIT →
CAPTURE → VALIDATE → REPORT.

All probing rides one scoped, rate- and budget-bounded HttpClient: the
allow-list defaults to the target's own origin (§12), verbs are inert unless
--active, and budget exhaustion is a normal stop (exit 0 once the gate
runs). Detectors emit a finding only after ≥2 reproductions (§7.1 evidence,
kind=reqresp). SERVICE MAPPING runs the Phase 4 network adapter: bounded
TCP connect scan of in-scope hosts (no raw/SYN sockets) with passive
banner reads, TLS handshake probes, and budget-charged HTTP HEAD
classification of web services on non-standard ports.
"""

from __future__ import annotations

import sys
from dataclasses import asdict
from pathlib import Path
from typing import Dict, List, Optional
from urllib.parse import urlparse

from velora.modes.common import (
    EXIT_FINDINGS,
    EXIT_USAGE,
    NA,
    GrammarError,
    ModeContext,
    check_dynamic_inputs,
    execute_stage_loop,
    preload_findings,
    run_mode_shell,
    run_oracle,
    runtime_na,
    severity_rank,
    stage_exploit,
    stage_triage,
    working_set,
)

DEFAULT_RATE = 20.0
DEFAULT_DEPTH = 2
DEFAULT_PAGES = 50
DEFAULT_BUDGET = 500


def run(args) -> int:
    return run_mode_shell("blackbox", args, executor=execute)


def execute(ctx: ModeContext) -> None:
    """Run the resolved blackbox plan; run_mode_shell owns grammar,
    interrupts, and the severity gate around this."""
    plan = list(ctx.selection.plan) if ctx.selection is not None else []
    preload_findings(ctx, "hunt")
    ctx.inputs.findings = len(ctx.findings)
    if "hunt" not in plan:
        check_dynamic_inputs(ctx.mode, ctx.selection, ctx.inputs)

    def after_stage(c: ModeContext, stage: str) -> None:
        if stage == "hunt":
            check_dynamic_inputs(c.mode, c.selection, c.inputs)

    execute_stage_loop(ctx, _STAGE_RUNNERS, after_stage=after_stage)


# ---------------------------------------------------------------------------
# Inputs: targets, scope, auth, client (one per run, cached on ctx)
# ---------------------------------------------------------------------------

def _ensure_scheme(url: str) -> str:
    url = url.strip()
    if not url:
        return url
    if "://" not in url:
        return "https://" + url
    return url


def _target_urls(ctx: ModeContext) -> List[str]:
    """TARGET is a URL, a bare host, or a file of one URL per line (§8.4)."""
    raw = (ctx.inputs.target or "").strip()
    if not raw:
        return []
    if "://" in raw:
        return [raw]
    path = Path(raw)
    if path.is_file():
        try:
            lines = path.read_text(encoding="utf-8").splitlines()
        except OSError as exc:
            raise GrammarError(
                EXIT_FINDINGS, f"TARGET: cannot read {raw}: {exc}"
            ) from exc
        return [
            _ensure_scheme(line)
            for line in lines
            if line.strip() and not line.lstrip().startswith("#")
        ]
    return [_ensure_scheme(raw)]


def _scope_hosts(ctx: ModeContext) -> List[str]:
    """Allow-list: every TARGET host (same-origin default) + --scope(file)."""
    from velora.active.client import normalize_host

    entries: List[str] = list(_target_urls(ctx))
    entries.extend(getattr(ctx.args, "scope", None) or [])
    scope_file = getattr(ctx.args, "scope_file", None)
    if scope_file:
        try:
            text = (
                sys.stdin.read() if scope_file == "-"
                else Path(scope_file).read_text()
            )
        except OSError as exc:
            raise GrammarError(
                EXIT_FINDINGS, f"--scope-file: cannot read {scope_file}: {exc}"
            ) from exc
        entries.extend(
            line for line in text.splitlines()
            if line.strip() and not line.lstrip().startswith("#")
        )
    hosts: List[str] = []
    for entry in entries:
        host = normalize_host(str(entry))
        if host and host not in hosts:
            hosts.append(host)
    return hosts


def _auth(ctx: ModeContext):
    cached = getattr(ctx, "_bb_auth", None)
    if cached is not None:
        return cached
    from velora.active.session import AuthFormatError, build_auth, replay_auth_refs

    try:
        material = build_auth(
            getattr(ctx.args, "header", None),
            getattr(ctx.args, "auth_file", None),
        )
    except AuthFormatError as exc:
        message = str(exc)
        code = EXIT_USAGE if message.startswith("--header") else EXIT_FINDINGS
        raise GrammarError(code, message) from exc
    if ctx.session is not None:
        stored = ctx.session.read_json("auth.json", None)
        if isinstance(stored, dict) and stored.get("refs"):
            extra, unreplayable = replay_auth_refs(stored["refs"], material)
            for name, value in extra.items():
                material.headers.setdefault(name, value)
            for name in unreplayable:
                ctx.eprint(
                    f"[velora] auth: {name!r} not replayable on resume "
                    "(pass --header/--auth-script again)"
                )
    scripts = getattr(ctx.args, "auth_script", None) or []
    selection = getattr(ctx, "selection", None)
    plan = list(getattr(selection, "plan", None) or []) if selection else []
    if scripts and plan and "auth" not in plan and not getattr(
        ctx, "_bb_auth_script_warned", False
    ):
        ctx._bb_auth_script_warned = True
        ctx.eprint(
            "[velora] auth: --auth-script ignored (auth stage not selected; "
            "include it or drop the flag)"
        )
    ctx._bb_auth = material
    return material


def _client(ctx: ModeContext):
    cached = getattr(ctx, "_bb_client", None)
    if cached is not None:
        return cached
    from velora.active.client import HttpClient

    hosts = _scope_hosts(ctx)
    if not hosts:
        raise GrammarError(
            EXIT_FINDINGS, "no in-scope hosts (pass TARGET and/or --scope)"
        )
    args = ctx.args
    rate = getattr(args, "rate", None)
    if rate is None:
        rate = DEFAULT_RATE
    budget = getattr(args, "http_budget", None)
    if budget is None:
        budget = getattr(args, "budget", None)
    if budget is None:
        budget = DEFAULT_BUDGET
    script_used = int(getattr(ctx, "_bb_budget_used", 0) or 0)
    if script_used:
        # one budget per run (§8.4): scripted login requests already spent
        budget = max(1, int(budget) - script_used)
    client = HttpClient(
        hosts,
        rate=rate,
        budget=budget,
        proxy=getattr(args, "proxy", None),
        insecure=bool(getattr(args, "insecure", False)),
        user_agent=getattr(args, "user_agent", None),
        headers=_auth(ctx).headers,
        allow_active=bool(getattr(args, "active", False)),
    )
    ctx._bb_client = client
    return client


def _recon(ctx: ModeContext) -> Optional[Dict]:
    payload = getattr(ctx, "_bb_recon", None)
    if isinstance(payload, dict):
        return payload
    if ctx.session is not None:
        stored = ctx.session.read_json("recon.json", None)
        if isinstance(stored, dict):
            return stored
    return None


def _surface(ctx: ModeContext) -> Optional[Dict]:
    payload = getattr(ctx, "_bb_surface", None)
    if isinstance(payload, dict):
        return payload
    if ctx.session is not None:
        stored = ctx.session.read_json("surface.json", None)
        if isinstance(stored, dict):
            return stored
    return None


# ---------------------------------------------------------------------------
# Stage runners
# ---------------------------------------------------------------------------

def _stage_scope(ctx: ModeContext) -> Dict[str, object]:
    hosts = _scope_hosts(ctx)
    if not hosts:
        raise GrammarError(
            EXIT_FINDINGS, "no in-scope hosts (pass TARGET and/or --scope)"
        )
    return {
        "scope.json": {
            "source": None,
            "target": ctx.inputs.target,
            "hosts": hosts,
            "policy": "same-origin default; --scope widens; off-list refused",
        }
    }


def _base_url(ctx: ModeContext) -> str:
    urls = _target_urls(ctx)
    if not urls:
        raise GrammarError(
            EXIT_FINDINGS, "--auth-script: TARGET is required"
        )
    return urls[0]


def _script_client(ctx: ModeContext, flows) -> object:
    """Scoped client for login scripts: active verbs + cookie jar allowed."""
    from velora.active.client import HttpClient

    hosts = _scope_hosts(ctx)
    if not hosts:
        raise GrammarError(
            EXIT_FINDINGS, "no in-scope hosts (pass TARGET and/or --scope)"
        )
    args = ctx.args
    rate = getattr(args, "rate", None)
    if rate is None:
        rate = DEFAULT_RATE
    budget = sum(len(flow.steps) for _, _, flow in flows) + 2
    return HttpClient(
        hosts,
        rate=rate,
        budget=budget,
        proxy=getattr(args, "proxy", None),
        insecure=bool(getattr(args, "insecure", False)),
        user_agent=getattr(args, "user_agent", None),
        headers=dict(_auth(ctx).headers),
        allow_active=True,
        cookie_jar=True,
    )


def _stage_auth(ctx: ModeContext) -> Dict[str, object]:
    from velora.active.loginflow import FlowFormatError, FlowRunError, load_flow, run_flow
    from velora.active.session import AuthFormatError, parse_role_spec

    material = _auth(ctx)
    script_specs = list(getattr(ctx.args, "auth_script", None) or [])
    ran: List[Dict[str, object]] = []
    if script_specs:
        cli_names = {
            str(spec).partition(":")[0].strip().lower()
            for spec in (getattr(ctx.args, "header", None) or ())
            if str(spec).partition(":")[0].strip()
        }
        cli_snapshot = {
            key: value for key, value in material.headers.items()
            if key.lower() in cli_names
        }
        flows = []
        try:
            for raw in script_specs:
                role, path = parse_role_spec(str(raw), "--auth-script")
                flows.append((role, path, load_flow(path)))
        except (AuthFormatError, FlowFormatError) as exc:
            raise GrammarError(EXIT_FINDINGS, str(exc)) from exc
        client = _script_client(ctx, flows)
        for role, path, flow in flows:
            try:
                headers = run_flow(client, flow, _base_url(ctx))
            except FlowRunError as exc:
                raise GrammarError(EXIT_FINDINGS, str(exc)) from exc
            material.roles.setdefault(role, {}).update(headers)
            # CLI --header always wins over script output for its names
            material.headers.update(cli_snapshot)
            material.refs.append({
                "kind": "auth-script",
                "name": str(path),
                "ref": f"file:{path}",
                "role": role,
            })
            ran.append({
                "name": str(path),
                "role": role,
                "steps": len(flow.steps),
                "headers": sorted(headers),
            })
        ctx._bb_budget_used = client.requests_made
    if ctx.session is not None:
        for ref in material.refs:
            ctx.session.record_secret_ref(
                str(ref.get("kind") or ""),
                str(ref.get("name") or ""),
                str(ref.get("ref") or ""),
            )
    payload: Dict[str, object] = {
        "refs": material.refs,
        "headers": sorted(material.headers),
        "count": len(material.headers),
    }
    if set(material.roles) != {"default"}:
        payload["roles"] = {
            role: sorted(headers)
            for role, headers in sorted(material.roles.items())
        }
    if ran:
        payload["scripts"] = ran
    return {"auth.json": payload}


def _stage_intel(ctx: ModeContext) -> Dict[str, object]:
    """Off-default: DNS + header fingerprint (no crawling)."""
    from velora.active.intel import fingerprint_target

    urls = _target_urls(ctx)
    first = urls[0] if urls else ""
    client = _client(ctx) if first and _scope_hosts(ctx) else None
    return {"intel.json": fingerprint_target(first, client)}


def _osint_ports(ctx: ModeContext) -> List[int]:
    """TLS ports worth a certificate grab: https targets + 443."""
    ports: List[int] = []
    for url in _target_urls(ctx):
        parts = urlparse(url)
        if parts.scheme != "https":
            continue
        try:
            port = int(parts.port or 443)
        except ValueError:
            port = 443
        if port not in ports:
            ports.append(port)
    if 443 not in ports:
        ports.append(443)
    return ports[:3]


def _stage_osint(ctx: ModeContext) -> object:
    """Off-default (--with-osint): public-source identifiers — cert + DNS."""
    from velora.active.osint import collect_osint

    hosts = _scope_hosts(ctx)
    if not hosts:
        runtime_na(ctx, "osint", "no in-scope hosts")
        return NA
    return {"osint.json": collect_osint(hosts, cert_ports=_osint_ports(ctx))}


def _stage_deepthink(ctx: ModeContext) -> Dict[str, object]:
    """Off-default in blackbox: the shared hypothesis-ledger engine."""
    from velora.modes.loop import stage_deepthink

    return stage_deepthink(ctx)


def _stage_search(ctx: ModeContext) -> Dict[str, object]:
    """Off-default in blackbox: gap snapshot (the ↺ loop itself is bughunt)."""
    from velora.modes.loop import stage_search

    return stage_search(ctx)


def _stage_recon(ctx: ModeContext) -> Dict[str, object]:
    from velora.active.recon import crawl

    client = _client(ctx)
    seeds: List[str] = []
    for url in _target_urls(ctx):
        if client.in_scope(url):
            seeds.append(url)
        else:
            ctx.eprint(f"[velora] recon: seed out of scope, skipping: {url}")
    for seed in getattr(ctx.args, "seed", None) or ():
        if client.in_scope(seed):
            seeds.append(seed)
        else:
            ctx.eprint(f"[velora] recon: seed out of scope, skipping: {seed}")
    if not seeds:
        raise GrammarError(EXIT_FINDINGS, "recon: no in-scope seed URLs")
    result = crawl(
        client,
        seeds,
        depth=getattr(ctx.args, "depth", None),
        pages=getattr(ctx.args, "pages", None),
    )
    payload = asdict(result)
    ctx._bb_recon = payload
    if result.budget_exhausted:
        ctx.eprint("[velora] recon: budget exhausted — partial results kept")
    return {"recon.json": payload}


def _stage_asset_discovery(ctx: ModeContext) -> object:
    from velora.assets.surface import recon_to_graph

    recon = _recon(ctx)
    if recon is None:
        runtime_na(ctx, "asset-discovery", "recon results unavailable")
        return NA
    origins = recon.get("origins") or []
    graph = recon_to_graph(recon, origins)
    return {"assets.json": graph.to_dict()}


def _stage_surface(ctx: ModeContext) -> object:
    from velora.assets.surface import (
        add_tech,
        finalize,
        new_surface,
        upsert_endpoint,
    )

    recon = _recon(ctx)
    if recon is None:
        runtime_na(ctx, "surface", "recon results unavailable")
        return NA
    surface = new_surface(recon.get("origins") or [])
    for page in recon.get("pages") or []:
        upsert_endpoint(
            surface,
            page.get("url") or "",
            status=page.get("status"),
            depth=page.get("depth"),
            content_type=page.get("content_type"),
            title=page.get("title"),
        )
    for url, data in (recon.get("endpoints") or {}).items():
        upsert_endpoint(
            surface,
            url,
            methods=data.get("methods"),
            params=data.get("params"),
        )
    for url in recon.get("discovered") or []:
        upsert_endpoint(surface, url)
    surface["api_ops"] = list(recon.get("api_ops") or [])
    tech_store = recon.get("tech") or {}
    add_tech(surface, tech_store.get("tech") or tech_store)
    finalize(surface)
    ctx._bb_surface = surface
    return {"surface.json": surface}


def _stage_enumerate(ctx: ModeContext) -> object:
    from velora.active.probe import enumerate_surface
    from velora.assets.surface import api_coverage

    surface = _surface(ctx)
    if surface is None:
        runtime_na(ctx, "enumerate", "surface results unavailable")
        return NA
    client = _client(ctx)
    stats = enumerate_surface(client, surface)
    stats.update(api_coverage(surface))
    ctx._bb_surface = surface
    return {"surface.json": surface, "enumerate.json": stats}


def _stage_service_mapping(ctx: ModeContext) -> Dict[str, object]:
    """Phase 4 full adapter: TCP connect scan + banner + TLS + HEAD probe."""
    from velora.active.services import DEFAULT_PORTS, collect_services

    recon = _recon(ctx) or {}
    recon_entries: Dict[tuple, Dict[str, object]] = {}
    for origin in recon.get("origins") or []:
        parts = urlparse(origin)
        host = (parts.hostname or "").lower()
        if not host:
            continue
        scheme = parts.scheme or "http"
        port = parts.port or (443 if scheme == "https" else 80)
        recon_entries[(host, int(port))] = {
            "host": host, "port": int(port), "scheme": scheme,
            "source": "recon",
        }
    hosts = _scope_hosts(ctx)
    ports = sorted({int(p) for p in DEFAULT_PORTS} | {
        int(key[1]) for key in recon_entries
    })
    client = _client(ctx)
    scan = collect_services(hosts, ports, client=client)
    by_key = {(str(s["host"]), int(s["port"])): s
              for s in scan["services"]}
    services: List[Dict[str, object]] = []
    for key, entry in sorted(by_key.items(), key=lambda kv: kv[0]):
        merged = dict(entry)
        source = "scan"
        if key in recon_entries:
            source = "recon+scan"
            merged.setdefault("scheme", recon_entries[key]["scheme"])
        merged["source"] = source
        services.append(merged)
    for key, entry in sorted(recon_entries.items(), key=lambda kv: kv[0]):
        if key in by_key:
            continue
        services.append(dict(entry))
    return {
        "service-map.json": {
            "capability": "full",
            "note": (
                "TCP connect scan (no raw/SYN sockets) + passive banner + "
                "TLS handshake + HTTP HEAD probe"
            ),
            "services": services,
            "stats": scan["stats"],
            "tech": recon.get("tech") or {},
            "hosts": len(hosts),
        }
    }


def _stage_hunt(ctx: ModeContext) -> object:
    from velora.active.client import BudgetExhausted, ScopeRefused
    from velora.active.probe import DETECTORS

    surface = _surface(ctx)
    if surface is None:
        runtime_na(ctx, "hunt", "surface results unavailable")
        return NA
    client = _client(ctx)
    findings: List[Dict] = []
    stopped = None
    for detector in DETECTORS:
        try:
            findings.extend(detector(client, surface))
        except BudgetExhausted:
            stopped = "budget"
            ctx.eprint(
                "[velora] hunt: budget exhausted — keeping partial results"
            )
            break
        except ScopeRefused:
            continue
    ctx.add_findings(findings)
    ctx._bb_surface = surface
    by_detector: Dict[str, int] = {}
    for finding in findings:
        key = str(finding.get("detector") or "unknown")
        by_detector[key] = by_detector.get(key, 0) + 1
    return {
        "hunt.json": {
            "count": len(findings),
            "detectors": by_detector,
            "repro": 2,
            "stopped": stopped,
            "budget_exhausted": client.budget_exhausted,
        },
        "surface.json": surface,
    }


def _stage_verify(ctx: ModeContext) -> Dict[str, object]:
    from velora.active.client import BudgetExhausted
    from velora.active.probe import recheck

    client = _client(ctx)
    proofs: List[Dict[str, object]] = []
    reproduced = 0
    exhausted = False
    for finding in working_set(ctx):
        entry: Dict[str, object] = {
            "title": finding.get("title"),
            "detector": finding.get("detector"),
            "location": finding.get("location"),
            "cwe_id": finding.get("cwe_id") or finding.get("cwe"),
            "type": finding.get("type"),
            "confidence": finding.get("confidence"),
        }
        if not finding.get("detector"):
            entry["ok"] = None
            entry["reason"] = "no detector (not re-runnable)"
        elif exhausted:
            entry["ok"] = None
            entry["reason"] = "budget exhausted"
        else:
            try:
                ok = recheck(client, finding)
            except BudgetExhausted:
                exhausted = True
                entry["ok"] = None
                entry["reason"] = "budget exhausted"
            else:
                entry["ok"] = bool(ok)
                if ok:
                    reproduced += 1
        proofs.append(entry)
    return {
        "verify.json": {
            "checked": len(proofs),
            "reproduced": reproduced,
            "proofs": proofs,
            "success_check": (
                run_oracle(getattr(ctx.args, "success_check", None))
                if getattr(ctx.args, "success_check", None) else None
            ),
        }
    }


def _stage_capture(ctx: ModeContext) -> Dict[str, object]:
    """Persist the redacted request/response evidence trail (§7.1)."""
    client = getattr(ctx, "_bb_client", None)
    evidence = client.export_evidence() if client is not None else []
    payload = {
        "requests": client.requests_made if client is not None else 0,
        "budget": client.budget if client is not None else None,
        "remaining": (
            client.remaining_budget() if client is not None else None
        ),
        "evidence_count": len(evidence),
        "dropped": client.evidence_dropped if client is not None else 0,
        "budget_exhausted": (
            client.budget_exhausted if client is not None else False
        ),
        "evidence": evidence,
    }
    return {"evidence.json": payload}


def _stage_validate(ctx: ModeContext) -> Dict[str, object]:
    """Independent re-check: fresh probes against every finding (§4)."""
    from velora.active.client import BudgetExhausted
    from velora.active.probe import recheck

    client = _client(ctx)
    results: List[Dict[str, object]] = []
    reproduced = 0
    exhausted = False
    for finding in working_set(ctx):
        entry: Dict[str, object] = {
            "title": finding.get("title"),
            "location": finding.get("location"),
            "type": finding.get("type"),
        }
        detector = finding.get("detector")
        if not detector:
            entry["reproduced"] = False
            entry["reason"] = "no detector (not re-runnable)"
        elif exhausted:
            entry["reproduced"] = False
            entry["reason"] = "budget exhausted"
        else:
            try:
                ok = recheck(client, finding)
            except BudgetExhausted:
                exhausted = True
                entry["reproduced"] = False
                entry["reason"] = "budget exhausted"
            else:
                entry["reproduced"] = bool(ok)
                if ok:
                    reproduced += 1
        results.append(entry)
    return {
        "validate.json": {
            "checked": len(results),
            "reproduced": reproduced,
            "results": results,
            "success_check": (
                run_oracle(getattr(ctx.args, "success_check", None))
                if getattr(ctx.args, "success_check", None) else None
            ),
        }
    }


def _stage_report(ctx: ModeContext) -> Optional[Dict[str, str]]:
    from velora.tui.report import (
        build_report,
        render_findings_json,
        render_findings_sarif,
    )

    floor_name = getattr(ctx.args, "min_severity", None) or "low"
    floor_rank = severity_rank(floor_name)
    fmt = getattr(ctx.args, "format", "text") or "text"
    recorded = [
        f for f in ctx.findings
        if isinstance(f, dict)
        and severity_rank(str(f.get("severity") or "")) >= floor_rank
    ]
    if fmt == "json":
        rendered = render_findings_json(recorded, mode="blackbox")
    elif fmt == "sarif":
        rendered = render_findings_sarif(recorded, mode="blackbox")
    else:
        trace = None
        evidence = None
        if ctx.session is not None:
            stored = ctx.session.read_json("trace.json", None)
            if isinstance(stored, dict):
                trace = stored
            stored_ev = ctx.session.read_json("evidence.json", None)
            if isinstance(stored_ev, dict):
                evidence = stored_ev.get("evidence") or None
        rendered = build_report(
            recorded,
            trace=trace,
            evidence=evidence,
            meta={
                "subject": ctx.inputs.target or "",
                "model": (trace or {}).get("model", ""),
            },
        )
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


def _stage_plan(ctx: ModeContext) -> Dict[str, object]:
    """Off-default: attack leads + candidate endpoints (§7.3 surface[])."""
    from velora.sil.llm_exploit import guidance_from_finding

    surface = _surface(ctx) or {}
    endpoints = list(surface.get("endpoints") or {})[:20]
    leads: List[Dict[str, object]] = []
    for finding in working_set(ctx):
        lead: Dict[str, object] = dict(guidance_from_finding(finding))
        merged = list(dict.fromkeys(
            list(lead.get("surface") or []) + endpoints
        ))
        lead["surface"] = merged[:8]
        leads.append(lead)
    if any(lead.get("provenance") == "symbolic" for lead in leads):
        provenance = "symbolic"
    elif any(lead.get("provenance") == "dynamic" for lead in leads):
        provenance = "dynamic"
    else:
        provenance = "llm"
    return {
        "guidance.json": {
            "leads": leads,
            "provenance": provenance,
            "goal": getattr(ctx.args, "goal", None),
            "surface": endpoints,
        }
    }


_STAGE_RUNNERS = {
    "scope": _stage_scope,
    "auth": _stage_auth,
    "intel": _stage_intel,
    "osint": _stage_osint,
    "recon": _stage_recon,
    "asset-discovery": _stage_asset_discovery,
    "surface": _stage_surface,
    "enumerate": _stage_enumerate,
    "service-mapping": _stage_service_mapping,
    "hunt": _stage_hunt,
    "triage": stage_triage,
    "deepthink": _stage_deepthink,
    "plan": _stage_plan,
    "verify": _stage_verify,
    "exploit": stage_exploit,
    "capture": _stage_capture,
    "validate": _stage_validate,
    "search": _stage_search,
    "report": _stage_report,
}
