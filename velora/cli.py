#!/usr/bin/env python3
"""
Velora CLI - Separation Logic Verification Tool.

A unified command-line interface for Velora's capabilities:
- scan: Scan source code for security vulnerabilities
- solve: Solve separation logic entailments
- check: Check specific entailment queries
- parse: Parse and display formula AST

Usage:
    velora scan app.py                    # Scan for vulnerabilities
    velora solve "x |-> 5 |- x |-> 5"     # Check entailment
    velora check entailments.txt          # Check batch of entailments
    velora parse "x |-> 5 * y |-> 3"      # Parse and display formula
"""

import argparse
import os
import sys
import json
import time
from pathlib import Path
from typing import List, Optional

# Import version from main package (single source of truth)
from velora import __version__


def create_parser() -> argparse.ArgumentParser:
    """Create the main argument parser"""
    parser = argparse.ArgumentParser(
        prog="velora",
        description="Velora - Separation Logic Verification Tool",
        epilog="Use 'velora <command> --help' for more information on a specific command.",
    )

    parser.add_argument(
        "-V", "--version",
        action="version",
        version=f"%(prog)s {__version__}"
    )

    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # === SCAN command ===
    scan_parser = subparsers.add_parser(
        "scan",
        help="Scan source code for security vulnerabilities",
        description="Scan source files for vulnerabilities using taint analysis and verification."
    )
    scan_parser.add_argument(
        "target",
        help="File or directory to scan"
    )
    scan_parser.add_argument(
        "-l", "--language",
        default="python",
        help="Source language (default: python). Symbolic frontends: python, "
             "javascript, typescript, java, c, cpp, csharp. Any other language "
             "(e.g. php, ruby, go) runs LLM-detect only under --ai. Files are "
             "auto-detected by extension; -l is the fallback for unknown ones."
    )
    scan_parser.add_argument(
        "-p", "--pattern",
        default="**/*.py",
        help="Glob pattern for directory scan (default: **/*.py)"
    )
    scan_parser.add_argument(
        "--no-default-excludes",
        action="store_true",
        help="Directory scans skip agent/tool state and dependency "
             "directories by default (.git, .claude/worktrees, "
             ".cursor/worktrees, .worktrees, .idea, .vscode, node_modules, "
             ".venv, venv [only if it looks like a virtualenv], .tox, "
             "__pycache__, .mypy_cache, .pytest_cache). Pass this to scan "
             "them too."
    )
    scan_parser.add_argument(
        "-f", "--format",
        default="text",
        choices=["text", "json", "sarif"],
        help="Output format (default: text)"
    )
    scan_parser.add_argument(
        "-o", "--output",
        help="Output file (default: stdout)"
    )
    scan_parser.add_argument(
        "--no-verify",
        action="store_true",
        help="Skip Velora verification (faster, may have false positives)"
    )
    scan_parser.add_argument(
        "--min-severity",
        default="low",
        choices=["critical", "high", "medium", "low", "info"],
        help="Minimum severity to report (default: low)"
    )
    scan_parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Verbose output"
    )
    scan_parser.add_argument(
        "--timeout",
        type=int,
        default=5000,
        help="Verification timeout in ms (default: 5000)"
    )
    scan_parser.add_argument(
        "--fail-on",
        choices=["critical", "high", "medium", "low", "any", "none"],
        default="high",
        help="Exit with error if vulnerabilities of this severity found (default: high)"
    )
    scan_parser.add_argument(
        "--ai",
        action="store_true",
        help="Enable the AI layer (LLM detection + triage). Needs VELORA_LLM_BASE_URL "
             "and VELORA_LLM_MODEL, e.g. a local mlx-optiq or any OpenAI-compatible endpoint"
    )
    scan_parser.add_argument(
        "--llm-detect",
        action="store_true",
        help="Enable LLM detection only (adds findings the symbolic engine misses)"
    )
    scan_parser.add_argument(
        "--llm-triage",
        action="store_true",
        help="Enable LLM triage only (drops confident false positives)"
    )
    scan_parser.add_argument(
        "--model",
        help="Override VELORA_LLM_MODEL for this scan (same as setting the env var)"
    )
    scan_parser.add_argument(
        "--no-tui", action="store_true",
        help="Run plain even on a terminal (default on a TTY: live TUI; "
             "pipes/redirects always stay plain). VELORA_TUI=0 also disables."
    )
    scan_parser.add_argument(
        "--curses", action="store_true",
        help="Open the classic curses TUI instead of the default "
             "PentestGPT-style interface (TTY only)."
    )

    # === EXPLOIT command ===
    exploit_parser = subparsers.add_parser(
        "exploit",
        help="Drive an LLM agent to exploit a live target (authorized use only)",
        description="Run the neuro-symbolic exploitation agent against a live, in-scope "
                    "target. Optionally prime it with a Velora findings JSON (from "
                    "`velora scan --ai -f json`) so it attacks the localized flaw."
    )
    exploit_parser.add_argument(
        "--target", required=True,
        help="Target under test, e.g. http://app:8080 (must be authorized/in-scope)"
    )
    exploit_parser.add_argument(
        "--goal",
        help="Objective / success condition in words (default: read a secret, run a "
             "command, or modify server state)"
    )
    exploit_parser.add_argument(
        "--guidance",
        help="Velora findings JSON to prime the agent (file path, or '-' for stdin). "
             "Pipe from `velora scan --ai -f json`."
    )
    exploit_parser.add_argument(
        "--success-check",
        help="Shell command re-run after each step; exit 0 means solved (success "
             "oracle). Omit to let the agent self-terminate on its guarded "
             "`VERIFIED: <evidence>` claim instead."
    )
    exploit_parser.add_argument(
        "--max-steps", type=int, default=40,
        help="Maximum agent steps (default: 40)"
    )
    exploit_parser.add_argument(
        "--exec-timeout", type=int, default=120,
        help="Per-command execution timeout in seconds (default: 120)"
    )
    exploit_parser.add_argument(
        "--model",
        help="Override VELORA_LLM_MODEL for this run"
    )
    exploit_parser.add_argument(
        "--format", default="text", choices=["text", "json"],
        help="Output format (default: text)"
    )
    exploit_parser.add_argument(
        "--trace-out",
        help="Write the full agent trace (system prompt, guidance, every tool call "
             "and result) as JSON to this file -- useful for comparing model behavior."
    )
    exploit_parser.add_argument(
        "--no-tui", action="store_true",
        help="Run plain even on a terminal (default on a TTY: live TUI with agent "
             "feed, findings, and in-TUI report; pipes stay plain). "
             "VELORA_TUI=0 also disables."
    )
    exploit_parser.add_argument(
        "--curses", action="store_true",
        help="Open the classic curses TUI instead of the default "
             "PentestGPT-style interface (TTY only)."
    )

    # === REPORT command ===
    report_parser = subparsers.add_parser(
        "report",
        help="Build a markdown report from findings JSON (+ optional exploit trace)",
        description="Assemble `velora scan -o FILE -f json` findings and an "
                    "`velora exploit --trace-out FILE` trace into one markdown "
                    "report. On a TTY it opens a preview (j/k scroll, s save); "
                    "with -o or a pipe it emits markdown directly."
    )
    report_parser.add_argument(
        "findings", nargs="*",
        help="Findings JSON files (single-file, multi-file, or bare list)"
    )
    report_parser.add_argument(
        "--trace-out",
        help="Exploit trace JSON written by `velora exploit --trace-out`"
    )
    report_parser.add_argument(
        "-o", "--output",
        help="Write markdown to this file (default: TTY preview / stdout)"
    )
    report_parser.add_argument(
        "--subject",
        help="Subject line for the report header (target URL / app name)"
    )

    # === FIX command ===
    fix_parser = subparsers.add_parser(
        "fix",
        help="Generate (and verify) security fixes for scan findings",
        description="Remediate vulnerabilities found by `velora scan`. Generates a "
                    "minimal patch per finding, then VERIFIES it by re-scanning the "
                    "patched code -- Velora confirms the vulnerability is gone."
    )
    fix_parser.add_argument(
        "source", help="Source file or directory the findings refer to"
    )
    fix_parser.add_argument(
        "--guidance", required=True,
        help="Velora findings JSON to fix (file path, or '-' for stdin). Pipe from "
             "`velora scan --ai -f json`."
    )
    fix_parser.add_argument(
        "--in-place", action="store_true",
        help="Write the patches to the files (default: print a unified diff instead)"
    )
    fix_parser.add_argument(
        "--diff", action="store_true",
        help="Print a unified diff of the patches (the default when --in-place is off)"
    )
    fix_parser.add_argument(
        "--no-verify", action="store_true",
        help="Skip re-scanning the patched code to confirm the fix (verify is on by default)"
    )
    fix_parser.add_argument(
        "--model", help="Override VELORA_LLM_MODEL for this run"
    )
    fix_parser.add_argument(
        "--format", default="text", choices=["text", "json"],
        help="Output format (default: text)"
    )

    # === SOLVE command ===
    solve_parser = subparsers.add_parser(
        "solve",
        help="Check separation logic entailments",
        description="Check if a separation logic entailment P |- Q is valid."
    )
    solve_parser.add_argument(
        "entailment",
        nargs="?",
        help="Entailment to check (e.g., 'x |-> 5 |- x |-> 5')"
    )
    solve_parser.add_argument(
        "-f", "--file",
        help="Read entailment from file"
    )
    solve_parser.add_argument(
        "--timeout",
        type=int,
        default=5000,
        help="Solver timeout in ms (default: 5000)"
    )
    solve_parser.add_argument(
        "--unfold-depth",
        type=int,
        default=3,
        help="Maximum predicate unfolding depth (default: 3)"
    )
    solve_parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Show detailed solving steps"
    )
    solve_parser.add_argument(
        "--format",
        default="text",
        choices=["text", "json"],
        help="Output format (default: text)"
    )
    solve_parser.add_argument(
        "--model",
        action="store_true",
        help="Show countermodel if invalid"
    )

    # === CHECK command ===
    check_parser = subparsers.add_parser(
        "check",
        help="Check batch of entailments from file",
        description="Check multiple entailments from a file (one per line)."
    )
    check_parser.add_argument(
        "file",
        help="File containing entailments (one per line)"
    )
    check_parser.add_argument(
        "--timeout",
        type=int,
        default=5000,
        help="Solver timeout in ms per entailment (default: 5000)"
    )
    check_parser.add_argument(
        "--unfold-depth",
        type=int,
        default=3,
        help="Maximum predicate unfolding depth (default: 3)"
    )
    check_parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Show detailed output for each entailment"
    )
    check_parser.add_argument(
        "--format",
        default="text",
        choices=["text", "json", "csv"],
        help="Output format (default: text)"
    )
    check_parser.add_argument(
        "-o", "--output",
        help="Output file (default: stdout)"
    )
    check_parser.add_argument(
        "--stop-on-failure",
        action="store_true",
        help="Stop checking after first invalid entailment"
    )

    # === PARSE command ===
    parse_parser = subparsers.add_parser(
        "parse",
        help="Parse and display formula structure",
        description="Parse a separation logic formula and display its AST."
    )
    parse_parser.add_argument(
        "formula",
        nargs="?",
        help="Formula to parse"
    )
    parse_parser.add_argument(
        "-f", "--file",
        help="Read formula from file"
    )
    parse_parser.add_argument(
        "--format",
        default="tree",
        choices=["tree", "json", "sexp"],
        help="Output format (default: tree)"
    )

    # === REPL command ===
    repl_parser = subparsers.add_parser(
        "repl",
        help="Interactive separation logic REPL",
        description="Start an interactive Read-Eval-Print Loop for separation logic."
    )
    repl_parser.add_argument(
        "--timeout",
        type=int,
        default=5000,
        help="Solver timeout in ms (default: 5000)"
    )

    # === models command ===
    models_parser = subparsers.add_parser(
        "models",
        help="Browse & switch AI models (OpenCode Zen free tier + models.dev)",
        description="Browse free/paid AI models and set the active one for "
                    "`velora scan --ai` (OpenCode Zen + models.dev registry)."
    )
    models_parser.add_argument(
        "models_action", nargs="?", default="list",
        choices=["list", "use", "current", "providers", "import-opencode",
                 "tui"],
        help="Action (default: list)"
    )
    models_parser.add_argument(
        "ref", nargs="?",
        help="Model ref for `use`: zen/<id>, opencode/<provider>/<model>, "
             "or <provider>/<model> (with --base-url)"
    )
    models_parser.add_argument("--free", action="store_true",
                               help="Only free models")
    models_parser.add_argument("--registry", action="store_true",
                               help="List the full models.dev registry "
                                    "(default: OpenCode Zen catalog)")
    models_parser.add_argument("--query", help="Filter by name/id substring")
    models_parser.add_argument("--provider", help="Filter by provider id")
    models_parser.add_argument("--format", default="table",
                               choices=["table", "json"], help="Output format")
    models_parser.add_argument("--refresh", action="store_true",
                               help="Re-fetch catalogs (bypass 24h cache)")
    models_parser.add_argument("--base-url",
                               help="OpenAI-compatible endpoint for `use` "
                                    "(required for unknown providers)")
    models_parser.add_argument("--api-key", help="API key for `use` "
                               "(else prompt/env/opencode)")
    models_parser.add_argument("--no-prompt", action="store_true",
                               help="Never prompt for an API key")
    models_parser.add_argument("--limit", type=int,
                               help="Max rows for `list --registry`")
    models_parser.add_argument("--local-url", action="append",
                               metavar="[NAME=]URL",
                               help="Extra local OpenAI-compatible endpoint "
                                    "for `tui` (repeatable), e.g. "
                                    "optiq=http://localhost:47317/v1")

    # === serve-bridge command ===
    serve_bridge_parser = subparsers.add_parser(
        "serve-bridge",
        help="Run the local OpenAI-compatible bridge to opencode (zero-key --ai)",
        description="Expose opencode's models (incl. free Zen tier) as a local "
                    "OpenAI-compatible server for `velora scan --ai`. opencode "
                    "holds all API keys; Velora stores none."
    )
    bridge_group = serve_bridge_parser.add_mutually_exclusive_group()
    bridge_group.add_argument("--start", dest="bridge_cmd",
                              action="store_const", const="start",
                              help="run in the background (pidfile + log)")
    bridge_group.add_argument("--stop", dest="bridge_cmd",
                              action="store_const", const="stop",
                              help="stop the background daemon")
    bridge_group.add_argument("--status", dest="bridge_cmd",
                              action="store_const", const="status",
                              help="report daemon health (exit 0 when healthy)")
    serve_bridge_parser.set_defaults(bridge_cmd=None)
    serve_bridge_parser.add_argument("--format", default="text",
                                     choices=["text", "json"],
                                     help="Output format for --status")
    serve_bridge_parser.add_argument("--port", type=int, default=8399,
                                     help="Bridge port (default: 8399)")
    serve_bridge_parser.add_argument("--opencode-port", type=int, default=4599,
                                     help="Port for the opencode server the "
                                          "bridge spawns (default: 4599)")
    serve_bridge_parser.add_argument("--configure", action="store_true",
                                     help="Persist the active model in velora "
                                          "config once the bridge is healthy")
    serve_bridge_parser.add_argument("--model",
                                     help="Model id (e.g. "
                                          "opencode/mimo-v2.6-flash-free) for "
                                          "--configure")

    # === doctor command ===
    doctor_parser = subparsers.add_parser(
        "doctor",
        help="Diagnose the zero-key AI setup (exit 1 when not ready)",
        description="Checks platform, node/opencode binaries, bridge deps, "
                    "daemon health, active model and local endpoints; each "
                    "failure comes with the exact fix command."
    )
    doctor_parser.add_argument("--probe", action="store_true",
                               help="Send one test chat through the bridge "
                                    "(slow: verifies free-tier access for real)")
    doctor_parser.add_argument("--format", default="text",
                               choices=["text", "json"],
                               help="Output format")

    # === setup command ===
    setup_parser = subparsers.add_parser(
        "setup",
        help="One-time bootstrap: install missing prerequisites (no sudo)",
        description="Runs `velora doctor`, shows exactly what it will install "
                    "(user-local Node + opencode + bridge deps), asks once, "
                    "then starts the bridge and verifies keyless access."
    )
    setup_parser.add_argument("--yes", action="store_true",
                              help="Assume yes at the consent prompt")
    setup_parser.add_argument("--no-start", action="store_true",
                              help="Do not start the bridge daemon at the end")
    setup_parser.add_argument("--no-probe", action="store_true",
                              help="Skip the live keyless probe chat")

    return parser


# ============================================================================
# SCAN Command
# ============================================================================

def _apply_model_override(args) -> None:
    """`--model` is sugar for VELORA_LLM_MODEL: setting it here means every layer
    (scan/detect/triage/exploit) reading the env picks it up. Flag beats env."""
    if getattr(args, "model", None):
        os.environ["VELORA_LLM_MODEL"] = args.model


# ---------------------------------------------------------------------------
# Live TUI gate: documented `velora exploit` / `velora scan` open the curses
# TUI on a terminal, spawn the exact same command as a piped child, and paint
# its output.  Non-TTY runs (pipes, redirects, tests) are byte-identical to
# the plain path -- the gate never fires there.
# ---------------------------------------------------------------------------

def _tui_active(args, raw_argv: List[str]) -> bool:
    if os.environ.get("VELORA_TUI_CHILD") == "1":   # we are the wrapped child
        return False
    if os.environ.get("VELORA_TUI", "1").lower() in ("0", "false", "off", "no"):
        return False
    if getattr(args, "no_tui", False) or "--no-tui" in raw_argv:
        return False
    if getattr(args, "guidance", None) == "-":      # stdin carries data, not keys
        return False
    try:
        return sys.stdin.isatty() and sys.stdout.isatty()
    except Exception:
        return False


def _run_tui_wrap(args, raw_argv: List[str]) -> int:
    """Spawn today's command as a child and hand its stream to the TUI.

    Default on a TTY: the PentestGPT-style line interface (``velora.ptui``).
    ``--curses`` (or VELORA_UI=curses) selects the classic curses view; if the
    PentestGPT interface cannot load (missing deps) or crashes, we fall back
    to curses and finally to today's plain run.
    """
    from velora.tui.render import run_tui
    from velora.tui.runner import RunSpec, TuiRunner, child_argv

    kind = args.command
    spec = RunSpec(
        argv=child_argv(list(raw_argv)),
        kind=kind,
        feed=(kind == "exploit"),
        subject=getattr(args, "target", "") or "",
        guidance_path=getattr(args, "guidance", None),
        trace_out=getattr(args, "trace_out", None),
        findings_out=(getattr(args, "output", None)
                      if getattr(args, "format", None) == "json" else None),
        env={"VELORA_TUI_CHILD": "1"},
    )
    runner = TuiRunner(spec)

    def _stop_quiet() -> None:
        try:
            if runner.child_done() is False:
                runner.stop()
        except Exception:
            pass

    use_curses = (getattr(args, "curses", False)
                  or os.environ.get("VELORA_UI", "").lower() in ("curses", "ctty"))
    if not use_curses:
        try:
            from velora.ptui import run_ptui
        except ImportError:                     # rich/prompt_toolkit absent
            run_ptui = None
        if run_ptui is not None:
            try:
                return run_ptui(runner, kind=kind, subject=spec.subject)
            except Exception:
                # PentestGPT-style view failed: stop its child, retry with a
                # fresh runner under the classic curses view.
                _stop_quiet()
                runner = TuiRunner(spec)
    try:
        return run_tui(runner, kind=kind, subject=spec.subject)
    except Exception:
        # curses unavailable (TERM=dumb etc.): fall back to today's plain run
        # with inherited stdio -- same bytes the user would have gotten.
        _stop_quiet()
        import subprocess
        env = dict(os.environ)
        env.update(spec.env)
        return subprocess.call([sys.executable, "-m", "velora", *raw_argv],
                               env=env)


def cmd_report(args) -> int:
    """Assemble findings JSON (+ optional exploit trace) into a markdown report."""
    from velora.tui.report import build_report, load_findings, load_trace

    findings: List[dict] = []
    for path in args.findings or []:
        try:
            findings.extend(load_findings(path))
        except Exception as exc:  # noqa: BLE001
            print(f"Error reading {path}: {exc}", file=sys.stderr)
            return 1
    trace = None
    if args.trace_out:
        try:
            trace = load_trace(args.trace_out)
        except Exception as exc:  # noqa: BLE001
            print(f"Error reading {args.trace_out}: {exc}", file=sys.stderr)
            return 1
    md = build_report(findings, trace=trace,
                      meta={"subject": args.subject or "",
                            "model": (trace or {}).get("model", "")})
    if args.output:
        try:
            Path(args.output).write_text(md, encoding="utf-8")
        except Exception as exc:  # noqa: BLE001
            print(f"Error writing {args.output}: {exc}", file=sys.stderr)
            return 1
        print(f"report written to {args.output} "
              f"({len(findings)} finding{'s' if len(findings) != 1 else ''})")
        return 0
    try:
        to_tty = sys.stdout.isatty()
    except Exception:
        to_tty = False
    if to_tty and (findings or trace):
        from velora.tui.render import preview_markdown
        saved = preview_markdown(md)
        if saved:
            print(f"report saved to {saved}")
        return 0
    print(md, end="")
    return 0


def cmd_scan(args, _raw_argv: Optional[List[str]] = None) -> int:
    """Execute scan command"""
    _apply_model_override(args)
    raw = list(_raw_argv) if _raw_argv is not None else list(sys.argv[1:])
    if _tui_active(args, raw):
        return _run_tui_wrap(args, raw)
    # Delegate to the SIL scanner CLI
    from velora.sil.cli import cmd_scan as sil_scan
    return sil_scan(args)


# ============================================================================
# EXPLOIT Command
# ============================================================================

_SEVERITY_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}


def _load_findings(raw: str) -> List[dict]:
    """Flatten a `velora scan -f json` payload (single file, multi-file, or a bare
    list) into a flat list of finding dicts."""
    data = json.loads(raw)
    if isinstance(data, list):
        return data
    if isinstance(data, dict):
        if "vulnerabilities" in data:
            return data["vulnerabilities"] or []
        if "files" in data:
            out: List[dict] = []
            for f in data["files"]:
                out.extend(f.get("vulnerabilities", []) or [])
            return out
    return []


def _top_finding(findings: List[dict]) -> Optional[dict]:
    """Pick the finding most worth exploiting: highest severity, then confidence."""
    if not findings:
        return None

    def _key(f: dict):
        sev = _SEVERITY_RANK.get(str(f.get("severity", "")).lower(), 0)
        try:
            conf = float(f.get("confidence", 0) or 0)
        except (TypeError, ValueError):
            conf = 0.0
        return (sev, conf)

    return max(findings, key=_key)


def _finding_rank(f: dict):
    sev = _SEVERITY_RANK.get(str(f.get("severity", "")).lower(), 0)
    try:
        conf = float(f.get("confidence", 0) or 0)
    except (TypeError, ValueError):
        conf = 0.0
    return (sev, conf)


def _select_findings(findings: List[dict], n: int = 6) -> List[dict]:
    """Deduped top-N findings to pass as exploit leads.

    The top-1 is frequently NOT the exploitable bug: findings bunch at the same
    severity/confidence, so ranking barely discriminates and a deserialization
    finding can outrank the actual path traversal. Passing several deduped leads
    (one per distinct cwe+type+file) lets the agent attack the right surface.
    """
    ranked = sorted(findings, key=_finding_rank, reverse=True)
    seen: set = set()
    out: List[dict] = []
    for f in ranked:
        loc = str(f.get("location") or "").rsplit("/", 1)[-1]
        key = (f.get("cwe_id") or f.get("cwe"), f.get("type"), loc)
        if key in seen:
            continue
        seen.add(key)
        out.append(f)
        if len(out) >= n:
            break
    return out


def cmd_exploit(args, _raw_argv: Optional[List[str]] = None) -> int:
    """Execute exploit command - run the LLM exploitation agent against a target."""
    import subprocess
    from velora.sil.llm_client import LLMConfig
    from velora.sil.llm_exploit import (
        exploit_agentic, local_exec_tool, guidance_from_finding,
    )

    # LLM config from env (VELORA_LLM_*). --model overrides VELORA_LLM_MODEL, the
    # same single knob every layer reads (flag beats env, uniformly).
    _apply_model_override(args)
    config = LLMConfig.from_env()
    if not config.base_url or not config.model:
        print("Error: set VELORA_LLM_BASE_URL and VELORA_LLM_MODEL (an OpenAI-compatible "
              "endpoint) to use the exploit agent.", file=sys.stderr)
        return 1
    raw = list(_raw_argv) if _raw_argv is not None else list(sys.argv[1:])
    if _tui_active(args, raw):
        return _run_tui_wrap(args, raw)
    config.exploit_max_steps = args.max_steps

    # Optional guidance: findings JSON (file or '-' stdin) -> top finding -> guidance.
    guidance = None
    if args.guidance:
        try:
            raw = sys.stdin.read() if args.guidance == "-" else Path(args.guidance).read_text()
            findings = _load_findings(raw)
        except Exception as e:
            print(f"Error reading guidance findings: {e}", file=sys.stderr)
            return 1
        selected = _select_findings(findings)
        if selected:
            leads = [guidance_from_finding(f) for f in selected]
            guidance = {
                "leads": leads,
                "provenance": "symbolic" if any(l.get("provenance") == "symbolic"
                                                for l in leads) else "llm",
            }
        else:
            print("Warning: guidance provided but no findings parsed; running unguided.",
                  file=sys.stderr)

    goal = args.goal or ("Compromise the target: read a protected secret, execute a "
                         "command, or modify server state -- and prove it with observed "
                         "output.")
    task_prompt = f"Target: {args.target}\n\nObjective: {goal}"

    # Success oracle: optional shell command, exit 0 == solved. Output is captured
    # (a bare `curl` would otherwise spew its body mid-log) and shown as evidence
    # when it passes -- that observed state change is what "solved" means.
    is_solved = None
    if args.success_check:
        def is_solved() -> bool:
            try:
                proc = subprocess.run(args.success_check, shell=True, timeout=60,
                                      capture_output=True, text=True, errors="replace")
            except Exception:
                return False
            if proc.returncode == 0 and args.format == "text":
                evidence = " ".join(((proc.stdout or "") + (proc.stderr or "")).split())
                if evidence:
                    print(f"[success-check] {evidence[:120]}", flush=True)
            return proc.returncode == 0

    exec_tool = local_exec_tool(timeout=args.exec_timeout)
    result = exploit_agentic(task_prompt, config, exec_tool=exec_tool,
                             guidance=guidance, is_solved=is_solved,
                             max_steps=args.max_steps)

    out = {
        "target": args.target,
        "solved": result.solved,
        "steps": result.steps,
        "reason": result.reason,
        "guided": guidance is not None,
        "provenance": guidance.get("provenance") if guidance else None,
    }
    if getattr(args, "trace_out", None):
        try:
            with open(args.trace_out, "w") as fh:
                json.dump({"model": config.model, "summary": out,
                           "transcript": result.transcript}, fh, indent=2, default=str)
        except Exception as e:
            print(f"Warning: could not write trace to {args.trace_out}: {e}",
                  file=sys.stderr)
    if args.format == "json":
        print(json.dumps(out, indent=2))
    else:
        status = "✓ EXPLOITED" if result.solved else "✗ NOT EXPLOITED"
        print(f"{status}  (steps={result.steps}, reason={result.reason}, "
              f"guided={out['guided']}"
              + (f", lead={out['provenance']}" if guidance else "") + ")")
    return 0 if result.solved else 1


# ============================================================================
# FIX Command
# ============================================================================

_LANG_BY_EXT = {".py": "python", ".js": "javascript", ".jsx": "javascript",
                ".ts": "typescript", ".tsx": "typescript", ".java": "java",
                ".c": "c", ".h": "c", ".cpp": "cpp", ".cc": "cpp", ".cs": "csharp",
                ".php": "php", ".rb": "ruby", ".go": "go"}


def _lang_for(path: str) -> str:
    return _LANG_BY_EXT.get(os.path.splitext(path)[1].lower(), "python")


def _resolve_finding_file(loc: Optional[str], source: str) -> Optional[str]:
    """Locate a finding's file relative to the user-supplied source path."""
    if loc and os.path.isfile(loc):
        return loc
    if os.path.isfile(source):
        return source
    if loc and os.path.isdir(source):
        cand = os.path.join(source, os.path.basename(loc))
        if os.path.isfile(cand):
            return cand
    return None


def cmd_fix(args) -> int:
    """Execute fix command - generate and verify security patches for findings."""
    from collections import OrderedDict
    from velora.sil.llm_client import LLMConfig
    from velora.sil.llm_fix import generate_fix, apply_fix, make_diff, verify_fixes, FixResult

    _apply_model_override(args)
    config = LLMConfig.from_env()
    if not config.base_url or not config.model:
        print("Error: set VELORA_LLM_BASE_URL and VELORA_LLM_MODEL (an OpenAI-compatible "
              "endpoint) to use fix.", file=sys.stderr)
        return 1
    try:
        raw = sys.stdin.read() if args.guidance == "-" else Path(args.guidance).read_text()
        findings = _load_findings(raw)
    except Exception as e:
        print(f"Error reading findings: {e}", file=sys.stderr)
        return 1
    if not findings:
        print("No findings to fix.", file=sys.stderr)
        return 1

    by_file: "OrderedDict[str, list]" = OrderedDict()
    for f in findings:
        fp = _resolve_finding_file(f.get("location"), args.source)
        if fp is not None:
            by_file.setdefault(fp, []).append(f)
    if not by_file:
        print("Could not locate any finding's file under the given source path.",
              file=sys.stderr)
        return 1

    results: List[FixResult] = []
    for fp, flist in by_file.items():
        try:
            original = Path(fp).read_text()
        except Exception as e:
            print(f"Warning: cannot read {fp}: {e}", file=sys.stderr)
            continue
        patched = original
        lang = _lang_for(fp)
        file_results: List[FixResult] = []
        for f in flist:
            patch = generate_fix(f, patched, config)
            new, applied = apply_fix(patched, patch)
            if applied:
                patched = new
            file_results.append(FixResult(
                file=fp, cwe=str(f.get("cwe_id") or f.get("cwe") or ""),
                line=f.get("line") or 0, applied=applied, verified=None,
                rationale=(patch or {}).get("rationale", ""),
                original=(patch or {}).get("original", ""),
                replacement=(patch or {}).get("replacement", "")))
        # One re-scan verifies every applied finding for this file (not one per finding
        # -- per-finding re-scanning timed out on a file with 13 findings).
        if not args.no_verify and patched != original:
            applied_findings = [flist[i] for i, r in enumerate(file_results) if r.applied]
            verdicts = iter(verify_fixes(patched, lang, os.path.basename(fp),
                                         applied_findings, config))
            for r in file_results:
                if r.applied:
                    r.verified = next(verdicts, None)
        results.extend(file_results)
        if patched != original:
            if args.in_place:
                Path(fp).write_text(patched)
            elif args.format != "json":
                print(make_diff(fp, original, patched))

    applied_n = sum(1 for r in results if r.applied)
    verified_n = sum(1 for r in results if r.verified is True)
    if args.format == "json":
        print(json.dumps([{"file": r.file, "cwe": r.cwe, "line": r.line,
                           "applied": r.applied, "verified": r.verified,
                           "rationale": r.rationale} for r in results], indent=2))
    else:
        for r in results:
            v = ("verified✓" if r.verified is True else
                 "STILL DETECTED" if r.verified is False else "verify-skipped")
            print(f"  {r.cwe} {os.path.basename(r.file)}:{r.line} -> "
                  + (f"patched ({v})" if r.applied else "could not apply"))
        mode = "written in place" if args.in_place else "shown as diff"
        print(f"\n{applied_n}/{len(results)} findings patched ({mode}); "
              f"{verified_n} verified fixed by re-scan.")
    return 0 if applied_n > 0 else 1


# ============================================================================
# SOLVE Command
# ============================================================================

def cmd_solve(args) -> int:
    """Execute solve command - check a single entailment"""
    from velora import EntailmentChecker

    # Get entailment string
    if args.entailment:
        entailment = args.entailment
    elif args.file:
        try:
            entailment = Path(args.file).read_text().strip()
        except Exception as e:
            print(f"Error reading file: {e}", file=sys.stderr)
            return 1
    else:
        print("Error: Provide an entailment string or use -f to read from file", file=sys.stderr)
        return 1

    # Create checker
    checker = EntailmentChecker(timeout=args.timeout)

    if args.verbose:
        print(f"Checking: {entailment}")
        print("-" * 60)

    # Check entailment
    start_time = time.time()
    try:
        result = checker.check_entailment(entailment)
    except Exception as e:
        if args.format == "json":
            print(json.dumps({
                "entailment": entailment,
                "error": str(e),
                "valid": None
            }, indent=2))
        else:
            print(f"Error: {e}", file=sys.stderr)
        return 1

    elapsed_ms = (time.time() - start_time) * 1000

    # Output result
    if args.format == "json":
        output = {
            "entailment": entailment,
            "valid": result.valid,
            "reason": result.reason,
            "time_ms": round(elapsed_ms, 2)
        }
        if args.model and not result.valid and result.model:
            output["countermodel"] = str(result.model)
        print(json.dumps(output, indent=2))
    else:
        if result.valid:
            print(f"✓ VALID")
            if args.verbose:
                print(f"  Reason: {result.reason}")
        else:
            print(f"✗ INVALID")
            if result.reason:
                print(f"  Reason: {result.reason}")
            if args.model and result.model:
                print(f"  Countermodel: {result.model}")

        if args.verbose:
            print(f"  Time: {elapsed_ms:.2f}ms")

    return 0 if result.valid else 1


# ============================================================================
# CHECK Command
# ============================================================================

def cmd_check(args) -> int:
    """Execute check command - check batch of entailments"""
    from velora import EntailmentChecker

    # Read entailments from file
    try:
        lines = Path(args.file).read_text().strip().split('\n')
    except Exception as e:
        print(f"Error reading file: {e}", file=sys.stderr)
        return 1

    # Filter out comments and empty lines
    entailments = []
    for line in lines:
        line = line.strip()
        if line and not line.startswith('#') and not line.startswith('//'):
            entailments.append(line)

    if not entailments:
        print("No entailments found in file", file=sys.stderr)
        return 1

    # Create checker
    checker = EntailmentChecker(timeout=args.timeout)

    # Check each entailment
    results = []
    total_time = 0
    valid_count = 0
    invalid_count = 0
    error_count = 0

    for i, entailment in enumerate(entailments, 1):
        if args.verbose:
            print(f"[{i}/{len(entailments)}] Checking: {entailment}")

        start_time = time.time()
        try:
            result = checker.check_entailment(entailment)
            elapsed_ms = (time.time() - start_time) * 1000
            total_time += elapsed_ms

            if result.valid:
                valid_count += 1
                status = "valid"
            else:
                invalid_count += 1
                status = "invalid"

            results.append({
                "entailment": entailment,
                "valid": result.valid,
                "reason": result.reason,
                "time_ms": round(elapsed_ms, 2)
            })

            if args.verbose:
                symbol = "✓" if result.valid else "✗"
                print(f"  {symbol} {status.upper()} ({elapsed_ms:.2f}ms)")

            if not result.valid and args.stop_on_failure:
                break

        except Exception as e:
            elapsed_ms = (time.time() - start_time) * 1000
            total_time += elapsed_ms
            error_count += 1

            results.append({
                "entailment": entailment,
                "valid": None,
                "error": str(e),
                "time_ms": round(elapsed_ms, 2)
            })

            if args.verbose:
                print(f"  ⚠ ERROR: {e}")

    # Output results
    output_data = {
        "file": args.file,
        "total": len(entailments),
        "checked": len(results),
        "valid": valid_count,
        "invalid": invalid_count,
        "errors": error_count,
        "total_time_ms": round(total_time, 2),
        "results": results
    }

    if args.format == "json":
        output_str = json.dumps(output_data, indent=2)
    elif args.format == "csv":
        lines = ["entailment,valid,time_ms,reason"]
        for r in results:
            valid_str = str(r.get("valid", "error")).lower()
            reason = r.get("reason") or r.get("error") or ""
            reason = reason.replace(",", ";") if reason else ""
            lines.append(f"\"{r['entailment']}\",{valid_str},{r['time_ms']},\"{reason}\"")
        output_str = "\n".join(lines)
    else:
        # Text format
        lines = []
        lines.append(f"\n{'='*60}")
        lines.append(f"Velora Entailment Check: {args.file}")
        lines.append(f"{'='*60}")
        lines.append(f"\nTotal: {len(entailments)}")
        lines.append(f"Valid: {valid_count} ({100*valid_count/len(results):.1f}%)" if results else "Valid: 0")
        lines.append(f"Invalid: {invalid_count}")
        lines.append(f"Errors: {error_count}")
        lines.append(f"Time: {total_time:.2f}ms")

        if invalid_count > 0:
            lines.append(f"\nInvalid entailments:")
            for r in results:
                if r.get("valid") is False:
                    lines.append(f"  ✗ {r['entailment']}")

        if error_count > 0:
            lines.append(f"\nErrors:")
            for r in results:
                if r.get("error"):
                    lines.append(f"  ⚠ {r['entailment']}: {r['error']}")

        lines.append(f"\n{'='*60}\n")
        output_str = "\n".join(lines)

    # Write output
    if args.output:
        Path(args.output).write_text(output_str)
        print(f"Results written to {args.output}")
    else:
        print(output_str)

    return 0 if invalid_count == 0 and error_count == 0 else 1


# ============================================================================
# PARSE Command
# ============================================================================

def cmd_parse(args) -> int:
    """Execute parse command - parse and display formula"""
    from velora import parse

    # Get formula string
    if args.formula:
        formula_str = args.formula
    elif args.file:
        try:
            formula_str = Path(args.file).read_text().strip()
        except Exception as e:
            print(f"Error reading file: {e}", file=sys.stderr)
            return 1
    else:
        print("Error: Provide a formula string or use -f to read from file", file=sys.stderr)
        return 1

    # Parse formula
    try:
        formula = parse(formula_str)
    except Exception as e:
        print(f"Parse error: {e}", file=sys.stderr)
        return 1

    # Output in requested format
    if args.format == "json":
        print(json.dumps(formula_to_dict(formula), indent=2))
    elif args.format == "sexp":
        print(formula_to_sexp(formula))
    else:
        # Tree format
        print(formula_to_tree(formula))

    return 0


def formula_to_dict(formula) -> dict:
    """Convert formula to dictionary representation"""
    from velora.core.ast import (
        Emp, PointsTo, SepConj, Wand, And, Or, Not, Eq, Neq,
        Lt, Le, Gt, Ge, True_, False_, Exists, Forall, Var, Const,
        PredicateCall
    )

    if isinstance(formula, Emp):
        return {"type": "emp"}
    elif isinstance(formula, PointsTo):
        return {
            "type": "points_to",
            "location": formula_to_dict(formula.location),
            "values": [formula_to_dict(v) for v in formula.values]
        }
    elif isinstance(formula, SepConj):
        return {
            "type": "sep_conj",
            "left": formula_to_dict(formula.left),
            "right": formula_to_dict(formula.right)
        }
    elif isinstance(formula, Wand):
        return {
            "type": "wand",
            "left": formula_to_dict(formula.left),
            "right": formula_to_dict(formula.right)
        }
    elif isinstance(formula, And):
        return {
            "type": "and",
            "left": formula_to_dict(formula.left),
            "right": formula_to_dict(formula.right)
        }
    elif isinstance(formula, Or):
        return {
            "type": "or",
            "left": formula_to_dict(formula.left),
            "right": formula_to_dict(formula.right)
        }
    elif isinstance(formula, Not):
        return {
            "type": "not",
            "operand": formula_to_dict(formula.formula)
        }
    elif isinstance(formula, Eq):
        return {
            "type": "eq",
            "left": formula_to_dict(formula.left),
            "right": formula_to_dict(formula.right)
        }
    elif isinstance(formula, Neq):
        return {
            "type": "neq",
            "left": formula_to_dict(formula.left),
            "right": formula_to_dict(formula.right)
        }
    elif isinstance(formula, (Lt, Le, Gt, Ge)):
        return {
            "type": formula.__class__.__name__.lower(),
            "left": formula_to_dict(formula.left),
            "right": formula_to_dict(formula.right)
        }
    elif isinstance(formula, True_):
        return {"type": "true"}
    elif isinstance(formula, False_):
        return {"type": "false"}
    elif isinstance(formula, Exists):
        return {
            "type": "exists",
            "var": str(formula.var),
            "body": formula_to_dict(formula.body)
        }
    elif isinstance(formula, Forall):
        return {
            "type": "forall",
            "var": str(formula.var),
            "body": formula_to_dict(formula.body)
        }
    elif isinstance(formula, Var):
        return {"type": "var", "name": formula.name}
    elif isinstance(formula, Const):
        return {"type": "const", "value": formula.value}
    elif isinstance(formula, PredicateCall):
        return {
            "type": "predicate",
            "name": formula.name,
            "args": [formula_to_dict(a) for a in formula.args]
        }
    else:
        return {"type": "unknown", "repr": str(formula)}


def formula_to_sexp(formula, indent=0) -> str:
    """Convert formula to S-expression format"""
    from velora.core.ast import (
        Emp, PointsTo, SepConj, Wand, And, Or, Not, Eq, Neq,
        Lt, Le, Gt, Ge, True_, False_, Exists, Forall, Var, Const,
        PredicateCall
    )

    if isinstance(formula, Emp):
        return "emp"
    elif isinstance(formula, PointsTo):
        vals = " ".join(formula_to_sexp(v) for v in formula.values)
        return f"(pto {formula_to_sexp(formula.location)} {vals})"
    elif isinstance(formula, SepConj):
        return f"(sep {formula_to_sexp(formula.left)} {formula_to_sexp(formula.right)})"
    elif isinstance(formula, Wand):
        return f"(wand {formula_to_sexp(formula.left)} {formula_to_sexp(formula.right)})"
    elif isinstance(formula, And):
        return f"(and {formula_to_sexp(formula.left)} {formula_to_sexp(formula.right)})"
    elif isinstance(formula, Or):
        return f"(or {formula_to_sexp(formula.left)} {formula_to_sexp(formula.right)})"
    elif isinstance(formula, Not):
        return f"(not {formula_to_sexp(formula.formula)})"
    elif isinstance(formula, Eq):
        return f"(= {formula_to_sexp(formula.left)} {formula_to_sexp(formula.right)})"
    elif isinstance(formula, Neq):
        return f"(!= {formula_to_sexp(formula.left)} {formula_to_sexp(formula.right)})"
    elif isinstance(formula, Lt):
        return f"(< {formula_to_sexp(formula.left)} {formula_to_sexp(formula.right)})"
    elif isinstance(formula, Le):
        return f"(<= {formula_to_sexp(formula.left)} {formula_to_sexp(formula.right)})"
    elif isinstance(formula, Gt):
        return f"(> {formula_to_sexp(formula.left)} {formula_to_sexp(formula.right)})"
    elif isinstance(formula, Ge):
        return f"(>= {formula_to_sexp(formula.left)} {formula_to_sexp(formula.right)})"
    elif isinstance(formula, True_):
        return "true"
    elif isinstance(formula, False_):
        return "false"
    elif isinstance(formula, Exists):
        return f"(exists ({formula.var}) {formula_to_sexp(formula.body)})"
    elif isinstance(formula, Forall):
        return f"(forall ({formula.var}) {formula_to_sexp(formula.body)})"
    elif isinstance(formula, Var):
        return formula.name
    elif isinstance(formula, Const):
        return str(formula.value)
    elif isinstance(formula, PredicateCall):
        args = " ".join(formula_to_sexp(a) for a in formula.args)
        return f"({formula.name} {args})"
    else:
        return str(formula)


def formula_to_tree(formula, prefix="", is_last=True) -> str:
    """Convert formula to tree visualization"""
    from velora.core.ast import (
        Emp, PointsTo, SepConj, Wand, And, Or, Not, Eq, Neq,
        Lt, Le, Gt, Ge, True_, False_, Exists, Forall, Var, Const,
        PredicateCall
    )

    connector = "└── " if is_last else "├── "
    child_prefix = prefix + ("    " if is_last else "│   ")

    lines = []

    if isinstance(formula, Emp):
        lines.append(f"{prefix}{connector}emp")
    elif isinstance(formula, PointsTo):
        lines.append(f"{prefix}{connector}points-to")
        lines.append(formula_to_tree(formula.location, child_prefix, False))
        for i, v in enumerate(formula.values):
            is_last_val = (i == len(formula.values) - 1)
            lines.append(formula_to_tree(v, child_prefix, is_last_val))
    elif isinstance(formula, SepConj):
        lines.append(f"{prefix}{connector}*")
        lines.append(formula_to_tree(formula.left, child_prefix, False))
        lines.append(formula_to_tree(formula.right, child_prefix, True))
    elif isinstance(formula, Wand):
        lines.append(f"{prefix}{connector}-*")
        lines.append(formula_to_tree(formula.left, child_prefix, False))
        lines.append(formula_to_tree(formula.right, child_prefix, True))
    elif isinstance(formula, And):
        lines.append(f"{prefix}{connector}∧")
        lines.append(formula_to_tree(formula.left, child_prefix, False))
        lines.append(formula_to_tree(formula.right, child_prefix, True))
    elif isinstance(formula, Or):
        lines.append(f"{prefix}{connector}∨")
        lines.append(formula_to_tree(formula.left, child_prefix, False))
        lines.append(formula_to_tree(formula.right, child_prefix, True))
    elif isinstance(formula, Not):
        lines.append(f"{prefix}{connector}¬")
        lines.append(formula_to_tree(formula.formula, child_prefix, True))
    elif isinstance(formula, (Eq, Neq, Lt, Le, Gt, Ge)):
        op_map = {Eq: "=", Neq: "≠", Lt: "<", Le: "≤", Gt: ">", Ge: "≥"}
        op = op_map.get(type(formula), "?")
        lines.append(f"{prefix}{connector}{op}")
        lines.append(formula_to_tree(formula.left, child_prefix, False))
        lines.append(formula_to_tree(formula.right, child_prefix, True))
    elif isinstance(formula, True_):
        lines.append(f"{prefix}{connector}true")
    elif isinstance(formula, False_):
        lines.append(f"{prefix}{connector}false")
    elif isinstance(formula, Exists):
        lines.append(f"{prefix}{connector}∃{formula.var}")
        lines.append(formula_to_tree(formula.body, child_prefix, True))
    elif isinstance(formula, Forall):
        lines.append(f"{prefix}{connector}∀{formula.var}")
        lines.append(formula_to_tree(formula.body, child_prefix, True))
    elif isinstance(formula, Var):
        lines.append(f"{prefix}{connector}{formula.name}")
    elif isinstance(formula, Const):
        lines.append(f"{prefix}{connector}{formula.value}")
    elif isinstance(formula, PredicateCall):
        args = ", ".join(str(a) for a in formula.args)
        lines.append(f"{prefix}{connector}{formula.name}({args})")
    else:
        lines.append(f"{prefix}{connector}{formula}")

    return "\n".join(lines)


# ============================================================================
# REPL Command
# ============================================================================

def cmd_repl(args) -> int:
    """Execute REPL command - interactive mode"""
    from velora import EntailmentChecker, parse

    checker = EntailmentChecker(timeout=args.timeout)

    print("Velora Interactive REPL")
    print("=" * 40)
    print("Commands:")
    print("  <entailment>     Check entailment (e.g., 'x |-> 5 |- x |-> 5')")
    print("  :parse <formula> Parse and display formula")
    print("  :help            Show this help")
    print("  :quit            Exit REPL")
    print("=" * 40)
    print()

    while True:
        try:
            line = input("velora> ").strip()
        except EOFError:
            print()
            break
        except KeyboardInterrupt:
            print()
            continue

        if not line:
            continue

        if line in (":quit", ":exit", ":q"):
            break
        elif line == ":help":
            print("Commands:")
            print("  <entailment>     Check entailment (e.g., 'x |-> 5 |- x |-> 5')")
            print("  :parse <formula> Parse and display formula")
            print("  :help            Show this help")
            print("  :quit            Exit REPL")
        elif line.startswith(":parse "):
            formula_str = line[7:].strip()
            try:
                formula = parse(formula_str)
                print(formula_to_tree(formula, "", True))
            except Exception as e:
                print(f"Parse error: {e}")
        elif "|-" in line:
            # Entailment check
            try:
                result = checker.check_entailment(line)
                if result.valid:
                    print(f"✓ VALID ({result.reason})")
                else:
                    print(f"✗ INVALID ({result.reason})")
            except Exception as e:
                print(f"Error: {e}")
        else:
            # Try to parse as formula
            try:
                formula = parse(line)
                print(f"Parsed: {formula}")
            except Exception as e:
                print(f"Error: {e}")

    print("Goodbye!")
    return 0


# ============================================================================
# Main Entry Point
# ============================================================================

def _cmd_models(args) -> int:
    """Lazy import so `velora models` pulls in the catalog modules only."""
    from velora.models_cli import cmd_models
    return cmd_models(args)


def _cmd_serve_bridge(args) -> int:
    from velora.bridge_cli import cmd_serve_bridge
    return cmd_serve_bridge(args)


def _cmd_doctor(args) -> int:
    from velora.doctor_cli import cmd_doctor
    return cmd_doctor(args)


def _cmd_setup(args) -> int:
    from velora.setup_cli import cmd_setup
    return cmd_setup(args)


def main(argv: List[str] = None) -> int:
    """Main CLI entry point"""
    parser = create_parser()
    args = parser.parse_args(argv)

    if not args.command:
        parser.print_help()
        return 0

    raw_argv = list(argv) if argv is not None else list(sys.argv[1:])

    # Dispatch to command handler
    commands = {
        "scan": cmd_scan,
        "exploit": cmd_exploit,
        "report": cmd_report,
        "fix": cmd_fix,
        "solve": cmd_solve,
        "check": cmd_check,
        "parse": cmd_parse,
        "repl": cmd_repl,
        "models": _cmd_models,
        "serve-bridge": _cmd_serve_bridge,
        "doctor": _cmd_doctor,
        "setup": _cmd_setup,
    }

    handler = commands.get(args.command)
    if handler:
        try:
            if args.command in ("scan", "exploit"):
                return handler(args, _raw_argv=raw_argv)
            return handler(args)
        except KeyboardInterrupt:
            print("\ninterrupted -- stopping (exit 130)", file=sys.stderr)
            return 130
    else:
        parser.print_help()
        return 1


def main_legacy(argv: List[str] = None) -> int:
    """Deprecated `frame` entry point; delegates to `velora`."""
    print(
        "warning: the 'frame' command is deprecated, use 'velora' instead",
        file=sys.stderr,
    )
    return main(argv)


if __name__ == "__main__":
    sys.exit(main())
