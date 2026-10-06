#!/usr/bin/env python3
"""
Velora Security Scanner CLI.

Command-line interface for scanning source code for vulnerabilities.

Usage:
    # Scan a single file
    python -m velora.sil.cli scan app.py

    # Scan with SARIF output (for GitHub Actions)
    python -m velora.sil.cli scan app.py --format sarif -o results.sarif

    # Scan a directory (current folder; --pattern picks the files)
    python -m velora.sil.cli scan . --pattern "**/*.py"

    # Scan without verification (faster, may have FPs)
    python -m velora.sil.cli scan app.py --no-verify
"""

import argparse
import sys
import json
from dataclasses import replace
from pathlib import Path
from typing import List

from velora.sil.scanner import VeloraScanner, ScanResult, Severity
from velora.sil.llm_client import LLMUnavailableError


def create_parser() -> argparse.ArgumentParser:
    """Create argument parser"""
    parser = argparse.ArgumentParser(
        prog="velora-scan",
        description="Velora Security Scanner - Verification-grade vulnerability detection",
    )

    subparsers = parser.add_subparsers(dest="command", help="Commands")

    # Scan command
    scan_parser = subparsers.add_parser("scan", help="Scan files for vulnerabilities")
    scan_parser.add_argument(
        "target",
        help="File or directory to scan"
    )
    scan_parser.add_argument(
        "-l", "--language",
        default="python",
        help="Source language (default: python). Symbolic frontends: python, "
             "javascript, typescript, java, c, cpp, csharp. Any other language "
             "(e.g. php, ruby, go) runs LLM-detect only under --ai."
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
        help="Enable the LLM layer (detection + triage). Needs an LLM endpoint "
             "configured via VELORA_LLM_* env vars."
    )
    scan_parser.add_argument(
        "--llm-detect",
        action="store_true",
        help="Enable LLM detection only (find vulnerabilities the symbolic engine misses)."
    )
    scan_parser.add_argument(
        "--llm-triage",
        action="store_true",
        help="Enable LLM triage only (filter false positives from symbolic findings)."
    )
    scan_parser.add_argument(
        "--repo-scale",
        action="store_true",
        help="Analyze the whole repository in one LLM session instead of one per "
             "file. Far faster and cheaper on real projects, and lets the model "
             "follow flows across files. Requires --ai or --llm-detect."
    )

    return parser


def severity_value(severity: Severity) -> int:
    """Get numeric value for severity comparison"""
    values = {
        Severity.CRITICAL: 5,
        Severity.HIGH: 4,
        Severity.MEDIUM: 3,
        Severity.LOW: 2,
        Severity.INFO: 1,
    }
    return values.get(severity, 0)


def parse_severity(name: str) -> Severity:
    """Parse severity from string"""
    mapping = {
        "critical": Severity.CRITICAL,
        "high": Severity.HIGH,
        "medium": Severity.MEDIUM,
        "low": Severity.LOW,
        "info": Severity.INFO,
    }
    return mapping.get(name.lower(), Severity.LOW)


def filter_min_severity(result: ScanResult, min_severity: Severity) -> ScanResult:
    """Copy `result` with vulnerabilities below `min_severity` removed.

    The severity floor is applied exactly ONCE, before any formatter, so
    text/JSON/SARIF all carry the same finding set and the --fail-on gate
    agrees with the emitted artifact (BUG-017).
    """
    keep = [v for v in result.vulnerabilities
            if severity_value(v.severity) >= severity_value(min_severity)]
    if len(keep) == len(result.vulnerabilities):
        return result
    return replace(result, vulnerabilities=keep)


def format_text_result(result: ScanResult, min_severity: Severity) -> str:
    """Format scan result as human-readable text"""
    lines = []

    # Header
    lines.append(f"\n{'='*60}")
    lines.append(f"Velora Security Scan: {result.filename}")
    lines.append(f"{'='*60}")

    # Stats
    lines.append(f"\nLines scanned: {result.lines_scanned}")
    lines.append(f"Procedures analyzed: {result.procedures_analyzed}")
    lines.append(f"Scan time: {result.scan_time_ms:.2f}ms")

    # Errors
    if result.errors:
        lines.append(f"\nErrors:")
        for error in result.errors:
            lines.append(f"  ❌ {error}")

    # Vulnerabilities
    vulns = [v for v in result.vulnerabilities
             if severity_value(v.severity) >= severity_value(min_severity)]

    if vulns:
        lines.append(f"\nVulnerabilities Found: {len(vulns)}")
        lines.append("-" * 40)

        for i, vuln in enumerate(vulns, 1):
            severity_icon = {
                Severity.CRITICAL: "🔴",
                Severity.HIGH: "🟠",
                Severity.MEDIUM: "🟡",
                Severity.LOW: "🔵",
                Severity.INFO: "⚪",
            }.get(vuln.severity, "⚫")

            lines.append(f"\n{i}. [{vuln.severity.value.upper()}] {severity_icon} {vuln.type.value}")
            lines.append(f"   Location: {vuln.location}:{vuln.line}:{vuln.column}")
            lines.append(f"   Function: {vuln.procedure}")
            lines.append(f"   Description: {vuln.description}")

            if vuln.cwe_id:
                lines.append(f"   CWE: {vuln.cwe_id}")

            if vuln.source_var:
                lines.append(f"   Source: {vuln.source_var}")

            if vuln.data_flow:
                flow = " → ".join(vuln.data_flow[:5])
                if len(vuln.data_flow) > 5:
                    flow += " → ..."
                lines.append(f"   Data flow: {flow}")

            if vuln.witness:
                lines.append(f"   Exploit witness: {vuln.witness}")

            lines.append(f"   Confidence: {vuln.confidence:.0%}")

    else:
        lines.append(f"\n✅ No vulnerabilities found!")

    lines.append(f"\n{'='*60}\n")

    return "\n".join(lines)


def format_json_result(results: List[ScanResult]) -> str:
    """Format results as JSON"""
    if len(results) == 1:
        return results[0].to_json()
    else:
        combined = {
            "files": [r.to_dict() for r in results],
            "summary": {
                "files_scanned": len(results),
                "total_vulnerabilities": sum(len(r.vulnerabilities) for r in results),
                "critical": sum(r.critical_count for r in results),
                "high": sum(r.high_count for r in results),
            }
        }
        return json.dumps(combined, indent=2)


def format_sarif_result(results: List[ScanResult]) -> str:
    """Format results as SARIF"""
    if len(results) == 1:
        return json.dumps(results[0].to_sarif(), indent=2)
    else:
        # Combine multiple files into one SARIF run
        all_results = []
        rules = {}

        for result in results:
            sarif = result.to_sarif()
            if sarif["runs"]:
                run = sarif["runs"][0]
                all_results.extend(run.get("results", []))
                for rule in run["tool"]["driver"].get("rules", []):
                    rules[rule["id"]] = rule

        combined = {
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [{
                "tool": {
                    "driver": {
                        "name": "Velora Security Scanner",
                        "version": "0.1.0",
                        "rules": list(rules.values()),
                    }
                },
                "results": all_results,
            }]
        }
        return json.dumps(combined, indent=2)


def should_fail(results: List[ScanResult], fail_on: str) -> bool:
    """Determine if scan should fail based on findings"""
    if fail_on == "none":
        return False

    if fail_on == "any":
        return any(r.vulnerabilities for r in results)

    threshold = parse_severity(fail_on)
    threshold_value = severity_value(threshold)

    for result in results:
        for vuln in result.vulnerabilities:
            if severity_value(vuln.severity) >= threshold_value:
                return True

    return False


def main(argv: List[str] = None) -> int:
    """Main CLI entry point"""
    parser = create_parser()
    args = parser.parse_args(argv)

    if not args.command:
        parser.print_help()
        return 0

    if args.command == "scan":
        return cmd_scan(args)

    return 0


def cmd_scan(args) -> int:
    """Execute scan command"""
    target = Path(args.target)

    if not target.exists():
        print(f"Error: Target not found: {args.target}", file=sys.stderr)
        return 1

    # DOC-005: an AI layer the user asked for but that has no endpoint/model
    # must say so on stderr unconditionally -- not only under -v. The scan
    # proceeds without the LLM tier either way; silence makes `--ai` look like
    # it worked. Same config source the scanner's own gate uses.
    ai_requested = (getattr(args, "ai", False)
                    or getattr(args, "llm_detect", False)
                    or getattr(args, "llm_triage", False))
    if ai_requested:
        try:
            from velora.sil.llm_triage import TriageConfig
            _ai_cfg = TriageConfig.from_env()
            _ai_configured = bool(getattr(_ai_cfg, "base_url", "")
                                  and getattr(_ai_cfg, "model", ""))
        except Exception:
            _ai_configured = False
        if not _ai_configured:
            print("Note: AI layer requested (--ai) but no endpoint/model is "
                  "configured (VELORA_LLM_BASE_URL / VELORA_LLM_MODEL); "
                  "running without the LLM tier -- see docs/ai-models.md.",
                  file=sys.stderr)

    # Create scanner
    try:
        # AI layer: --ai turns on both; --llm-detect / --llm-triage are granular.
        ai = getattr(args, "ai", False)
        scanner = VeloraScanner(
            language=args.language,
            verify=not args.no_verify,
            timeout=args.timeout,
            verbose=args.verbose,
            llm_detect=ai or getattr(args, "llm_detect", False),
            llm_triage=ai or getattr(args, "llm_triage", False),
            llm_repo_scale=getattr(args, "repo_scale", False),
        )
    except ImportError as e:
        print(f"Error: {e}", file=sys.stderr)
        print("Install tree-sitter: pip install tree-sitter tree-sitter-python", file=sys.stderr)
        return 1

    # Perform scan. An unreachable LLM endpoint (with --ai) surfaces as a hard
    # error, never a misleading "no vulnerabilities found".
    results = []
    try:
        if target.is_file():
            result = scanner.scan_file(str(target))
            results.append(result)
        else:
            exclude_dirs = [] if getattr(args, "no_default_excludes", False) else None
            results = scanner.scan_directory(str(target), args.pattern,
                                              exclude_dirs=exclude_dirs)
    except LLMUnavailableError as e:
        print(f"Error: LLM layer unavailable -- scan aborted (findings NOT reliable): {e}",
              file=sys.stderr)
        return 2

    if not results:
        print("No files found to scan.", file=sys.stderr)
        return 1

    # Apply the severity floor once, before any formatter: text/JSON/SARIF then
    # expose identical finding sets and the exit gate matches the artifact
    # (BUG-017).
    min_severity = parse_severity(args.min_severity)
    results = [filter_min_severity(r, min_severity) for r in results]

    # Scan I/O errors are a failure of their own: surface them on stderr (JSON
    # payloads carry them too) and never exit 0 because of them, regardless of
    # --fail-on, which gates findings only (BUG-018).
    scan_errors = [e for r in results for e in r.errors]
    for err in scan_errors:
        print(f"Scan error: {err}", file=sys.stderr)

    if args.format == "text":
        outputs = [format_text_result(result, min_severity)
                   for result in results]
        if args.output:
            # One write, mode "w": a rerun must replace the previous report, not
            # append to it (BUG-019). Multi-file scans join in one write.
            with open(args.output, 'w') as f:
                f.write("".join(outputs))
        else:
            for output in outputs:
                print(output)

    elif args.format == "json":
        output = format_json_result(results)
        if args.output:
            with open(args.output, 'w') as f:
                f.write(output)
        else:
            print(output)

    elif args.format == "sarif":
        output = format_sarif_result(results)
        if args.output:
            with open(args.output, 'w') as f:
                f.write(output)
        else:
            print(output)

    # Determine exit code: findings gate first (1), then scan I/O errors (3).
    if should_fail(results, args.fail_on):
        return 1
    if scan_errors:
        return 3

    return 0


if __name__ == "__main__":
    sys.exit(main())
