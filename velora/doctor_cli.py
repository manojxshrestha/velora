"""`velora doctor` -- diagnose the zero-key AI setup.

Read-only. Every failed check carries the exact fix command. Exit code 0
means `velora scan --ai` can work with zero API keys right now (scriptable
in CI: "works on my machine" becomes testable).
"""

from __future__ import annotations

import json
import os
import sys
import time
import urllib.request
from dataclasses import dataclass
from typing import List, Optional

from velora import bridge_cli

OK, WARN, FAIL = "ok", "warn", "fail"
_MARK = {OK: "✅", WARN: "⚠️ ", FAIL: "❌"}


@dataclass
class Check:
    id: str
    status: str
    detail: str
    fix: str = ""

    @property
    def failed(self) -> bool:
        return self.status == FAIL


def _check_platform() -> Check:
    summary = bridge_cli.platform_summary()
    if bridge_cli.is_windows():
        return Check("platform", FAIL, summary,
                     "run Velora inside WSL:  wsl --install")
    return Check("platform", OK, summary)


def _check_python() -> Check:
    import velora
    try:
        import z3
        z3_ver = getattr(z3, "get_version_string", lambda: "?")()
    except Exception as exc:  # noqa: BLE001
        return Check("python", FAIL, f"velora {velora.__version__}, z3 missing "
                                     f"({exc})",
                     "pip install z3-solver")
    return Check("python", OK,
                 f"Python {sys.version.split()[0]}, velora {velora.__version__}, "
                 f"z3 {z3_ver}")


def _check_node() -> Check:
    node = bridge_cli.find_node()
    if not node:
        return Check("node", FAIL, "not found",
                     "velora setup   (installs Node user-local, no sudo)")
    ver = bridge_cli.tool_version(node)
    major = bridge_cli.node_major(ver)
    if major and major < bridge_cli.MIN_NODE_MAJOR:
        return Check("node", FAIL, f"{node} ({ver}) is older than "
                                   f"v{bridge_cli.MIN_NODE_MAJOR}",
                     "velora setup")
    return Check("node", OK, f"{node} ({ver or 'version unknown'})")


def _check_opencode() -> Check:
    oc = bridge_cli.find_opencode()
    if not oc:
        return Check("opencode", FAIL, "not found",
                     "velora setup   (official installer, no sudo)")
    return Check("opencode", OK, f"{oc} ({bridge_cli.tool_version(oc)})")


def _check_sources() -> Check:
    src = bridge_cli.bridge_sources_dir()
    missing = [f for f in bridge_cli.BRIDGE_FILES if not (src / f).is_file()]
    if missing:
        return Check("bridge-sources", FAIL,
                     f"packaged files missing: {', '.join(missing)}",
                     "pip install --force-reinstall velora")
    return Check("bridge-sources", OK, str(src))


def _check_runtime() -> Check:
    dst = bridge_cli.bridge_dir()
    seeded = (dst / "server.js").is_file()
    deps = bridge_cli.bridge_deps_ready(dst)
    if not seeded:
        return Check("bridge-runtime", FAIL, f"not seeded ({dst})",
                     "velora setup")
    if not deps:
        return Check("bridge-runtime", FAIL, f"deps not installed ({dst})",
                     "velora setup")
    return Check("bridge-runtime", OK, f"{dst} (deps installed)")


def _active_model():
    """(base, model, provider, source) merging env > config like LLMConfig."""
    env_base = (os.environ.get("VELORA_LLM_BASE_URL")
                or os.environ.get("FRAME_LLM_BASE_URL") or "").rstrip("/")
    env_model = (os.environ.get("VELORA_LLM_MODEL")
                 or os.environ.get("FRAME_LLM_MODEL") or "")
    from velora.sil import model_config
    cfg = model_config.active() or {}
    base = env_base or str(cfg.get("base_url") or "").rstrip("/")
    model = env_model or str(cfg.get("model") or "")
    provider = str(cfg.get("provider") or "")
    source = "env" if (env_base or env_model) else ("config" if cfg else "")
    if not env_base and not env_model and cfg:
        source = f"config ({cfg.get('source', 'velora-models')})"
    return base, model, provider, source


def _needs_bridge(base: str, provider: str) -> bool:
    return (base == bridge_cli.DEFAULT_BASE_URL
            or provider == "opencode-bridge"
            or base.endswith(":8399/v1"))


def _check_model() -> Check:
    base, model, provider, source = _active_model()
    if not base and not model:
        return Check("model", FAIL, "no active model",
                     "velora models tui")
    if not base or not model:
        missing = "base_url" if not base else "model"
        return Check("model", FAIL, f"partial config (missing {missing})",
                     "velora models tui")
    return Check("model", OK,
                 f"{provider + '/' if provider else ''}{model} -> {base} "
                 f"[{source}]")


def _check_bridge() -> Check:
    port = bridge_cli.DEFAULT_PORT
    state = bridge_cli._read_state()
    pid = int(state.get("pid") or 0) if state else 0
    alive = bool(pid and bridge_cli._pid_alive(pid))
    if bridge_cli.bridge_health(port):
        return Check("bridge", OK,
                     f"healthy on :{port} (pid {pid or '?'})")
    if alive:
        return Check("bridge", FAIL,
                     f"pid {pid} alive but unhealthy "
                     f"(see {bridge_cli.logfile_path()})",
                     "velora serve-bridge --stop && velora serve-bridge --start")
    if bridge_cli._port_busy(port):
        return Check("bridge", FAIL, f"port {port} taken by a foreign process",
                     f"free the port, or run with --port <other>")
    return Check("bridge", WARN, "not running",
                 "velora serve-bridge --start")


def _check_bridge_required() -> Check:
    base, model, provider, _ = _active_model()
    if not model:
        return Check("bridge-required", WARN, "skipped (no model yet)")
    if not _needs_bridge(base, provider):
        return Check("bridge-required", WARN,
                     "not needed (active model is a local/hosted endpoint)")
    if bridge_cli.bridge_health(bridge_cli.DEFAULT_PORT):
        return Check("bridge-required", OK,
                     "active model is bridge-backed and the bridge is healthy")
    return Check("bridge-required", FAIL,
                 "active model is bridge-backed but the bridge is down",
                 "velora serve-bridge --start")


def _check_endpoints() -> Check:
    try:
        from velora.models_tui import discover
        _, summary = discover(None)
    except Exception as exc:  # noqa: BLE001
        return Check("endpoints", WARN, f"probe failed ({exc})")
    return Check("endpoints", OK, summary)


def probe_chat(base_url: Optional[str] = None, model: Optional[str] = None,
               timeout: float = 180.0):
    """One real keyless chat; returns (ok, detail)."""
    base = (base_url or bridge_cli.DEFAULT_BASE_URL).rstrip("/")
    if not model:
        _, cfg_model, provider, _ = _active_model()
        model = cfg_model if provider == "opencode-bridge" else ""
    model = model or "opencode/mimo-v2.6-flash-free"
    payload = json.dumps({
        "model": model,
        "messages": [{"role": "user",
                      "content": "Reply with exactly: OK"}],
        "temperature": 0,
        "max_tokens": 200,
    }).encode()
    req = urllib.request.Request(
        f"{base}/chat/completions", data=payload,
        headers={"Content-Type": "application/json"})
    started = time.time()
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            body = json.loads(resp.read())
        text = body["choices"][0]["message"]["content"]
        elapsed = time.time() - started
        return True, f"keyless chat OK in {elapsed:.0f}s via {model} " \
                     f"(replied {text.strip()[:40]!r})"
    except Exception as exc:  # noqa: BLE001
        return False, f"keyless chat FAILED: {exc}"


def _check_probe() -> Check:
    if not bridge_cli.bridge_health(bridge_cli.DEFAULT_PORT):
        return Check("probe", WARN, "skipped (bridge not running)",
                     "velora serve-bridge --start")
    ok, detail = probe_chat()
    return Check("probe", OK if ok else FAIL, detail,
                 "" if ok else "check opencode free-tier status: "
                               "`opencode serve` logs; retry later")


def run_checks(probe: bool = False) -> List[Check]:
    checks = [_check_platform(), _check_python(), _check_node(),
              _check_opencode(), _check_sources(), _check_runtime(),
              _check_bridge(), _check_model(), _check_bridge_required(),
              _check_endpoints()]
    if probe:
        checks.append(_check_probe())
    return checks


def ready(checks: List[Check]) -> bool:
    return not any(c.failed for c in checks)


def cmd_doctor(args) -> int:
    checks = run_checks(probe=getattr(args, "probe", False))
    ok = ready(checks)
    if getattr(args, "format", "text") == "json":
        print(json.dumps({
            "ready": ok,
            "platform": bridge_cli.platform_summary(),
            "checks": [{"id": c.id, "status": c.status, "detail": c.detail,
                        "fix": c.fix} for c in checks],
        }, indent=2))
        return 0 if ok else 1

    print("velora doctor")
    for c in checks:
        print(f"  {_MARK[c.status]} {c.id:<16} {c.detail}")
        if c.fix and c.status != OK:
            print(f"       fix: {c.fix}")
    failures = [c for c in checks if c.failed]
    warns = [c for c in checks if c.status == WARN]
    if ok:
        print(f"\nready for zero-key `velora scan --ai`"
              + (f"  ({len(warns)} advisory)" if warns else ""))
        return 0
    print(f"\n{len(failures)} problem(s) block zero-key AI. "
          "Fix them with:  velora setup")
    return 1
