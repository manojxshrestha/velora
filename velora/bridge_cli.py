"""`velora serve-bridge` -- OpenAI-compatible bridge to opencode (zero-key --ai).

The bridge (Node + @opencode-ai/sdk; sources ship in ``velora/_bridge``) is
seeded into a writable runtime dir (``$VELORA_BRIDGE_HOME`` or
``$XDG_DATA_HOME/velora/bridge``), deps installed once, then served:

    velora serve-bridge              # foreground (blocks the terminal)
    velora serve-bridge --start      # background daemon (pidfile + log)
    velora serve-bridge --stop
    velora serve-bridge --status

opencode owns every API key (incl. the free Zen tier); Velora stores none.
Supported platforms: Linux, WSL, macOS. Native Windows binaries are rejected
(their loopback differs from WSL tooling) -- use WSL.
"""

from __future__ import annotations

import json
import os
import platform as _platform
import shutil
import signal
import socket
import subprocess
import sys
import time
import urllib.request
from pathlib import Path
from typing import Dict, List, Optional, Tuple

DEFAULT_PORT = 8399
DEFAULT_OC_PORT = 4599
DEFAULT_BASE_URL = f"http://127.0.0.1:{DEFAULT_PORT}/v1"
MIN_NODE_MAJOR = 18
BRIDGE_FILES = ("server.js", "server.test.js", "package.json", "package-lock.json")
_START_TIMEOUT = 90.0
_WINDOWS_MARKERS = (".exe", "/mnt/c/")


# ---------------------------------------------------------------------------
# Platform
# ---------------------------------------------------------------------------

def is_wsl() -> bool:
    if os.environ.get("WSL_DISTRO_NAME") or os.environ.get("WSL_INTEROP"):
        return True
    try:
        return "microsoft" in _platform.release().lower()
    except Exception:  # noqa: BLE001
        return False


def is_windows() -> bool:
    return sys.platform == "win32" and not is_wsl()


def platform_summary() -> str:
    bits = []
    try:
        bits.append(f"{_platform.system()} {_platform.release()} "
                    f"({_platform.machine()})")
    except Exception:  # noqa: BLE001
        bits.append(sys.platform)
    if is_wsl():
        bits.append("WSL")
    if is_windows():
        bits.append("native Windows (unsupported: use WSL)")
    return " ".join(bits)


# ---------------------------------------------------------------------------
# Discovery (native Linux/macOS binaries only)
# ---------------------------------------------------------------------------

def _is_native(path: str) -> bool:
    low = path.lower().replace("\\", "/")
    return not any(marker in low for marker in _WINDOWS_MARKERS)


def _first_existing(candidates: List[str]) -> Optional[str]:
    seen = set()
    for cand in candidates:
        if not cand:
            continue
        cand = str(cand)
        if cand in seen:
            continue
        seen.add(cand)
        if _is_native(cand) and Path(cand).is_file():
            return cand
    return None


def find_node() -> Optional[str]:
    home = Path.home()
    candidates = [str(home / ".local" / "bin" / "node"),   # managed install
                  shutil.which("node"),
                  "/opt/homebrew/bin/node",
                  "/usr/local/bin/node",
                  "/usr/bin/node",
                  "/opt/node/bin/node"]
    opt = home / ".local" / "opt"
    if opt.is_dir():
        candidates += sorted((str(p) for p in opt.glob("node-*/bin/node")),
                             reverse=True)
    return _first_existing(candidates)


def find_npm(node: Optional[str] = None) -> Optional[str]:
    if node:
        real_bin = Path(node).resolve().parent
        sibling = _first_existing([str(real_bin / "npm"),
                                   str(Path(node).parent / "npm")])
        if sibling:
            return sibling
    home = Path.home()
    return _first_existing([shutil.which("npm"),
                            str(home / ".local" / "bin" / "npm"),
                            "/opt/homebrew/bin/npm",
                            "/usr/local/bin/npm",
                            "/usr/bin/npm"])


def find_opencode() -> Optional[str]:
    home = Path.home()
    return _first_existing([str(home / ".opencode" / "bin" / "opencode"),
                            str(home / ".local" / "bin" / "opencode"),
                            shutil.which("opencode"),
                            "/opt/homebrew/bin/opencode",
                            "/usr/local/bin/opencode",
                            "/usr/bin/opencode"])


def tool_version(path: str) -> str:
    try:
        proc = subprocess.run([path, "--version"], capture_output=True,
                              text=True, timeout=15)
        out = (proc.stdout or proc.stderr or "").strip().splitlines()
        return out[0].strip() if out else ""
    except Exception:  # noqa: BLE001
        return ""


def node_major(version: str) -> int:
    text = (version or "").strip().lstrip("vV")
    digits = ""
    for ch in text:
        if ch.isdigit():
            digits += ch
        else:
            break
    return int(digits) if digits else 0


def _env_for(node: str, opencode: Optional[str] = None) -> dict:
    env = os.environ.copy()
    parts: List[str] = []
    if opencode:
        parts.append(str(Path(opencode).parent))
    parts.append(str(Path(node).parent))
    env["PATH"] = os.pathsep.join(parts) + os.pathsep + env.get("PATH", "")
    return env


# ---------------------------------------------------------------------------
# Bridge sources: package -> writable runtime dir
# ---------------------------------------------------------------------------

def bridge_sources_dir() -> Path:
    return Path(__file__).resolve().parent / "_bridge"


def bridge_dir() -> Path:
    override = os.environ.get("VELORA_BRIDGE_HOME")
    if override:
        return Path(override).expanduser()
    xdg = os.environ.get("XDG_DATA_HOME") or str(Path.home() / ".local" / "share")
    return Path(xdg) / "velora" / "bridge"


def seed_bridge_sources(dst: Optional[Path] = None) -> bool:
    """Copy packaged sources into the runtime dir; True if anything changed."""
    src = bridge_sources_dir()
    dst = dst or bridge_dir()
    dst.mkdir(parents=True, exist_ok=True)
    changed = False
    for name in BRIDGE_FILES:
        source = src / name
        if not source.is_file():
            continue
        data = source.read_bytes()
        target = dst / name
        if not target.is_file() or target.read_bytes() != data:
            target.write_bytes(data)
            changed = True
    return changed


def bridge_deps_ready(dst: Optional[Path] = None) -> bool:
    dst = dst or bridge_dir()
    return (dst / "node_modules" / "@opencode-ai").is_dir()


def install_bridge_deps(node: str, dst: Optional[Path] = None,
                        env: Optional[dict] = None) -> Optional[str]:
    dst = dst or bridge_dir()
    if bridge_deps_ready(dst):
        return None
    npm = find_npm(node)
    if not npm:
        return (f"npm not found next to {node}; install Node >= "
                f"{MIN_NODE_MAJOR} (or run `velora setup`)")
    print(f"[bridge] installing deps in {dst} ...")
    proc = subprocess.run([npm, "install", "--omit=dev"], cwd=dst,
                          env=env or _env_for(node),
                          capture_output=True, text=True)
    if proc.returncode != 0:
        return f"npm install failed:\n{proc.stdout}\n{proc.stderr}"
    return None


def ensure_bridge(node: Optional[str] = None,
                  env: Optional[dict] = None) -> Optional[str]:
    """Seed sources + install deps; returns an error string or None."""
    node = node or find_node()
    if not node:
        return _missing_node_message()
    seed_bridge_sources()
    return install_bridge_deps(node, env=env or _env_for(node))


def _missing_node_message() -> str:
    if is_windows():
        return ("native Windows is not supported yet -- run Velora inside WSL "
                "(wsl --install) and re-run `velora setup` there")
    return (f"no native `node` found (Node >= {MIN_NODE_MAJOR}); "
            "run `velora setup` to install it (user-local, no sudo)")


# ---------------------------------------------------------------------------
# Health / ports / state
# ---------------------------------------------------------------------------

def _port_busy(port: int) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(0.5)
        return sock.connect_ex(("127.0.0.1", port)) == 0


def bridge_health(port: int = DEFAULT_PORT, timeout: float = 2.0) -> bool:
    try:
        with urllib.request.urlopen(f"http://127.0.0.1:{port}/health",
                                    timeout=timeout) as resp:
            return resp.status == 200
    except Exception:  # noqa: BLE001
        return False


def _wait_health(port: int, timeout: float = _START_TIMEOUT) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        if bridge_health(port, timeout=2.0):
            return True
        time.sleep(0.5)
    return False


def state_dir() -> Path:
    override = os.environ.get("VELORA_STATE_HOME")
    if override:
        return Path(override).expanduser()
    xdg = os.environ.get("XDG_STATE_HOME") or str(Path.home() / ".local" / "state")
    return Path(xdg) / "velora"


def pidfile_path() -> Path:
    return state_dir() / "bridge.json"


def logfile_path() -> Path:
    return state_dir() / "bridge.log"


def _read_state() -> Optional[dict]:
    try:
        data = json.loads(pidfile_path().read_text())
        return data if isinstance(data, dict) else None
    except (OSError, ValueError):
        return None


def _write_state(state: dict) -> None:
    state_dir().mkdir(parents=True, exist_ok=True)
    pidfile_path().write_text(json.dumps(state, indent=2) + "\n")


def _clear_state() -> None:
    try:
        pidfile_path().unlink()
    except OSError:
        pass


def _pid_alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    except OSError:
        return False
    return True


def _check_ports(port: int, oc_port: int) -> Optional[str]:
    if _port_busy(oc_port):
        return (f"port {oc_port} is already in use (stale opencode would make "
                f"the bridge die with ServeError).\n  stop it first:\n"
                f"    pkill -f 'opencode serve --port {oc_port}'\n"
                "  or pass --opencode-port <other>")
    if _port_busy(port):
        return (f"port {port} is already in use -- is another "
                "`velora serve-bridge` running?\n"
                "  check:  velora serve-bridge --status\n"
                "  stop:   velora serve-bridge --stop\n"
                "  or pass --port <other>")
    return None


# ---------------------------------------------------------------------------
# Preparation shared by foreground and daemon modes
# ---------------------------------------------------------------------------

def _prepare(args=None) -> Tuple[Optional[Dict], Optional[str]]:
    """Returns ({node, opencode, env, dst}, error)."""
    bdir = bridge_dir()
    node = find_node()
    if not node:
        return None, _missing_node_message()
    opencode = find_opencode()
    if not opencode:
        if is_windows():
            return None, ("native Windows is not supported yet -- use WSL "
                          "and re-run `velora setup` there")
        return None, ("no native `opencode` binary found.\n  install it:\n"
                      "    curl -fsSL https://opencode.ai/install | bash\n"
                      "  (a Windows shim on PATH is rejected: it binds the "
                      "Windows loopback)")
    env = _env_for(node, opencode)
    err = ensure_bridge(node, env=env)
    if err:
        return None, err
    port = (getattr(args, "port", None) or DEFAULT_PORT) if args is not None else DEFAULT_PORT
    oc_port = (getattr(args, "opencode_port", None) or DEFAULT_OC_PORT) if args is not None else DEFAULT_OC_PORT
    return {"node": node, "opencode": opencode, "env": env, "dst": bdir,
            "port": int(port), "oc_port": int(oc_port)}, None


def _bridge_cmd(node: str, port: int, oc_port: int) -> List[str]:
    return [node, "server.js", "--port", str(port),
            "--opencode-port", str(oc_port)]


# ---------------------------------------------------------------------------
# Daemon: start / stop / status
# ---------------------------------------------------------------------------

def start_bridge(args=None, launcher=None, prep=None) -> int:
    if prep is None:
        prep, err = _prepare(args)
        if err:
            print(f"velora serve-bridge: {err}", file=sys.stderr)
            return 1
    port, oc_port = prep["port"], prep["oc_port"]
    if bridge_health(port):
        print(f"[bridge] already running and healthy on http://127.0.0.1:{port}")
        return 0
    state = _read_state()
    if state and state.get("pid") and _pid_alive(int(state["pid"])):
        print(f"[bridge] pid {state['pid']} is alive but not healthy -- "
              "stop it first:  velora serve-bridge --stop", file=sys.stderr)
        return 1
    _clear_state()
    conflict = _check_ports(port, oc_port)
    if conflict:
        print(f"velora serve-bridge: {conflict}", file=sys.stderr)
        return 1

    state_dir().mkdir(parents=True, exist_ok=True)
    cmd = _bridge_cmd(prep["node"], port, oc_port)
    if launcher is not None:
        child = launcher(cmd, prep["env"], prep["dst"])
    else:
        log = open(logfile_path(), "ab")
        try:
            child = subprocess.Popen(
                cmd, cwd=prep["dst"], env=prep["env"],
                stdout=log, stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL,
                start_new_session=True,
            )
        finally:
            log.close()
    _write_state({"pid": child.pid, "port": port, "oc_port": oc_port,
                  "node": prep["node"], "opencode": prep["opencode"],
                  "started_at": int(time.time())})
    if not _wait_health(port):
        print(f"velora serve-bridge: not healthy after "
              f"{int(_START_TIMEOUT)}s -- log tail:", file=sys.stderr)
        print(_log_tail(), file=sys.stderr)
        try:
            child.terminate()
        except Exception:  # noqa: BLE001
            pass
        _clear_state()
        return 1
    print(f"[bridge] started (pid {child.pid}): "
          f"http://127.0.0.1:{port}  log: {logfile_path()}")
    print("    velora models tui      # pick a model")
    print("    velora scan src/ --ai  # use it")
    return 0


def _log_tail(lines: int = 15) -> str:
    try:
        content = logfile_path().read_text(errors="replace")
        return "\n".join(content.splitlines()[-lines:])
    except OSError:
        return "(no log)"


def stop_bridge(args=None) -> int:
    port = (getattr(args, "port", None) or DEFAULT_PORT) if args is not None else DEFAULT_PORT
    state = _read_state()
    if not state:
        if bridge_health(port):
            print(f"[bridge] a bridge answers on :{port} but has no pidfile "
                  "(started elsewhere?) -- stop it manually", file=sys.stderr)
            return 1
        print("[bridge] not running")
        return 0
    pid = int(state.get("pid") or 0)
    if pid and _pid_alive(pid):
        for sig in (signal.SIGTERM, signal.SIGKILL):
            try:
                os.kill(pid, sig)
            except OSError:
                break
            deadline = time.time() + 8
            while time.time() < deadline and _pid_alive(pid):
                time.sleep(0.2)
            if not _pid_alive(pid):
                break
    oc_port = int(state.get("oc_port") or 0)
    if oc_port and _port_busy(oc_port) and shutil.which("pkill"):
        subprocess.run(["pkill", "-f",
                        f"opencode serve --port {oc_port}"],
                       capture_output=True)
    _clear_state()
    print("[bridge] stopped")
    return 0


def status_bridge(args=None, fmt: str = "text") -> int:
    port = (getattr(args, "port", None) or DEFAULT_PORT) if args is not None else DEFAULT_PORT
    state = _read_state()
    pid = int(state.get("pid") or 0) if state else 0
    alive = bool(pid and _pid_alive(pid))
    healthy = bridge_health(port)
    info = {"running": alive, "healthy": healthy, "pid": pid or None,
            "port": port, "base_url": f"http://127.0.0.1:{port}/v1",
            "pidfile": str(pidfile_path()), "log": str(logfile_path())}
    if fmt == "json":
        print(json.dumps(info, indent=2))
    else:
        if healthy:
            print(f"[bridge] healthy on http://127.0.0.1:{port} "
                  f"(pid {pid or '?'})")
        elif alive:
            print(f"[bridge] pid {pid} alive but NOT healthy "
                  f"(see {logfile_path()})")
        else:
            print("[bridge] not running  (velora serve-bridge --start)")
    return 0 if healthy else 1


# ---------------------------------------------------------------------------
# Foreground serve
# ---------------------------------------------------------------------------

def cmd_serve_bridge(args) -> int:
    mode = getattr(args, "bridge_cmd", None)
    if mode == "start":
        return start_bridge(args)
    if mode == "stop":
        return stop_bridge(args)
    if mode == "status":
        return status_bridge(args, fmt=getattr(args, "format", "text") or "text")

    prep, err = _prepare(args)
    if err:
        print(f"velora serve-bridge: {err}", file=sys.stderr)
        return 1
    port, oc_port = prep["port"], prep["oc_port"]
    conflict = _check_ports(port, oc_port)
    if conflict:
        print(f"velora serve-bridge: {conflict}", file=sys.stderr)
        return 1
    print(f"[serve-bridge] node     : {prep['node']}")
    print(f"[serve-bridge] opencode : {prep['opencode']}")
    print(f"[serve-bridge] bridge   : http://127.0.0.1:{port}  "
          f"(opencode on :{oc_port})")
    child = subprocess.Popen(_bridge_cmd(prep["node"], port, oc_port),
                             cwd=prep["dst"], env=prep["env"])
    try:
        if not _wait_health(port):
            print("velora serve-bridge: bridge did not become healthy in "
                  f"{int(_START_TIMEOUT)}s", file=sys.stderr)
            child.terminate()
            return 1
        print("[serve-bridge] healthy. Zero-key setup:")
        print(f"    export VELORA_LLM_BASE_URL={DEFAULT_BASE_URL}   "
              "# optional; `velora models tui` persists it instead")
        print("    velora models tui        # pick an opencode model (TTY)")
        print("    velora scan src/ --ai    # run with the active model")
        if getattr(args, "configure", False):
            try:
                _configure(f"http://127.0.0.1:{port}/v1",
                           getattr(args, "model", None))
            except Exception as exc:  # noqa: BLE001
                print(f"[serve-bridge] --configure failed: {exc}",
                      file=sys.stderr)
        while True:
            rc = child.poll()
            if rc is not None:
                return rc or 0
            time.sleep(0.5)
    except KeyboardInterrupt:
        print("\n[serve-bridge] shutting down")
        child.terminate()
        try:
            child.wait(timeout=10)
        except subprocess.TimeoutExpired:
            child.kill()
        return 0


def _configure(base_url: str, model: Optional[str]) -> None:
    from velora.sil import model_config
    if not model:
        with urllib.request.urlopen(f"{base_url}/models", timeout=10) as resp:
            rows = json.loads(resp.read()).get("data", [])
        if not rows:
            raise RuntimeError("bridge returned no models to configure")
        model = rows[0]["id"]
    path = model_config.save(provider="opencode-bridge", base_url=base_url,
                             model=model, source="opencode-bridge")
    print(f"[serve-bridge] active model set: opencode-bridge/{model} -> "
          f"{base_url}")
    print(f"[serve-bridge] saved to {path} (no API key stored)")
