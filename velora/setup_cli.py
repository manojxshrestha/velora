"""`velora setup` -- one-time bootstrap of the zero-key AI stack.

Diagnoses with `velora doctor`, shows exactly what will be installed, asks
once (or takes `--yes`), then:

* Node (official tarball -> ``~/.local/opt`` + ``~/.local/bin`` symlinks,
  no sudo; arch-aware for Linux/macOS x64+arm64)
* opencode (official installer script, shown in the consent text)
* bridge runtime dir (packaged sources + ``npm install``)

Finishes by starting the daemon and running one real keyless probe chat so
"works on my machine" is verified, not assumed. Idempotent: safe to re-run.
"""

from __future__ import annotations

import shutil
import subprocess
import sys
import tarfile
import tempfile
import urllib.request
from pathlib import Path
from typing import Callable, List, Optional, Tuple

from velora import bridge_cli, doctor_cli

NODE_VERSION = "v22.23.3"
NODE_BASE = f"https://nodejs.org/dist/{NODE_VERSION}"
OPENCODE_INSTALL_URL = "https://opencode.ai/install"

Report = Callable[[str], None]


def _node_asset() -> Optional[str]:
    system = {"linux": "linux", "darwin": "darwin"}.get(sys.platform)
    arch = {"x86_64": "x64", "amd64": "x64",
            "aarch64": "arm64", "arm64": "arm64"}.get(
                __import__("platform").machine().lower())
    if not system or not arch:
        return None
    return f"node-{NODE_VERSION}-{system}-{arch}.tar.xz"


def _download(url: str, dest: Path, report: Report) -> None:
    report(f"downloading {url}")
    with urllib.request.urlopen(url, timeout=60) as resp, open(dest, "wb") as out:
        total = int(resp.headers.get("Content-Length") or 0)
        done = 0
        while True:
            chunk = resp.read(1024 * 256)
            if not chunk:
                break
            out.write(chunk)
            done += len(chunk)
            if total and done // (10 * 1024 * 1024) != (done - len(chunk)) // (10 * 1024 * 1024):
                report(f"  ... {done // (1024 * 1024)}/{total // (1024 * 1024)} MB")
    report(f"downloaded {dest.name} ({dest.stat().st_size // (1024 * 1024)} MB)")


def _symlink(target: Path, link: Path) -> None:
    link.parent.mkdir(parents=True, exist_ok=True)
    if link.is_symlink() or link.exists():
        try:
            link.unlink()
        except OSError:
            return
    try:
        link.symlink_to(target)
    except OSError:
        shutil.copy2(target, link)


def install_node(report: Report = print) -> Tuple[bool, str]:
    node = bridge_cli.find_node()
    if node and bridge_cli.node_major(bridge_cli.tool_version(node)) >= bridge_cli.MIN_NODE_MAJOR:
        return True, f"already installed: {node}"
    asset = _node_asset()
    if not asset:
        return False, (f"unsupported platform for auto-install "
                       f"({sys.platform}); install Node "
                       f">= {bridge_cli.MIN_NODE_MAJOR} manually, then re-run")
    url = f"{NODE_BASE}/{asset}"
    with tempfile.TemporaryDirectory(prefix="velora-node-") as td:
        archive = Path(td) / asset
        _download(url, archive, report)
        report(f"extracting {asset} ...")
        with tarfile.open(archive) as tf:
            try:
                tf.extractall(td, filter="data")
            except TypeError:  # Python < 3.12
                tf.extractall(td)
        root = Path(td) / f"node-{NODE_VERSION}-{asset.split(f'node-{NODE_VERSION}-', 1)[1].rsplit('.tar', 1)[0]}"
        if not root.is_dir():
            return False, f"unexpected archive layout (no {root.name}/)"
        dest = Path.home() / ".local" / "opt" / root.name
        if dest.exists():
            shutil.rmtree(dest)
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.move(str(root), str(dest))
    for name in ("node", "npm", "npx"):
        target = dest / "bin" / name
        if target.exists() or target.is_symlink():
            _symlink(target, Path.home() / ".local" / "bin" / name)
    verify = subprocess.run([str(dest / "bin" / "node"), "--version"],
                            capture_output=True, text=True, timeout=30)
    if verify.returncode != 0:
        return False, f"node install verification failed: {verify.stderr.strip()}"
    return True, f"Node {NODE_VERSION} -> {dest} (symlinks in ~/.local/bin)"


def install_opencode(report: Report = print) -> Tuple[bool, str]:
    existing = bridge_cli.find_opencode()
    if existing:
        return True, f"already installed: {existing}"
    if not shutil.which("bash"):
        return False, "bash not found; install opencode manually: " \
                      f"see {OPENCODE_INSTALL_URL}"
    report(f"fetching the official installer: {OPENCODE_INSTALL_URL}")
    try:
        with urllib.request.urlopen(OPENCODE_INSTALL_URL, timeout=30) as resp:
            script = resp.read().decode("utf-8", errors="replace")
    except Exception as exc:  # noqa: BLE001
        return False, f"could not fetch installer ({exc}); install manually: " \
                      f"curl -fsSL {OPENCODE_INSTALL_URL} | bash"
    with tempfile.NamedTemporaryFile("w", suffix=".sh",
                                     prefix="opencode-install-",
                                     delete=False) as fh:
        fh.write(script)
        script_path = fh.name
    report("running the official installer ...")
    proc = subprocess.run(["bash", script_path], capture_output=True,
                          text=True, timeout=300)
    Path(script_path).unlink(missing_ok=True)
    found = bridge_cli.find_opencode()
    if found:
        return True, f"opencode -> {found}"
    tail = (proc.stderr or proc.stdout or "").strip().splitlines()[-5:]
    return False, "installer did not produce a usable binary:\n    " + \
        "\n    ".join(tail)


def _confirm(plan: List[str], assume_yes: bool,
             input_fn: Callable[[str], str] = input) -> bool:
    print("velora setup will:")
    for line in plan:
        print(f"  - {line}")
    if assume_yes:
        return True
    if not sys.stdin.isatty():
        print("non-interactive terminal: re-run with  velora setup --yes",
              file=sys.stderr)
        return False
    try:
        answer = input_fn("Proceed? [y/N] ").strip().lower()
    except (EOFError, KeyboardInterrupt):
        print()
        return False
    return answer in ("y", "yes")


def _print_result(ok: bool, label: str, detail: str) -> None:
    mark = "✅" if ok else "❌"
    print(f"  {mark} {label}: {detail}")


def cmd_setup(args) -> int:
    if bridge_cli.is_windows():
        print("velora setup: native Windows is not supported yet -- use WSL:\n"
              "    wsl --install", file=sys.stderr)
        return 1
    print(f"velora setup -- {bridge_cli.platform_summary()}")
    checks = doctor_cli.run_checks(probe=False)
    by_id = {c.id: c for c in checks}

    hard = [c for c in checks
            if c.failed and c.id not in ("bridge", "bridge-required")]
    node_gap = by_id["node"].failed
    oc_gap = by_id["opencode"].failed
    runtime_gap = by_id["bridge-runtime"].failed
    other = [c for c in hard
             if c.id not in ("node", "opencode", "bridge-runtime", "model")]

    plan: List[str] = []
    if node_gap:
        plan.append(f"install Node {NODE_VERSION} (official tarball -> "
                    "~/.local/opt, symlinks in ~/.local/bin, no sudo)")
    if oc_gap:
        plan.append(f"install opencode via the official script "
                    f"({OPENCODE_INSTALL_URL}) into ~/.opencode/bin")
    if runtime_gap:
        plan.append(f"seed bridge sources + npm install -> "
                    f"{bridge_cli.bridge_dir()}")
    if not plan:
        print("  all prerequisites already present")

    if other:
        print("\nthese need a manual fix (setup won't touch them):")
        for c in other:
            print(f"  ❌ {c.id}: {c.detail}")
            if c.fix:
                print(f"       fix: {c.fix}")
        return 1

    if plan and not _confirm(plan, bool(getattr(args, "yes", False))):
        print("aborted")
        return 1

    results: List[Tuple[bool, str, str]] = []
    if node_gap:
        ok, detail = install_node()
        results.append((ok, "node", detail))
        _print_result(ok, "node", detail)
    if oc_gap:
        ok, detail = install_opencode()
        results.append((ok, "opencode", detail))
        _print_result(ok, "opencode", detail)
    if runtime_gap or node_gap or oc_gap:
        err = bridge_cli.ensure_bridge()
        ok = err is None
        results.append((ok, "bridge deps", err or "seeded + installed"))
        _print_result(ok, "bridge deps", err or
                      f"seeded in {bridge_cli.bridge_dir()}")
    if any(not ok for ok, _, _ in results):
        print("\nsetup incomplete -- re-run `velora setup` after fixing the "
              "failures above; `velora doctor` shows current state")
        return 1

    if not getattr(args, "no_start", False):
        if bridge_cli.bridge_health():
            print("✅ bridge: already running")
        else:
            rc = bridge_cli.start_bridge()
            if rc != 0:
                print("❌ bridge: failed to start (see above; "
                      "`velora doctor` for state)", file=sys.stderr)
                return 1

    if not getattr(args, "no_probe", False):
        if bridge_cli.bridge_health():
            ok, detail = doctor_cli.probe_chat()
            _print_result(ok, "probe", detail)
            if not ok:
                print("    (the bridge works; the free tier refused this "
                      "account/IP -- retry later or check opencode status)")
        else:
            _print_result(False, "probe", "bridge not running (skipped)")

    _, model, _, source = doctor_cli._active_model()
    print("\nnext steps:")
    if not model:
        print("    velora models tui          # pick a model (auto-starts "
              "the bridge)")
    else:
        print(f"    active model: {model} [{source}]")
    print("    velora scan src/ --ai      # zero-key AI scan")
    print("    velora doctor              # re-check anytime")
    return 0
