"""`velora models tui` -- interactive model picker (opencode bridge + local).

Sources probed on every run:

* the local ``velora serve-bridge`` (opencode's model catalog, free tier
  included) -- optional; a down bridge just means no bridge entries
* OpenAI-compatible local servers: mlx-optiq (the README benchmark setup on
  port 47317), Ollama, LM Studio, llama.cpp, vLLM -- plus extras from
  ``$VELORA_LOCAL_URLS`` (comma-separated ``NAME=URL``) or repeatable
  ``--local-url``

The selection is persisted through ``velora.sil.model_config`` so
``velora scan --ai`` picks it up. Local servers need no key; none is stored.
"""

from __future__ import annotations

import json
import os
import sys
import urllib.request
from typing import Callable, Dict, List, Optional, Tuple
from urllib.parse import urlparse

from velora import bridge_cli
from velora.bridge_cli import DEFAULT_BASE_URL
from velora.sil import model_config

DEFAULT_BRIDGE = DEFAULT_BASE_URL
PROVIDER = "opencode-bridge"
SOURCE = "opencode-bridge"
LOCAL_SOURCE = "local"
BRIDGE_TIMEOUT = 5.0
LOCAL_TIMEOUT = 1.0

DEFAULT_LOCAL_ENDPOINTS: Tuple[Tuple[str, str], ...] = (
    ("optiq", "http://localhost:47317/v1"),   # mlx-optiq, README setup
    ("ollama", "http://localhost:11434/v1"),
    ("lmstudio", "http://localhost:1234/v1"),
    ("llama.cpp", "http://localhost:8080/v1"),
    ("vllm", "http://localhost:8000/v1"),
)


def bridge_base(args=None) -> str:
    for candidate in (
        (getattr(args, "base_url", None) if args is not None else None),
        os.environ.get("VELORA_BRIDGE_URL"),
        DEFAULT_BRIDGE,
    ):
        if candidate:
            return candidate.rstrip("/")
    return DEFAULT_BRIDGE


def fetch_models(base_url: str, timeout: float = 5.0) -> List[str]:
    with urllib.request.urlopen(f"{base_url.rstrip('/')}/models",
                                timeout=timeout) as resp:
        payload = json.loads(resp.read())
    rows = payload.get("data") or []
    ids = [str(r.get("id") or "") for r in rows]
    return [i for i in ids if i]


def _name_from_url(url: str) -> str:
    netloc = urlparse(url).netloc
    return netloc.replace(":", "-") or "local"


def parse_endpoint(spec: str) -> Tuple[str, str]:
    """``NAME=URL`` or a bare URL (name derived from host:port)."""
    spec = (spec or "").strip()
    if not spec:
        raise ValueError("empty endpoint spec")
    if spec.startswith(("http://", "https://")):
        return _name_from_url(spec), spec.rstrip("/")
    if "=" not in spec:
        raise ValueError(f"expected NAME=URL or URL, got {spec!r}")
    name, url = spec.split("=", 1)
    name, url = name.strip(), url.strip().rstrip("/")
    if not name:
        raise ValueError(f"missing NAME in {spec!r}")
    if not url.startswith(("http://", "https://")):
        raise ValueError(f"missing http(s) URL in {spec!r}")
    return name, url


def local_endpoints(args=None) -> List[Tuple[str, str]]:
    specs: List[str] = []
    env = os.environ.get("VELORA_LOCAL_URLS", "")
    specs += [s for s in env.split(",") if s.strip()]
    specs += list(getattr(args, "local_url", None) or [])

    by_url: Dict[str, str] = {}
    for name, url in DEFAULT_LOCAL_ENDPOINTS:
        by_url[url] = name
    for spec in specs:
        name, url = parse_endpoint(spec)
        by_url[url] = name

    used: Dict[str, int] = {}
    out: List[Tuple[str, str]] = []
    for url, name in by_url.items():
        count = used.get(name, 0)
        used[name] = count + 1
        out.append((f"{name}-{count + 1}" if count else name, url))
    return out


def _bridge_entry(model_id: str, base: str) -> dict:
    full = model_id if model_id.startswith("opencode/") else f"opencode/{model_id}"
    return {"provider": PROVIDER, "base_url": base, "model": full,
            "source": SOURCE, "label": f"[bridge] {full}"}


def discover(args=None) -> Tuple[List[dict], str]:
    """Probe every source; return (entries, human summary). Never raises."""
    entries: List[dict] = []
    notes: List[str] = []

    base = bridge_base(args)
    try:
        ids = fetch_models(base, timeout=BRIDGE_TIMEOUT)
        entries += [_bridge_entry(mid, base) for mid in ids]
        notes.append(f"bridge: {len(ids)}")
    except Exception:  # noqa: BLE001 -- bridge optional
        notes.append("bridge: down")

    try:
        endpoints = local_endpoints(args)
    except ValueError as exc:
        notes.append(f"bad endpoint spec: {exc}")
        endpoints = list(DEFAULT_LOCAL_ENDPOINTS)

    up: List[str] = []
    down = 0
    for name, url in endpoints:
        try:
            ids = fetch_models(url, timeout=LOCAL_TIMEOUT)
        except Exception:  # noqa: BLE001 -- endpoint not running
            down += 1
            continue
        if not ids:
            down += 1
            continue
        up.append(name)
        entries += [
            {"provider": name, "base_url": url, "model": mid,
             "source": LOCAL_SOURCE, "label": f"[{name}] {mid}"}
            for mid in ids
        ]
    if up:
        notes.append("local: " + ", ".join(up))
    if down:
        notes.append(f"local down: {down}/{len(endpoints)}")
    return entries, "; ".join(notes)


def _active_key() -> Optional[Tuple[str, str]]:
    cfg = model_config.active()
    if not cfg:
        return None
    provider = str(cfg.get("provider") or "")
    model = str(cfg.get("model") or "")
    if provider and model:
        return (provider, model)
    return None


def render_list(entries: List[dict], active_key, cursor: int) -> str:
    lines = []
    for i, entry in enumerate(entries):
        marker = ">" if i == cursor else " "
        star = "  [active]" if (entry["provider"], entry["model"]) == active_key else ""
        lines.append(f" {marker} {entry['label']}{star}")
    return "\n".join(lines)


def choose_prompt(entries: List[dict], active_key,
                  input_fn: Callable[[str], str] = input) -> Optional[int]:
    print(f"models ({len(entries)}):")
    for i, entry in enumerate(entries, 1):
        star = ("  [active]" if (entry["provider"], entry["model"]) == active_key
                else "")
        print(f"  {i:>3}. {entry['label']}{star}")
    while True:
        try:
            raw = input_fn(f"Select 1-{len(entries)} (Enter cancels): ").strip()
        except (EOFError, KeyboardInterrupt):
            return None
        if not raw:
            return None
        if raw.isdigit() and 1 <= int(raw) <= len(entries):
            return int(raw) - 1
        print(f"  out of range: {raw!r}")


def run_curses(entries: List[dict], active_key,
               summary: str = "") -> Optional[int]:
    import curses

    def _main(screen):
        curses.curs_set(0)
        screen.keypad(True)
        cursor = next((i for i, e in enumerate(entries)
                       if (e["provider"], e["model"]) == active_key), 0)
        query: Optional[str] = None
        offset = 0

        def matches() -> List[int]:
            if not query:
                return list(range(len(entries)))
            q = query.lower()
            return [i for i, e in enumerate(entries) if q in e["label"].lower()]

        while True:
            screen.erase()
            idxs = matches()
            if cursor not in idxs:
                cursor = idxs[0] if idxs else 0
            height, width = screen.getmaxyx()
            title = (" model picker: opencode bridge + local -- arrows/j/k, "
                     "Enter select, / filter, q quit ")
            screen.addnstr(0, 0, title.ljust(width - 1), width - 1,
                           curses.A_REVERSE)
            status = f" {len(idxs)}/{len(entries)} models"
            if summary:
                status += f"  --  {summary}"
            if query is not None:
                status += f"  filter: {query}_"
            screen.addnstr(1, 0, status, width - 1)
            list_top = 3
            visible = max(1, height - list_top - 1)
            if cursor < offset:
                offset = cursor
            if cursor >= offset + visible:
                offset = cursor - visible + 1
            for row, i in enumerate(idxs[offset:offset + visible]):
                entry = entries[i]
                attr = curses.A_REVERSE if i == cursor else curses.A_NORMAL
                if (entry["provider"], entry["model"]) == active_key and i != cursor:
                    attr = curses.A_BOLD
                label = f" {entry['label']}"
                if (entry["provider"], entry["model"]) == active_key:
                    label += "  [active]"
                screen.addnstr(list_top + row, 0, label.ljust(width - 1),
                               width - 1, attr)
            hint = (" ↑/↓ or j/k move   Enter select   / filter   "
                    "Esc clear   q quit ")
            screen.addnstr(height - 1, 0, hint.ljust(width - 1), width - 1,
                           curses.A_DIM)
            screen.refresh()
            key = screen.getch()
            idxs = matches()
            pos = idxs.index(cursor) if cursor in idxs else 0
            if key in (ord("q"), ord("Q")):
                return None
            if key in (curses.KEY_UP, ord("k")) and idxs:
                pos = (pos - 1) % len(idxs)
                cursor = idxs[pos]
            elif key in (curses.KEY_DOWN, ord("j")) and idxs:
                pos = (pos + 1) % len(idxs)
                cursor = idxs[pos]
            elif key == curses.KEY_PAGEUP and idxs:
                pos = max(0, pos - visible)
                cursor = idxs[pos]
            elif key == curses.KEY_PAGEDOWN and idxs:
                pos = min(len(idxs) - 1, pos + visible)
                cursor = idxs[pos]
            elif key in (curses.KEY_HOME, ord("g")) and idxs:
                cursor = idxs[0]
            elif key in (curses.KEY_END, ord("G")) and idxs:
                cursor = idxs[-1]
            elif key in (curses.KEY_ENTER, 10, 13):
                return cursor
            elif key == 27:
                query = None
            elif key == ord("/"):
                curses.curs_set(1)
                buf = ""
                while True:
                    screen.addnstr(2, 0, f" /{buf}_".ljust(width - 1),
                                   width - 1, curses.A_REVERSE)
                    screen.refresh()
                    ch = screen.getch()
                    if ch in (curses.KEY_ENTER, 10, 13):
                        query = buf or None
                        break
                    if ch == 27:
                        break
                    if ch in (curses.KEY_BACKSPACE, 127, 8):
                        buf = buf[:-1]
                    elif 32 <= ch < 127:
                        buf += chr(ch)
                curses.curs_set(0)
            elif 32 <= key < 127 and query is not None:
                query = (query + chr(key))
            elif key in (curses.KEY_BACKSPACE, 127, 8) and query:
                query = query[:-1] or None

    return curses.wrapper(_main)


def cmd_tui(args) -> int:
    if bridge_base(args) == DEFAULT_BRIDGE and not bridge_cli.bridge_health():
        print("[velora] bridge not running -- starting it in the background "
              "(velora serve-bridge --stop to end it)")
        try:
            if bridge_cli.start_bridge() != 0:
                print("[velora] auto-start failed -- `velora doctor` explains why",
                      file=sys.stderr)
        except Exception as exc:  # noqa: BLE001
            print(f"[velora] auto-start failed: {exc}", file=sys.stderr)
    entries, summary = discover(args)
    if not entries:
        print("velora models tui: no models found\n"
              f"  probed: {summary}\n"
              "  start the bridge:       velora serve-bridge\n"
              "  start a local server:   ollama serve / optiq serve / ... "
              "(see README)\n"
              "  or point at one:        --local-url NAME=URL "
              "(or VELORA_LOCAL_URLS=NAME=URL,...)",
              file=sys.stderr)
        return 1
    active_key = _active_key()

    selection: Optional[int] = None
    if sys.stdin.isatty() and sys.stdout.isatty():
        try:
            selection = run_curses(entries, active_key, summary)
        except Exception:  # noqa: BLE001 -- fall back to prompt-style picker
            selection = None
        if selection is None:
            return 0
    else:
        print(f"probed: {summary}")
        selection = choose_prompt(entries, active_key)
        if selection is None:
            print("cancelled")
            return 0

    chosen = entries[selection]
    path = model_config.save(provider=chosen["provider"],
                             base_url=chosen["base_url"],
                             model=chosen["model"], source=chosen["source"])
    print(f"Active model set: {chosen['provider']}/{chosen['model']} -> "
          f"{chosen['base_url']}")
    print(f"Saved to {path} (no API key stored). "
          "`velora scan --ai` picks this up automatically.")
    return 0
