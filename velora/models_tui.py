"""`velora models tui` -- interactive model picker (all velora sources).

Sources probed on every run, in merge order:

* the local ``velora serve-bridge`` (opencode's free tier) -- optional; a down
  bridge just means no bridge entries
* opencode itself: providers declared in ``opencode.json`` plus keys acquired
  via ``/connect`` -- OpenAI-compatible ones are listed with their keys
  *reused* (velora stores nothing); native transports (google, anthropic, ...)
  are counted as phase 2 and listed once the bridge serves them
* OpenCode Zen's catalog (free tier first, prices shown) -- rows are gated on
  a key (env / opencode /connect / velora credentials, never copied)
* OpenAI-compatible local servers: mlx-optiq (the README benchmark setup on
  port 47317), Ollama, LM Studio, llama.cpp, vLLM -- plus extras from
  ``$VELORA_LOCAL_URLS`` (comma-separated ``NAME=URL``) or repeatable
  ``--local-url``
* with ``--registry``: the full models.dev registry (ready rows only,
  free-first, price labels), deduped against everything above

The selection is persisted through ``velora.sil.model_config`` so
``velora scan --ai`` picks it up. Local servers need no key; hosted rows reuse
their key from opencode/env at runtime -- none is stored by the picker.
"""

from __future__ import annotations

import json
import os
import sys
import urllib.request
from typing import Callable, Dict, List, Optional, Set, Tuple
from urllib.parse import urlparse

from velora import bridge_cli
from velora.bridge_cli import DEFAULT_BASE_URL
from velora.sil import model_config
from velora.sil import opencode_bridge
from velora.sil.model_catalog import ZEN_BASE_URL, registry_models, zen_models

DEFAULT_BRIDGE = DEFAULT_BASE_URL
PROVIDER = "opencode-bridge"
SOURCE = "opencode-bridge"
LOCAL_SOURCE = "local"
OPENCODE_SOURCE = "opencode"
ZEN_SOURCE = "zen"
REGISTRY_SOURCE = "velora-models"
BRIDGE_TIMEOUT = 5.0
LOCAL_TIMEOUT = 1.0

DEFAULT_LOCAL_ENDPOINTS: Tuple[Tuple[str, str], ...] = (
    ("optiq", "http://localhost:47317/v1"),   # mlx-optiq, README setup
    ("ollama", "http://localhost:11434/v1"),
    ("lmstudio", "http://localhost:1234/v1"),
    ("llama.cpp", "http://localhost:8080/v1"),
    ("vllm", "http://localhost:8000/v1"),
)

_KEYLESS: Set[str] = {PROVIDER, "ollama", "lmstudio", "llama.cpp", "optiq", "vllm"}


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
    url = f"{base_url.rstrip('/')}/models"
    # Bearer for velora's own bridge (BUG-013); empty for anything else.
    req = urllib.request.Request(url, headers=bridge_cli.auth_headers(url))
    with urllib.request.urlopen(req, timeout=timeout) as resp:
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
            "source": SOURCE, "label": f"[bridge] {full}",
            "key_status": "keyless"}


def _load_setup_safe():
    try:
        return opencode_bridge.load_setup()
    except Exception:  # noqa: BLE001 -- opencode optional everywhere
        return None


def _opencode_entries(setup, add, local_names: Set[str]) -> str:
    """Rows from opencode's config + ``/connect`` store (keys reused, never copied).

    Native-transport providers (google, anthropic, ...) are counted only --
    velora's /chat/completions client can't call them until the bridge serves
    them (phase 2).
    """
    if setup is None:
        return ""
    meta: Optional[dict] = None
    rows = native = nokey = 0
    for pid, prov in sorted(setup.providers.items()):
        if pid in local_names:
            continue                      # the live local probe owns these
        if not prov.compatible:
            if prov.api_key or prov.oauth:
                native += 1
            continue                      # native transport -- phase 2
        if not prov.endpoint:
            continue
        models = sorted(prov.models or {})
        if not models:
            if meta is None:
                meta = opencode_bridge._models_dev_meta()
            models = sorted((meta.get(pid) or {}).get("models") or {})
        if not models:
            continue
        if prov.api_key:
            status = "ok"
        elif pid in _KEYLESS:
            status = "keyless"
        else:
            status = "nokey"
            nokey += 1
        for mid in models:
            if add({"provider": pid, "base_url": prov.endpoint, "model": mid,
                    "source": OPENCODE_SOURCE,
                    "label": f"[opencode] {pid}/{mid}",
                    "key_status": status}):
                rows += 1
    if not (rows or native or nokey):
        return ""
    extra = ", ".join(x for x in (
        f"{nokey} no key" if nokey else "",
        f"{native} native/phase 2" if native else "",
    ) if x)
    return f"opencode: {rows}" + (f" ({extra})" if extra else "")


def _zen_entries(setup, add, bridge_ids: Set[str], zen_ids: Set[str]) -> str:
    """Zen catalog, free first; keyed rows reuse the key (nothing copied)."""
    try:
        rows = zen_models()
    except Exception:  # noqa: BLE001 -- catalog offline is fine
        return ""
    key = model_config.provider_reuse_key("zen", _setup=setup)
    status = "ok" if key else "nokey"
    added = free = 0
    for row in rows:
        if not row.ready:
            continue
        zen_ids.add(row.id)
        if row.id in bridge_ids:
            continue                      # the bridge already serves it keyless
        if add({"provider": "zen", "base_url": ZEN_BASE_URL, "model": row.id,
                "source": ZEN_SOURCE,
                "label": f"[zen] {row.id}  {row.price_label}",
                "key_status": status}):
            added += 1
            if row.free:
                free += 1
    if not added:
        return ""
    extra = f"{free} free" + (", no key" if status == "nokey" else "")
    return f"zen: {added} ({extra})"


def _keyed_pids(setup, meta: dict) -> Set[str]:
    """Provider ids with a usable key somewhere (velora / opencode / env)."""
    pids: Set[str] = set()
    try:
        creds = json.loads(model_config.credentials_path().read_text())
        if isinstance(creds, dict):
            pids.update(k for k, v in creds.items() if v)
    except (OSError, ValueError):
        pass
    if setup:
        pids.update(pid for pid, p in setup.providers.items() if p.api_key)
    for pid, m in (meta or {}).items():
        envs = m.get("env") if isinstance(m, dict) else None
        if isinstance(envs, list) and any(os.environ.get(str(e)) for e in envs):
            pids.add(pid)
    if os.environ.get("OPENCODE_API_KEY"):
        pids.update({"zen", "opencode"})
    if os.environ.get("VELORA_LLM_API_KEY"):
        pids.add("*")                     # generic override keys every row
    return pids


def _registry_entries(args, add, zen_ids: Set[str],
                      local_names: Set[str]) -> str:
    """Full models.dev registry behind --registry: ready rows, free first."""
    try:
        rows = registry_models(query=getattr(args, "query", None))
    except Exception as exc:  # noqa: BLE001 -- offline without cache
        return f"models.dev: down ({exc.__class__.__name__})"
    meta = opencode_bridge._models_dev_meta()
    keyed = _keyed_pids(_load_setup_safe(), meta)
    added = nokey = 0
    for row in rows:
        if not row.ready or row.provider in local_names:
            continue
        if row.provider == "opencode" and row.id in zen_ids:
            continue                      # already listed as [zen]
        m = meta.get(row.provider) or {}
        api = m.get("api")
        base = (api if isinstance(api, str) and api.startswith("http")
                else opencode_bridge.DEFAULT_ENDPOINTS.get(row.provider, ""))
        if not base:
            continue
        status = "ok" if ("*" in keyed or row.provider in keyed) else "nokey"
        if add({"provider": row.provider, "base_url": base, "model": row.id,
                "source": REGISTRY_SOURCE,
                "label": f"[{row.provider}] {row.id}  {row.price_label}",
                "key_status": status}):
            added += 1
            if status == "nokey":
                nokey += 1
    extra = f"{nokey} no key" if nokey else ""
    return f"models.dev: {added}" + (f" ({extra})" if extra else "")


def discover(args=None) -> Tuple[List[dict], str]:
    """Probe every source; return (entries, human summary). Never raises.

    Merge order: bridge (free default) -> opencode config + /connect -> zen
    -> local servers -> models.dev registry (with ``--registry``). Entries
    dedup on (provider, model); the first source wins.
    """
    entries: List[dict] = []
    notes: List[str] = []
    seen: Set[Tuple[str, str]] = set()

    def add(entry: dict) -> bool:
        key = (entry["provider"], entry["model"])
        if key in seen:
            return False
        seen.add(key)
        entries.append(entry)
        return True

    base = bridge_base(args)
    bridge_ids: Set[str] = set()
    try:
        ids = fetch_models(base, timeout=BRIDGE_TIMEOUT)
        for mid in ids:
            if add(_bridge_entry(mid, base)):
                bridge_ids.add(mid.split("/", 1)[1]
                               if mid.startswith("opencode/") else mid)
        notes.append(f"bridge: {len(ids)}")
    except Exception:  # noqa: BLE001 -- bridge optional
        notes.append("bridge: down")

    try:
        endpoints = local_endpoints(args)
    except ValueError as exc:
        notes.append(f"bad endpoint spec: {exc}")
        endpoints = list(DEFAULT_LOCAL_ENDPOINTS)
    local_names = {name for name, _ in endpoints}

    setup = _load_setup_safe()
    note = _opencode_entries(setup, add, local_names)
    if note:
        notes.append(note)

    zen_ids: Set[str] = set()
    note = _zen_entries(setup, add, bridge_ids, zen_ids)
    if note:
        notes.append(note)

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
        for mid in ids:
            add({"provider": name, "base_url": url, "model": mid,
                 "source": LOCAL_SOURCE, "label": f"[{name}] {mid}",
                 "key_status": "keyless"})
    if up:
        notes.append("local: " + ", ".join(up))
    if down:
        notes.append(f"local down: {down}/{len(endpoints)}")

    if getattr(args, "registry", False):
        note = _registry_entries(args, add, zen_ids, local_names)
        if note:
            notes.append(note)

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
            title = (" model picker: bridge + paid + local -- arrows/j/k, "
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
            elif key == curses.KEY_PPAGE and idxs:
                pos = max(0, pos - visible)
                cursor = idxs[pos]
            elif key == curses.KEY_NPAGE and idxs:
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
              "(or VELORA_LOCAL_URLS=NAME=URL,...)\n"
              "  connect a paid key:     opencode /connect, then re-run\n"
              "  browse models.dev:      velora models tui --registry",
              file=sys.stderr)
        return 1
    active_key = _active_key()

    selection: Optional[int] = None
    if sys.stdin.isatty() and sys.stdout.isatty():
        try:
            selection = run_curses(entries, active_key, summary)
        except Exception as exc:  # noqa: BLE001 -- prompt-style exit
            print(f"[velora] tui view failed: {exc!r}", file=sys.stderr)
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
    if chosen.get("key_status") == "nokey":
        pid, mid = chosen["provider"], chosen["model"]
        print(f"velora models tui: no API key for {pid}/{mid}", file=sys.stderr)
        if chosen.get("source") == ZEN_SOURCE:
            print("  zen needs a key (free models too): set OPENCODE_API_KEY, "
                  "or /connect in opencode, or\n"
                  f"  velora models use zen/{mid} --api-key ...",
                  file=sys.stderr)
        else:
            print("  connect it in opencode (/connect), store it with velora, "
                  "or\n"
                  f"  velora models use {pid}/{mid} --api-key ... "
                  f"--base-url {chosen['base_url']}",
                  file=sys.stderr)
        return 1
    path = model_config.save(provider=chosen["provider"],
                             base_url=chosen["base_url"],
                             model=chosen["model"], source=chosen["source"])
    print(f"Active model set: {chosen['provider']}/{chosen['model']} -> "
          f"{chosen['base_url']}")
    src = chosen.get("source", "")
    if src in (SOURCE, LOCAL_SOURCE):
        stored = "no API key stored"
    elif src == OPENCODE_SOURCE:
        stored = "keys reused from opencode /connect (nothing copied)"
    else:
        cred = (model_config.get_credential("zen")
                or model_config.get_credential("opencode")
                if src == ZEN_SOURCE
                else model_config.get_credential(chosen["provider"]))
        stored = ("credentials 0600" if cred else
                  "key reused from env / opencode /connect (nothing copied)")
    print(f"Saved to {path} ({stored}). "
          "`velora scan --ai` picks this up automatically.")
    return 0
