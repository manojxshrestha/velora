"""`velora models` -- browse free/paid AI models and switch the active one.

Sources: OpenCode Zen (curated gateway, incl. free tier) and the models.dev
registry opencode itself uses. Providers come from OpenCode's config/auth,
from `velora models use`, or from VELORA_LLM_* env vars.

    velora models list                 # Zen catalog (free first)
    velora models list --registry      # full models.dev registry
    velora models use zen/glm-5.2      # free tier, zero RAM
    velora models use opencode/<provider>/<model>   # reuse opencode setup
    velora models current | providers | import-opencode

The chosen model feeds `velora scan --ai` via LLMConfig.from_env (env >
velora config > opencode fallback).
"""

from __future__ import annotations

import getpass
import json
import os
import sys
from typing import List, Optional

from velora.sil import model_config
from velora.sil.model_catalog import (
    CatalogError, CatalogModel, ZEN_BASE_URL, registry_models, registry_stats,
    zen_lookup, zen_models,
)
from velora.sil.opencode_bridge import (
    DEFAULT_ENDPOINTS, ProviderCfg, load_setup,
)

_LOCAL_PROVIDERS = {"ollama", "lmstudio", "llama.cpp"}
_ZEN = "zen"


def _err(msg: str) -> int:
    print(f"velora models: {msg}", file=sys.stderr)
    return 1


def _active_line() -> Optional[str]:
    env_model = os.environ.get("VELORA_LLM_MODEL", "")
    env_base = os.environ.get("VELORA_LLM_BASE_URL", "")
    if env_model and env_base:
        return f"ACTIVE  {env_model} -> {env_base} (env VELORA_LLM_*)"
    if env_model and not env_base:
        return f"ACTIVE  {env_model} (env VELORA_LLM_MODEL; endpoint from config)"
    cfg = model_config.active()
    if cfg:
        return (f"ACTIVE  {cfg['provider']}/{cfg['model']} -> {cfg['base_url']} "
                f"({cfg.get('source', 'config')})")
    setup = None
    try:
        setup = load_setup()
    except Exception:  # noqa: BLE001
        setup = None
    if setup and setup.default_model and setup.default_provider:
        prov = setup.providers.get(setup.default_provider)
        if prov is not None and prov.compatible:
            return (f"ACTIVE  {setup.default_provider}/{setup.default_model} -> "
                    f"{prov.endpoint} (opencode fallback)")
    return None


# ---------------------------------------------------------------------------
# list
# ---------------------------------------------------------------------------

def _row(m: CatalogModel) -> str:
    mark = "✓" if m.ready else "✗"
    price = f"{m.price_label:<14}"
    note = f"  [{m.note}]" if m.note else ""
    return f"  {mark} {price} {m.id:<34} {m.name}{note}"


def _render_models(rows: List[CatalogModel], active: Optional[str]) -> int:
    print(active or "ACTIVE  none (run `velora models use zen/<model>` to set one)")
    print()
    if rows and rows[0].source == "zen":
        print(f"OpenCode Zen models ({len(rows)}) -- {ZEN_BASE_URL}:")
    else:
        print(f"models.dev registry -- showing {len(rows)}:")
    for m in rows:
        print(_row(m))
    free = sum(1 for m in rows if m.free)
    ready = sum(1 for m in rows if m.ready)
    print(f"\n{len(rows)} models ({free} free, {ready} ready for Velora's "
          f"/chat/completions client)")
    if rows and rows[0].source == "zen":
        print("✗ = phase 2 (non-OpenAI transport: responses/anthropic/google). "
              "Full catalog: `velora models list --registry`")
    return 0


def cmd_list(args) -> int:
    active = _active_line()
    try:
        if getattr(args, "registry", False):
            rows = registry_models(
                refresh=args.refresh, query=args.query,
                free_only=args.free, provider=args.provider,
                limit=args.limit if args.limit is not None else
                (50 if not (args.query or args.free or args.provider) else None),
            )
            if args.format == "json":
                print(json.dumps({"active": active, "models": [
                    m.__dict__ for m in rows]}, indent=2))
                return 0
            if active:
                print(active)
                print()
            stats = registry_stats()
            print(f"models.dev registry: {stats['providers']} providers, "
                  f"{stats['models']} models, {stats['free']} free")
            for m in rows:
                print(_row(m))
            if args.limit is None and len(rows) == 50 and not (args.query or args.free or args.provider):
                print("  ... (default --limit 50; raise with --limit N)")
            return 0
        rows = zen_models(refresh=args.refresh)
        if args.free:
            rows = [m for m in rows if m.free]
        if args.query:
            q = args.query.lower()
            rows = [m for m in rows
                    if q in m.id.lower() or q in m.name.lower()]
        if args.provider and args.provider != _ZEN:
            rows = []
        if args.format == "json":
            print(json.dumps({"active": active, "models": [
                m.__dict__ for m in rows]}, indent=2))
            return 0
        return _render_models(rows, active)
    except CatalogError as exc:
        return _err(str(exc))


# ---------------------------------------------------------------------------
# use
# ---------------------------------------------------------------------------

def _prompt_key(provider: str, no_prompt: bool) -> Optional[str]:
    if no_prompt or not sys.stdin.isatty():
        return None
    try:
        return getpass.getpass(
            f"{provider} API key (stored 0600 in {model_config.credentials_path()}): "
        ) or None
    except (EOFError, KeyboardInterrupt):
        return None


def _resolve_zen(ref_id: str, args) -> Optional[dict]:
    row = zen_lookup(ref_id)
    if row is None:
        return None
    if not row.ready:
        return {"error": f"zen/{ref_id} uses the {row.transport} transport "
                         f"(phase 2) -- not yet supported by Velora's client"}
    key = (getattr(args, "api_key", None)
           or os.environ.get("OPENCODE_API_KEY")
           or model_config.get_credential(_ZEN))
    if not key:
        setup = None
        try:
            setup = load_setup()
        except Exception:  # noqa: BLE001
            setup = None
        if setup:
            for pid in (_ZEN, "opencode"):
                prov = setup.providers.get(pid)
                if prov is not None and prov.api_key:
                    key = prov.api_key
                    break
    if not key:
        key = _prompt_key("zen", getattr(args, "no_prompt", False))
    if not key:
        return {"error": "zen needs an API key (free models too): set "
                         "OPENCODE_API_KEY, or rerun with a tty to prompt, "
                         "or pass --api-key"}
    return {"provider": _ZEN, "base_url": ZEN_BASE_URL, "model": ref_id,
            "api_key": key, "source": "velora-models"}


def _resolve_opencode(path: str, args) -> Optional[dict]:
    if "/" not in path:
        return {"error": "usage: velora models use opencode/<provider>/<model>"}
    pid, mid = path.split("/", 1)
    try:
        setup = load_setup()
    except Exception as exc:  # noqa: BLE001
        return {"error": f"could not read opencode config: {exc}"}
    prov = (setup.providers.get(pid) if setup else None)
    if prov is None:
        return {"error": f"opencode has no provider '{pid}'"}
    if not prov.compatible:
        return {"error": f"provider '{pid}' is not OpenAI-compatible "
                         f"(native transport -- phase 2)"}
    if not prov.endpoint:
        return {"error": f"provider '{pid}' has no resolvable endpoint "
                         f"(pass --base-url)"}
    key = (getattr(args, "api_key", None) or prov.api_key
           or model_config.get_credential(pid))
    if not key:
        if pid in _LOCAL_PROVIDERS:
            key = "sk-local"
        else:
            key = _prompt_key(pid, getattr(args, "no_prompt", False))
    if not key:
        return {"error": f"no API key for '{pid}' (set one in opencode auth, "
                         f"--api-key, or rerun with a tty)"}
    return {"provider": pid, "base_url": prov.endpoint, "model": mid,
            "api_key": key, "source": "opencode"}


def _resolve_generic(path: str, args) -> Optional[dict]:
    if "/" not in path:
        return {"error": f"unknown model '{path}': use zen/<id>, "
                         f"opencode/<provider>/<model>, or <provider>/<model> "
                         f"with --base-url"}
    pid, mid = path.split("/", 1)
    base = (getattr(args, "base_url", None)
            or DEFAULT_ENDPOINTS.get(pid, "")).rstrip("/")
    if not base:
        return {"error": f"no known endpoint for '{pid}': pass --base-url "
                         f"https://... (models.dev gives pricing, not endpoints)"}
    key = (getattr(args, "api_key", None)
           or os.environ.get("VELORA_LLM_API_KEY")
           or model_config.get_credential(pid))
    if not key:
        if pid in _LOCAL_PROVIDERS:
            key = "sk-local"
        else:
            key = _prompt_key(pid, getattr(args, "no_prompt", False))
    if not key:
        return {"error": f"no API key for '{pid}': pass --api-key or rerun "
                         f"with a tty to prompt"}
    return {"provider": pid, "base_url": base, "model": mid,
            "api_key": key, "source": "velora-models"}


def cmd_use(args) -> int:
    ref = args.ref
    if not ref:
        return _err("usage: velora models use <zen/ID | opencode/PROVIDER/MODEL | PROVIDER/MODEL>")
    if ref.startswith("zen/"):
        entry = _resolve_zen(ref.split("/", 1)[1], args)
    elif ref.startswith("opencode/"):
        entry = _resolve_opencode(ref[len("opencode/"):], args)
    elif "/" not in ref:
        entry = _resolve_zen(ref, args)   # bare id -> Zen shorthand
    else:
        entry = _resolve_generic(ref, args)
    if entry is None:
        return _err(f"'{ref}' is not in the Zen catalog "
                    f"(see `velora models list`)")
    if "error" in entry:
        return _err(entry["error"])
    prev = model_config.active()
    path = model_config.save(
        provider=entry["provider"], base_url=entry["base_url"],
        model=entry["model"], source=entry.get("source", "velora-models"),
        api_key=entry.get("api_key"),
    )
    replaced = (f" (replaces {prev['provider']}/{prev['model']})" if prev else "")
    print(f"Active model set: {entry['provider']}/{entry['model']} -> "
          f"{entry['base_url']}{replaced}")
    print(f"Saved to {path}; credentials 0600. "
          f"`velora scan --ai` picks this up automatically "
          f"(VELORA_LLM_* env still wins).")
    return 0


# ---------------------------------------------------------------------------
# current / providers / import-opencode
# ---------------------------------------------------------------------------

def cmd_current(args) -> int:
    active = _active_line()
    if args.format == "json":
        cfg = model_config.load()
        print(json.dumps({
            "active": active,
            "config": cfg or None,
            "env": {k: os.environ[k] for k in
                    ("VELORA_LLM_BASE_URL", "VELORA_LLM_MODEL")
                    if k in os.environ},
        }, indent=2))
        return 0
    print(active or "No model configured. Try: "
          "velora models use zen/glm-5.2   (free hosted model)")
    return 0


def _env_keys() -> List[tuple]:
    out = []
    for var, name in (("OPENAI_API_KEY", "openai"),
                      ("OPENROUTER_API_KEY", "openrouter"),
                      ("GROQ_API_KEY", "groq"),
                      ("DEEPSEEK_API_KEY", "deepseek"),
                      ("MISTRAL_API_KEY", "mistral"),
                      ("XAI_API_KEY", "xai"),
                      ("CEREBRAS_API_KEY", "cerebras"),
                      ("OPENCODE_API_KEY", "opencode (zen)")):
        if os.environ.get(var):
            out.append((f"env:{var}", name))
    return out


def cmd_providers(args) -> int:
    lines: List[str] = []
    cfg = model_config.active()
    lines.append(f"velora config : "
                 f"{cfg['provider']}/{cfg['model']} -> {cfg['base_url']}"
                 if cfg else "velora config : none")
    for var, name in _env_keys():
        lines.append(f"env key       : {name} ({var})")
    try:
        setup = load_setup()
    except Exception:  # noqa: BLE001
        setup = None
    if setup:
        lines.append(f"opencode      : {setup.config_paths[0]}"
                     + (f" (+{len(setup.config_paths) - 1} more)"
                        if len(setup.config_paths) > 1 else ""))
        for prov in setup.providers.values():
            if prov.compatible:
                mark = "✓ chat" if prov.endpoint else "✓ (endpoint unknown)"
                key = "key ✓" if prov.api_key else ("oauth (not importable)"
                                                    if prov.oauth else "no key")
                lines.append(f"  {mark:<22} {prov.id:<20} {prov.endpoint or '':<38} {key}")
            else:
                lines.append(f"  {'✗ phase 2':<22} {prov.id:<20} "
                             f"{'native transport':<38} "
                             f"{'oauth' if prov.oauth else ''}")
        if setup.default_model:
            lines.append(f"  opencode default: "
                         f"{setup.default_provider}/{setup.default_model}")
        if not setup.providers:
            lines.append("  (no providers declared in config)")
    else:
        lines.append("opencode      : not configured")
    if args.format == "json":
        print(json.dumps({"providers": lines}, indent=2))
    else:
        print("Providers:")
        for ln in lines:
            print(f"  {ln}")
    return 0


def cmd_import_opencode(args) -> int:
    try:
        setup = load_setup()
    except Exception as exc:  # noqa: BLE001
        return _err(f"could not read opencode config: {exc}")
    if not setup or not setup.providers:
        return _err("no opencode configuration found "
                    "(~/.config/opencode/opencode.json or OPENCODE_CONFIG)")
    imported = sum(1 for p in setup.providers.values()
                   if p.compatible and p.api_key)
    for prov in setup.providers.values():
        if prov.compatible and prov.api_key:
            model_config.save_credential(prov.id, prov.api_key)
    pid, mid = setup.default_provider, setup.default_model
    prov = setup.providers.get(pid) if pid else None
    if prov is not None and mid and prov.compatible and prov.endpoint:
        key = prov.api_key or ("" if pid in _LOCAL_PROVIDERS else None)
        if key is None:
            key = _prompt_key(pid, args.no_prompt)
        if key is None:
            return _err(f"opencode default {pid}/{mid} has no importable key "
                        f"(oauth? pass --api-key)")
        model_config.save(pid, prov.endpoint, mid, source="opencode",
                          api_key=key)
        print(f"Imported opencode default: {pid}/{mid} -> {prov.endpoint} "
              f"({imported} provider keys imported)")
        return 0
    reason = "no default model in opencode config" if not mid else (
        "native transport (phase 2)" if prov is not None and not prov.compatible
        else "no endpoint / provider missing")
    print(f"Imported {imported} provider key(s); opencode default not "
          f"activatable: {reason}", file=sys.stderr)
    print("Pick a working model instead:", file=sys.stderr)
    print("  velora models list --free          # Zen free tier", file=sys.stderr)
    print("  velora models use zen/<id>", file=sys.stderr)
    return 1


# ---------------------------------------------------------------------------
# entry point
# ---------------------------------------------------------------------------

def cmd_models(args) -> int:
    action = getattr(args, "models_action", None) or "list"
    handlers = {
        "list": cmd_list, "use": cmd_use, "current": cmd_current,
        "providers": cmd_providers, "import-opencode": cmd_import_opencode,
    }
    handler = handlers.get(action)
    if handler is None:
        return _err(f"unknown action '{action}'")
    return handler(args)
