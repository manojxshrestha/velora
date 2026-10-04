"""Read an existing OpenCode setup so Velora can reuse its providers and keys.

OpenCode stores provider configuration in ``opencode.json`` (global
``~/.config/opencode/`` + project root, JSONC, merged) and credentials in
``auth.json`` (``~/.local/share/opencode/auth.json``, written 0600). Documented
at https://opencode.ai/docs/config/ and /docs/providers/.

auth.json entries are ``{"type": "api", "key": ...}`` or
``{"type": "oauth", "access": ..., "refresh": ...}`` (verified against
opencode's ``packages/opencode/src/auth/index.ts``). OAuth tokens are surfaced
as *oauth-only* (no importable API key). ``OPENCODE_AUTH_CONTENT`` overrides
the on-disk file, matching opencode's own precedence.

Only OpenAI-compatible endpoints are usable by Velora's /chat/completions
client; providers that are native (anthropic, google, ...) are classified
``compatible=False`` and shown as phase-2 in `velora models`.
"""

from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional

from velora.sil.model_catalog import KNOWN_OPENAI_COMPATIBLE_PROVIDERS

# Fallback endpoints for well-known providers that omit baseURL from their
# opencode config (opencode hardcodes these internally).
DEFAULT_ENDPOINTS: Dict[str, str] = {
    "openai": "https://api.openai.com/v1",
    "openrouter": "https://openrouter.ai/api/v1",
    "groq": "https://api.groq.com/openai/v1",
    "deepseek": "https://api.deepseek.com/v1",
    "mistral": "https://api.mistral.ai/v1",
    "xai": "https://api.x.ai/v1",
    "cerebras": "https://api.cerebras.ai/v1",
    "together": "https://api.together.xyz/v1",
    "togetherai": "https://api.together.xyz/v1",
    "fireworksai": "https://api.fireworks.ai/inference/v1",
    "ollama": "http://localhost:11434/v1",
    "lmstudio": "http://localhost:1234/v1",
    "llama.cpp": "http://localhost:8080/v1",
    "opencode": "https://opencode.ai/zen/v1",
    "zai": "https://api.z.ai/api/paas/v4",
}

# Providers whose native API is NOT OpenAI-style, even with a baseURL set.
NATIVE_PROVIDERS = {
    "anthropic", "google", "gemini", "vertexai", "vertexai-google",
    "amazon-bedrock", "github-copilot", "gitlab", "azure", "azure-cognitive-services",
    "aws", "snowflake", "huggingface",
}


@dataclass
class ProviderCfg:
    id: str
    name: str = ""
    base_url: str = ""
    npm: str = ""
    models: Dict[str, str] = field(default_factory=dict)   # id -> display name
    api_key: Optional[str] = None
    oauth: bool = False

    @property
    def compatible(self) -> bool:
        """Does this provider speak OpenAI-style /chat/completions? (key-independent)"""
        if self.id in NATIVE_PROVIDERS:
            return False
        if self.id in KNOWN_OPENAI_COMPATIBLE_PROVIDERS:
            return True
        if self.npm in ("@ai-sdk/openai-compatible", "@ai-sdk/openai"):
            return True
        if self.npm:
            return False   # a native AI SDK package (anthropic, google, ...)
        return bool(self.endpoint)   # explicit baseURL of unknown family: usable

    @property
    def endpoint(self) -> str:
        return (self.base_url or DEFAULT_ENDPOINTS.get(self.id, "")).rstrip("/")


@dataclass
class OpencodeSetup:
    default_provider: str = ""
    default_model: str = ""
    providers: Dict[str, ProviderCfg] = field(default_factory=dict)
    config_paths: List[str] = field(default_factory=list)
    auth_path: str = ""

    def get(self, pid: str) -> Optional[ProviderCfg]:
        return self.providers.get(pid)


# ---------------------------------------------------------------------------
# JSONC parsing (comments + trailing commas, opencode configs are JSONC)
# ---------------------------------------------------------------------------

def strip_jsonc(text: str) -> str:
    out, i, n = [], 0, len(text)
    while i < n:
        ch = text[i]
        if ch in "\"'":
            quote = ch
            out.append(ch)
            i += 1
            while i < n:
                out.append(text[i])
                if text[i] == "\\" and i + 1 < n:
                    out.append(text[i + 1])
                    i += 2
                    continue
                if text[i] == quote:
                    i += 1
                    break
                i += 1
            continue
        if ch == "/" and i + 1 < n and text[i + 1] == "/":
            while i < n and text[i] != "\n":
                i += 1
            continue
        if ch == "/" and i + 1 < n and text[i + 1] == "*":
            i += 2
            while i + 1 < n and not (text[i] == "*" and text[i + 1] == "/"):
                i += 1
            i += 2
            continue
        out.append(ch)
        i += 1
    stripped = "".join(out)
    return re.sub(r",\s*([}\]])", r"\1", stripped)


_ENV_SUB = re.compile(r"\{env:([^}]+)\}")
_FILE_SUB = re.compile(r"\{file:([^}]+)\}")


def substitute(value: str, config_dir: Path) -> str:
    """Resolve opencode's {env:VAR} / {file:path} substitutions."""
    def env(m: re.Match) -> str:
        return os.environ.get(m.group(1), "")

    def file(m: re.Match) -> str:
        p = Path(m.group(1)).expanduser()
        if not p.is_absolute():
            p = config_dir / p
        try:
            return p.read_text().strip()
        except OSError:
            return ""

    value = _ENV_SUB.sub(env, value)
    return _FILE_SUB.sub(file, value)


# ---------------------------------------------------------------------------
# Discovery
# ---------------------------------------------------------------------------

def config_candidates(start: Optional[Path] = None) -> List[Path]:
    """OPENCODE_CONFIG, global config, then nearest project opencode.json[c]
    walking up from `start` (cwd by default) -- opencode's documented order.
    A set OPENCODE_CONFIG is authoritative (replaces the global config), which
    also gives tests a hermetic hook."""
    out: List[Path] = []
    env_cfg = os.environ.get("OPENCODE_CONFIG")
    if env_cfg:
        out.append(Path(env_cfg).expanduser())
    else:
        home = Path.home()
        for name in ("opencode.json", "opencode.jsonc"):
            p = home / ".config" / "opencode" / name
            if p.exists():
                out.append(p)
                break
    cur = (start or Path.cwd()).resolve()
    found: Optional[Path] = None
    for directory in [cur, *cur.parents]:
        for name in ("opencode.json", "opencode.jsonc"):
            p = directory / name
            if p.exists():
                found = p
                break
        if found:
            break
    if found:
        out.append(found)
    return out


def auth_path() -> Path:
    xdg = os.environ.get("XDG_DATA_HOME")
    base = Path(xdg).expanduser() if xdg else Path.home() / ".local" / "share"
    return base / "opencode" / "auth.json"


def _load_auth() -> Dict[str, dict]:
    raw = os.environ.get("OPENCODE_AUTH_CONTENT")
    if raw:
        try:
            parsed = json.loads(raw)
            if isinstance(parsed, dict):
                return parsed
        except ValueError:
            pass
    try:
        parsed = json.loads(auth_path().read_text())
        return parsed if isinstance(parsed, dict) else {}
    except (OSError, ValueError):
        return {}


def _api_key(entry: object) -> tuple:
    """-> (api_key or None, is_oauth)"""
    if not isinstance(entry, dict):
        return None, False
    if entry.get("type") == "api" and isinstance(entry.get("key"), str) and entry.get("key"):
        return entry["key"], False
    if entry.get("type") == "oauth":
        # OAuth bearer tokens expire and opencode refreshes them; we can't, so
        # surface the provider as oauth-only instead of importing a stale token.
        return None, True
    if isinstance(entry.get("key"), str) and entry.get("key"):   # shapeless legacy
        return entry["key"], False
    return None, False


def _read_jsonc(path: Path) -> Optional[dict]:
    try:
        text = path.read_text()
    except OSError:
        return None
    # OPENCODE_CONFIG may point at a missing file; treat as absent.
    if not path.exists():
        return None
    try:
        data = json.loads(strip_jsonc(text))
        return data if isinstance(data, dict) else None
    except ValueError:
        return None


def _models_dev_meta() -> dict:
    """models.dev provider metadata from velora's cache (never fetched).

    Reads the cache file directly so callers on the hot config path never hit
    the network; stale metadata is fine for npm/base-URL/model-name lookup.
    Returns {} on any failure.
    """
    try:
        from velora.sil.model_catalog import cache_dir
        raw = json.loads((cache_dir() / "models.dev.json").read_text())
        data = raw.get("data") if isinstance(raw, dict) else None
        return data if isinstance(data, dict) else {}
    except Exception:  # noqa: BLE001 -- metadata is best-effort
        return {}


def load_setup() -> Optional[OpencodeSetup]:
    """Merged opencode config + auth, or None when opencode isn't configured.

    Providers declared in ``opencode.json`` win; providers that only exist in
    ``auth.json`` (connected via opencode's ``/connect``) are merged in too,
    with npm/base URL/model names taken from velora's cached models.dev data
    so their keys become reusable by velora without copying them anywhere.
    """
    paths = [p for p in config_candidates() if p.exists()]
    merged: dict = {}
    used: List[str] = []
    for p in paths:
        data = _read_jsonc(p)
        if data is None:
            continue
        used.append(str(p))
        for key, val in data.items():
            if key == "provider" and isinstance(val, dict):
                merged.setdefault("provider", {}).update(val)
            else:
                merged[key] = val
    if not used:
        return None

    auth = _load_auth()
    setup = OpencodeSetup(default_provider="", default_model="",
                          config_paths=used, auth_path=str(auth_path()))
    for pid, pcfg in (merged.get("provider") or {}).items():
        if not isinstance(pcfg, dict):
            continue
        opts = pcfg.get("options") or {}
        base = opts.get("baseURL") or opts.get("base_url") or ""
        if isinstance(base, str) and base:
            base = substitute(base, Path(used[0]).parent)
        api_key = opts.get("apiKey") or opts.get("api_key")
        if isinstance(api_key, str) and api_key:
            api_key = substitute(api_key, Path(used[0]).parent) or None
            oauth = False
        else:
            api_key, oauth = _api_key(auth.get(pid))
        models = {}
        for mid, m in (pcfg.get("models") or {}).items():
            if isinstance(m, dict):
                models[mid] = str(m.get("name") or mid)
            else:
                models[mid] = str(mid)
        setup.providers[pid] = ProviderCfg(
            id=pid,
            name=str(pcfg.get("name") or pid),
            base_url=base,
            npm=str(pcfg.get("npm") or ""),
            models=models,
            api_key=api_key,
            oauth=oauth,
        )
    # auth-only providers: connected via /connect but never declared in config.
    meta: Optional[dict] = None
    for pid, entry in auth.items():
        if pid in setup.providers:
            continue                      # config-declared wins (key path above)
        key, oauth = _api_key(entry)
        if not key and not oauth:
            continue                      # unusable auth entry
        if meta is None:
            meta = _models_dev_meta()
        m = meta.get(pid) or {}
        api = m.get("api")
        base = api if isinstance(api, str) and api.startswith("http") else ""
        models = {}
        for mid, mdef in (m.get("models") or {}).items():
            name = mdef.get("name") if isinstance(mdef, dict) else None
            models[str(mid)] = str(name or mid)
        setup.providers[pid] = ProviderCfg(
            id=pid,
            name=str(m.get("name") or pid),
            base_url=base,
            npm=str(m.get("npm") or ""),
            models=models,
            api_key=key,
            oauth=oauth,
        )
    default = merged.get("model") or ""
    if isinstance(default, str) and "/" in default:
        setup.default_provider, setup.default_model = default.split("/", 1)
    elif isinstance(default, str) and default:
        setup.default_provider, setup.default_model = "", default
    return setup
