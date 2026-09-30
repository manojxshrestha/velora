"""Persistent Velora model selection + provider-fallback resolution.

`velora models use <id>` writes two files under ``~/.config/velora`` (override
with ``VELORA_CONFIG_HOME``):

* ``config.json``      -- non-secret: provider, base_url, model, source
* ``credentials.json`` -- API keys, chmod 0600 (keys copied per user choice so
  Velora works standalone of opencode)

``resolve_llm_settings()`` feeds ``LLMConfig.from_env`` when the documented
``VELORA_LLM_*`` env vars are incomplete:

    env (VELORA_LLM_*) > velora config.json > opencode auto-fallback > nothing

``VELORA_SKIP_PROVIDER_FALLBACK=1`` disables file/opencode fallback entirely
(used by the test-suite so a dev machine's real config can never leak in).
"""

from __future__ import annotations

import json
import os
import stat
import sys
from pathlib import Path
from typing import Dict, Optional


def config_home() -> Path:
    override = os.environ.get("VELORA_CONFIG_HOME")
    if override:
        return Path(override).expanduser()
    return Path.home() / ".config" / "velora"


def config_path() -> Path:
    return config_home() / "config.json"


def credentials_path() -> Path:
    return config_home() / "credentials.json"


def load() -> dict:
    try:
        data = json.loads(config_path().read_text())
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError):
        return {}


def get_credential(provider: str) -> str:
    if not provider:
        return ""
    try:
        creds = json.loads(credentials_path().read_text())
        if isinstance(creds, dict):
            return str(creds.get(provider) or "")
    except (OSError, ValueError):
        pass
    return ""


def save(provider: str, base_url: str, model: str, source: str = "velora-models",
         api_key: Optional[str] = None) -> Path:
    """Persist the active model (and key, if given) with a 0600 credentials file."""
    home = config_home()
    home.mkdir(parents=True, exist_ok=True)
    entry = {"provider": provider, "base_url": base_url.rstrip("/"),
             "model": model, "source": source}
    config_path().write_text(json.dumps(entry, indent=2) + "\n")
    if api_key:
        creds = {}
        try:
            existing = json.loads(credentials_path().read_text())
            if isinstance(existing, dict):
                creds = existing
        except (OSError, ValueError):
            pass
        creds[provider] = api_key
        cp = credentials_path()
        cp.write_text(json.dumps(creds, indent=2) + "\n")
        os.chmod(cp, stat.S_IRUSR | stat.S_IWUSR)   # 0600
    return config_path()


def save_credential(provider: str, api_key: str) -> None:
    """Write one provider key to credentials.json (0600), leaving config.json alone."""
    if not provider or not api_key:
        return
    home = config_home()
    home.mkdir(parents=True, exist_ok=True)
    creds = {}
    try:
        existing = json.loads(credentials_path().read_text())
        if isinstance(existing, dict):
            creds = existing
    except (OSError, ValueError):
        pass
    creds[provider] = api_key
    cp = credentials_path()
    cp.write_text(json.dumps(creds, indent=2) + "\n")
    os.chmod(cp, stat.S_IRUSR | stat.S_IWUSR)   # 0600


def active() -> Optional[dict]:
    cfg = load()
    if cfg.get("base_url") and cfg.get("model"):
        return cfg
    return None


def _fallback_active_model():
    """(provider, base_url, model, api_key, source) from velora config or opencode."""
    if os.environ.get("VELORA_SKIP_PROVIDER_FALLBACK"):
        return None
    cfg = active()
    if cfg:
        provider = str(cfg.get("provider") or "")
        return (provider, cfg["base_url"], cfg["model"],
                get_credential(provider),
                f"velora config ({config_path()})")
    # opencode auto-fallback: only complete, OpenAI-compatible providers.
    try:
        from velora.sil.opencode_bridge import load_setup
        setup = load_setup()
    except Exception:
        return None
    if not setup or not setup.default_model:
        return None
    prov = setup.providers.get(setup.default_provider)
    if prov is None or not prov.compatible or not prov.endpoint:
        return None
    key = prov.api_key or ""
    if not key and prov.id not in ("ollama", "lmstudio", "llama.cpp"):
        return None   # local servers need no key; hosted ones do
    return (prov.id, prov.endpoint, setup.default_model, key,
            f"opencode ({setup.config_paths[0]})")


def resolve_llm_settings() -> Dict[str, str]:
    """Fallback base_url/model/api_key when VELORA_LLM_* env vars are incomplete."""
    hit = _fallback_active_model()
    if not hit:
        return {}
    provider, base_url, model, api_key, source = hit
    return {"provider": provider, "base_url": base_url.rstrip("/"),
            "model": model, "api_key": api_key, "source": source}


_announced = False


def announce_fallback(source: str, model: str) -> None:
    """One-line stderr notice when config/opencode supplied the model."""
    global _announced
    if _announced:
        return
    _announced = True
    print(f"[velora] using model '{model}' from {source} "
          f"(VELORA_LLM_* env not set)", file=sys.stderr)
