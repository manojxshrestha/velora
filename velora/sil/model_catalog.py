"""Model catalogs: OpenCode Zen (curated, free + paid) and the models.dev registry.

Two sources feed `velora models`:

* **OpenCode Zen** -- a curated gateway (https://opencode.ai/zen/v1) with free
  and pay-as-you-go models. The static table in ``_zen_catalog`` carries id,
  transport and pricing; ``refresh`` validates ids against the public
  ``GET /v1/models`` listing (no key needed).
* **models.dev** -- the registry opencode itself uses: 225+ providers, ~8k
  models, per-token pricing (cost 0/0 = free). Fetched as one JSON blob and
  cached for 24h (it is ~5 MB).

Everything here is stdlib-only (urllib) and degrades gracefully offline: a
stale cache beats no catalog.
"""

from __future__ import annotations

import json
import os
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional

from velora.sil._zen_catalog import ZEN_BASE_URL, ZEN_MODELS

MODELS_DEV_URL = "https://models.dev/api.json"
ZEN_LIVE_URL = f"{ZEN_BASE_URL}/models"
CACHE_TTL_SECONDS = 24 * 3600
_HTTP_TIMEOUT = 30

# AI SDK packages / providers whose endpoints speak OpenAI-style
# /chat/completions (so Velora can call them directly).
OPENAI_COMPATIBLE_NPM = {"@ai-sdk/openai-compatible", "@ai-sdk/openai"}
KNOWN_OPENAI_COMPATIBLE_PROVIDERS = {
    "openai", "openrouter", "groq", "deepseek", "mistral", "xai", "cerebras",
    "together", "togetherai", "fireworksai", "moonshotai", "minimax", "zai",
    "siliconflow", "ollama", "lmstudio", "llama.cpp", "openai-gateway",
    "cloudflare-ai-gateway", "helicone", "vercel", "portkey",
}


class CatalogError(RuntimeError):
    """A catalog could not be fetched and no cached copy exists."""


@dataclass
class CatalogModel:
    provider: str
    id: str
    name: str
    transport: str = "chat"        # "chat" | "responses" | "anthropic" | "google" | "systemone" | npm id
    price_in: Optional[float] = None   # USD per 1M input tokens; None = free/unknown
    price_out: Optional[float] = None
    context: Optional[int] = None
    tool_call: Optional[bool] = None
    free: bool = False
    ready: bool = True             # usable by Velora's /chat/completions client
    source: str = "zen"            # "zen" | "registry"
    note: str = ""

    @property
    def key(self) -> str:
        return f"{self.provider}/{self.id}"

    @property
    def price_label(self) -> str:
        if self.free or (self.price_in is None and self.price_out is None):
            return "FREE"
        pin = "free" if self.price_in in (0, 0.0) else f"${self.price_in:g}"
        pout = "free" if self.price_out in (0, 0.0) else f"${self.price_out:g}"
        return f"{pin}/{pout}/1M"


def cache_dir() -> Path:
    override = os.environ.get("VELORA_CACHE_HOME")
    if override:
        return Path(override).expanduser()
    return Path.home() / ".cache" / "velora"


def _http_get(url: str, timeout: int = _HTTP_TIMEOUT) -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": "velora/0.1.0"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.read()


def _cache_read(name: str) -> Optional[dict]:
    path = cache_dir() / name
    try:
        return json.loads(path.read_text())
    except (OSError, ValueError):
        return None


def _cache_write(name: str, payload: dict) -> None:
    d = cache_dir()
    d.mkdir(parents=True, exist_ok=True)
    (d / name).write_text(json.dumps(payload))


# ---------------------------------------------------------------------------
# models.dev registry
# ---------------------------------------------------------------------------

def load_models_dev(refresh: bool = False) -> dict:
    """Return the raw models.dev provider->models mapping (cached, TTL 24h)."""
    cached = _cache_read("models.dev.json")
    now = time.time()
    if cached and not refresh and now - cached.get("fetched_at", 0) < CACHE_TTL_SECONDS:
        return cached["data"]
    try:
        raw = _http_get(MODELS_DEV_URL)
        data = json.loads(raw)
        _cache_write("models.dev.json", {"fetched_at": now, "data": data})
        return data
    except (urllib.error.URLError, OSError, ValueError) as exc:
        if cached and cached.get("data"):
            return cached["data"]  # stale beats nothing
        raise CatalogError(
            f"could not fetch https://models.dev ({exc}); no cached copy at "
            f"{cache_dir() / 'models.dev.json'}"
        ) from exc


def registry_models(refresh: bool = False, query: Optional[str] = None,
                    free_only: bool = False, provider: Optional[str] = None,
                    limit: Optional[int] = None) -> List[CatalogModel]:
    """Flatten models.dev into CatalogModel rows (free first, then price)."""
    data = load_models_dev(refresh=refresh)
    rows: List[CatalogModel] = []
    for prov_id, prov in data.items():
        if provider and provider != prov_id:
            continue
        npm = str(prov.get("npm") or "")
        compat = npm in OPENAI_COMPATIBLE_NPM or prov_id in KNOWN_OPENAI_COMPATIBLE_PROVIDERS
        endpoint = prov.get("api")
        has_endpoint = isinstance(endpoint, str) and endpoint.startswith("http")
        for mid, m in (prov.get("models") or {}).items():
            cost = m.get("cost") or {}
            pin = cost.get("input")
            pout = cost.get("output")
            is_free = pin == 0 and pout == 0
            if free_only and not is_free:
                continue
            name = str(m.get("name") or mid)
            if query:
                q = query.lower()
                if q not in mid.lower() and q not in name.lower() and q not in prov_id.lower():
                    continue
            limit_ctx = m.get("limit") or {}
            note = ""
            if not (compat or has_endpoint):
                note = "endpoint unverified"
            rows.append(CatalogModel(
                provider=prov_id, id=mid, name=name,
                transport=npm or "unknown",
                price_in=(pin if isinstance(pin, (int, float)) else None),
                price_out=(pout if isinstance(pout, (int, float)) else None),
                context=limit_ctx.get("context"),
                tool_call=m.get("tool_call"),
                free=is_free, ready=compat or has_endpoint,
                source="registry", note=note,
            ))
    rows.sort(key=lambda r: (not r.free, r.price_in if r.price_in is not None else 1e9,
                             r.provider, r.id))
    if limit is not None:
        rows = rows[:limit]
    return rows


def registry_stats() -> Dict[str, int]:
    data = load_models_dev()
    total = free = 0
    for prov in data.values():
        for m in (prov.get("models") or {}).values():
            total += 1
            cost = m.get("cost") or {}
            if cost.get("input") == 0 and cost.get("output") == 0:
                free += 1
    return {"providers": len(data), "models": total, "free": free}


# ---------------------------------------------------------------------------
# OpenCode Zen
# ---------------------------------------------------------------------------

def zen_models(refresh: bool = False) -> List[CatalogModel]:
    """Zen models from the static table, optionally validated against live ids."""
    rows = [
        CatalogModel(
            provider="zen", id=mid, name=name, transport=transport,
            price_in=pin, price_out=pout,
            free=(pin is None and pout is None),
            ready=(transport == "chat"),
            source="zen",
            note="" if transport == "chat" else f"phase 2: {transport} transport",
        )
        for mid, name, transport, pin, pout in ZEN_MODELS
    ]
    if refresh:
        try:
            live = {m.get("id") for m in json.loads(_http_get(ZEN_LIVE_URL)).get("data", [])}
        except (urllib.error.URLError, OSError, ValueError):
            live = None
        if live is not None:
            known = {r.id for r in rows}
            for mid in sorted(live - known):          # ids Zen added since our snapshot
                is_free = str(mid).endswith("-free")
                rows.append(CatalogModel(
                    provider="zen", id=str(mid), name=str(mid), transport="chat",
                    free=is_free, ready=True, source="zen",
                    note="new since snapshot -- transport unverified",
                ))
            for r in rows:
                if r.id not in live and "retired" not in r.note:
                    r.note = ((r.note + "; ") if r.note else "") + \
                        "may be retired (not in live listing)"
    rows.sort(key=lambda r: (not r.free, r.price_in if r.price_in is not None else 1e9, r.id))
    return rows


def zen_lookup(model_id: str) -> Optional[CatalogModel]:
    for row in zen_models():
        if row.id == model_id:
            return row
    return None
