"""Tests for `velora models`: catalogs, opencode bridge, config, precedence, CLI."""

import json
import os
import stat
import time
import urllib.error
from pathlib import Path

import pytest

from velora.cli import main
from velora.sil import model_config
from velora.sil.llm_client import LLMConfig
from velora.sil.model_catalog import (
    CatalogError, load_models_dev, registry_models, registry_stats, zen_models,
)
from velora.sil.opencode_bridge import (
    DEFAULT_ENDPOINTS, load_setup, strip_jsonc, substitute,
)

# ---------------------------------------------------------------------------
# Zen catalog (static, offline)
# ---------------------------------------------------------------------------

def test_zen_catalog_static_table_sanitized():
    rows = zen_models()
    assert len(rows) >= 80
    ids = [r.id for r in rows]
    assert len(ids) == len(set(ids))
    assert "glm-5.2" in ids and "mimo-v2.6-flash-free" in ids
    for r in rows:
        assert r.transport in ("chat", "responses", "anthropic", "google", "systemone")
        assert r.ready == (r.transport == "chat")
        if r.free:
            assert r.price_in is None and r.price_out is None
        if not r.ready:
            assert "phase 2" in r.note
    glm = next(r for r in rows if r.id == "glm-5.2")
    assert (glm.price_in, glm.price_out) == (1.4, 4.4)
    assert glm.ready and not glm.free


def test_zen_refresh_validates_against_live_listing(monkeypatch):
    payload = json.dumps({
        "data": [{"id": "glm-5.2"}, {"id": "big-pickle"},
                 {"id": "brand-new-free"}]
    }).encode()
    monkeypatch.setattr("velora.sil.model_catalog._http_get",
                        lambda *a, **k: payload)
    rows = zen_models(refresh=True)
    by_id = {r.id: r for r in rows}
    assert "brand-new-free" in by_id            # new id appended
    assert by_id["brand-new-free"].free         # free by naming convention
    assert "may be retired" in by_id["jev-1.13"].note  # missing from live
    assert not by_id["glm-5.2"].note


# ---------------------------------------------------------------------------
# models.dev registry (offline via cache fixture)
# ---------------------------------------------------------------------------

MINI_REGISTRY = {
    "groq": {"id": "groq", "npm": "@ai-sdk/openai-compatible",
             "env": ["GROQ_API_KEY"],
             "models": {"llama-3.3-70b": {"name": "Llama 3.3 70B",
                                          "tool_call": True,
                                          "cost": {"input": 0, "output": 0},
                                          "limit": {"context": 128000}}}},
    "anthropic": {"id": "anthropic", "npm": "@ai-sdk/anthropic",
                  "env": ["ANTHROPIC_API_KEY"],
                  "models": {"claude-sonnet": {"name": "Claude Sonnet",
                                               "cost": {"input": 3, "output": 15},
                                               "limit": {"context": 200000}}}},
    "weirdprov": {"id": "weirdprov", "npm": "@ai-sdk/other",
                  "env": ["W_KEY"],
                  "models": {"m1": {"name": "M1",
                                    "cost": {"input": 1, "output": 2}}}},
}


def _write_registry_cache(monkeypatch, data=None, age=0.0):
    cache = Path(os.environ["VELORA_CACHE_HOME"])
    cache.mkdir(parents=True, exist_ok=True)
    (cache / "models.dev.json").write_text(json.dumps({
        "fetched_at": time.time() - age,
        "data": data if data is not None else MINI_REGISTRY,
    }))


def test_registry_free_filter_ready_and_notes(monkeypatch):
    _write_registry_cache(monkeypatch)
    free = registry_models(free_only=True)
    assert [m.id for m in free] == ["llama-3.3-70b"]
    assert free[0].ready and free[0].free and free[0].source == "registry"
    everything = registry_models()
    by_id = {m.id: m for m in everything}
    assert not by_id["claude-sonnet"].ready          # native npm -> phase 2
    assert not by_id["m1"].ready                     # unknown endpoint
    assert by_id["m1"].note == "endpoint unverified"
    assert everything[0].free                        # free rows sort first


def test_registry_query_and_limit(monkeypatch):
    _write_registry_cache(monkeypatch)
    assert [m.id for m in registry_models(query="llama")] == ["llama-3.3-70b"]
    assert len(registry_models(limit=1)) == 1
    assert registry_models(provider="groq")
    assert not registry_models(provider="nope")


def test_registry_stats_from_cache(monkeypatch):
    _write_registry_cache(monkeypatch)
    stats = registry_stats()
    assert stats == {"providers": 3, "models": 3, "free": 1}


def test_registry_offline_without_cache_raises(monkeypatch):
    def _boom(*a, **k):
        raise urllib.error.URLError("offline")
    monkeypatch.setattr("velora.sil.model_catalog._http_get", _boom)
    with pytest.raises(CatalogError):
        load_models_dev()


def test_registry_stale_cache_survives_offline(monkeypatch):
    _write_registry_cache(monkeypatch, age=25 * 3600)   # past the 24h TTL
    calls = {"n": 0}

    def _boom(*a, **k):
        calls["n"] += 1
        raise urllib.error.URLError("offline")
    monkeypatch.setattr("velora.sil.model_catalog._http_get", _boom)
    data = load_models_dev()
    assert calls["n"] == 1 and "groq" in data           # refetched once, fell back


# ---------------------------------------------------------------------------
# opencode bridge
# ---------------------------------------------------------------------------

OPencode_CONFIG = """
{
  // global config with comments + trailing commas
  "model": "openrouter/qwen/qwen3-coder",
  "provider": {
    "openrouter": {
      "npm": "@ai-sdk/openai-compatible",
      "options": {"baseURL": "https://openrouter.ai/api/v1"},
      "models": {"qwen/qwen3-coder": {"name": "Qwen3 Coder"}},
    },
    "ollama": {
      "options": {},
      "models": {"llama3": {}},
    },
    "anthropic": {
      "npm": "@ai-sdk/anthropic",
      "models": {"claude-sonnet": {}},
    },
  },
}
"""

OPencode_AUTH = {
    "openrouter": {"type": "api", "key": "sk-or-123"},
    "anthropic": {"type": "oauth", "access": "x", "refresh": "y"},
}


def _write_opencode(tmp_path, config_text=OPencode_CONFIG, auth=None):
    cfg = tmp_path / "opencode.jsonc"
    cfg.write_text(config_text)
    os.environ["OPENCODE_CONFIG"] = str(cfg)
    auth_dir = Path(os.environ["XDG_DATA_HOME"]) / "opencode"
    auth_dir.mkdir(parents=True, exist_ok=True)
    (auth_dir / "auth.json").write_text(json.dumps(
        OPencode_AUTH if auth is None else auth))
    return cfg


def test_strip_jsonc_comments_and_trailing_commas():
    text = '{\n  // line comment\n  "a": "http://x//keep", /* block */ "b": 1,\n}'
    parsed = json.loads(strip_jsonc(text))
    assert parsed == {"a": "http://x//keep", "b": 1}


def test_substitute_env_and_file():
    cfg_dir = Path(os.environ["VELORA_CONFIG_HOME"])
    cfg_dir.mkdir(parents=True, exist_ok=True)
    (cfg_dir / "secret.txt").write_text("  tok-42 \n")
    os.environ["MY_BASE"] = "https://example.test/v1"
    try:
        assert substitute("{env:MY_BASE}", cfg_dir) == "https://example.test/v1"
        assert substitute("{file:secret.txt}", cfg_dir) == "tok-42"
        assert substitute("{file:/nonexistent}", cfg_dir) == ""
        assert substitute("{env:NOPE_VAR}", cfg_dir) == ""
    finally:
        del os.environ["MY_BASE"]


def test_load_setup_parses_default_and_compatibility(tmp_path, monkeypatch):
    _write_opencode(tmp_path)
    setup = load_setup()
    assert setup is not None
    assert setup.default_provider == "openrouter"
    assert setup.default_model == "qwen/qwen3-coder"      # split on first /
    orouter = setup.providers["openrouter"]
    assert orouter.compatible and orouter.api_key == "sk-or-123"
    assert orouter.endpoint == "https://openrouter.ai/api/v1"
    ollama = setup.providers["ollama"]
    assert ollama.compatible and ollama.api_key is None
    assert ollama.endpoint == DEFAULT_ENDPOINTS["ollama"]
    anthropic = setup.providers["anthropic"]
    assert not anthropic.compatible and anthropic.oauth
    assert anthropic.api_key is None


def test_load_setup_auth_env_content_overrides_file(tmp_path, monkeypatch):
    _write_opencode(tmp_path)
    monkeypatch.setenv("OPENCODE_AUTH_CONTENT", json.dumps(
        {"openrouter": {"type": "api", "key": "sk-from-env"}}))
    setup = load_setup()
    assert setup.providers["openrouter"].api_key == "sk-from-env"


def test_load_setup_env_substitution_in_base_url(tmp_path, monkeypatch):
    _write_opencode(tmp_path, config_text=json.dumps({
        "model": "custom/m",
        "provider": {"custom": {
            "options": {"baseURL": "{env:MY_CUSTOM_BASE}"},
            "models": {"m": {}}}},
    }))
    monkeypatch.setenv("MY_CUSTOM_BASE", "https://custom.test/v1")
    setup = load_setup()
    assert setup.providers["custom"].endpoint == "https://custom.test/v1"
    assert setup.providers["custom"].compatible     # explicit baseURL, no npm


def test_load_setup_none_when_opencode_absent():
    assert load_setup() is None      # OPENCODE_CONFIG points at a missing file


# ---------------------------------------------------------------------------
# velora config persistence
# ---------------------------------------------------------------------------

def test_save_and_load_roundtrip_with_0600_credentials():
    model_config.save("zen", "https://opencode.ai/zen/v1/", "glm-5.2",
                      api_key="sk-test")
    cfg = model_config.active()
    assert cfg["provider"] == "zen" and cfg["model"] == "glm-5.2"
    assert cfg["base_url"] == "https://opencode.ai/zen/v1"   # trailing / stripped
    assert model_config.get_credential("zen") == "sk-test"
    mode = stat.S_IMODE(os.stat(model_config.credentials_path()).st_mode)
    assert mode == 0o600


def test_broken_config_files_degrade_to_empty():
    model_config.config_home().mkdir(parents=True, exist_ok=True)
    model_config.config_path().write_text("{not json")
    model_config.credentials_path().write_text("also not json")
    assert model_config.load() == {} and model_config.active() is None
    assert model_config.get_credential("zen") == ""


def test_resolve_prefers_velora_config_over_opencode(tmp_path, monkeypatch):
    _write_opencode(tmp_path)
    model_config.save("zen", "https://opencode.ai/zen/v1", "glm-5.2",
                      api_key="cfg-key")
    monkeypatch.delenv("VELORA_SKIP_PROVIDER_FALLBACK")
    hit = model_config.resolve_llm_settings()
    assert hit["source"].startswith("velora config")
    assert hit["model"] == "glm-5.2" and hit["api_key"] == "cfg-key"


def test_resolve_opencode_fallback_when_no_velora_config(tmp_path, monkeypatch):
    _write_opencode(tmp_path)
    monkeypatch.delenv("VELORA_SKIP_PROVIDER_FALLBACK")
    hit = model_config.resolve_llm_settings()
    assert hit["source"].startswith("opencode")
    assert hit["provider"] == "openrouter"
    assert hit["base_url"] == "https://openrouter.ai/api/v1"
    assert hit["model"] == "qwen/qwen3-coder"
    assert hit["api_key"] == "sk-or-123"


def test_resolve_blocked_by_skip_env_and_incomplete_opencode(tmp_path, monkeypatch):
    _write_opencode(tmp_path)
    # conftest sets VELORA_SKIP_PROVIDER_FALLBACK=1 -> no fallback at all
    assert model_config.resolve_llm_settings() == {}
    # phase-2-only default (anthropic oauth) -> not resolvable either
    monkeypatch.delenv("VELORA_SKIP_PROVIDER_FALLBACK")
    _write_opencode(tmp_path, config_text=json.dumps(
        {"model": "anthropic/claude-sonnet",
         "provider": {"anthropic": {"npm": "@ai-sdk/anthropic",
                                    "models": {"claude-sonnet": {}}}}}))
    assert model_config.resolve_llm_settings() == {}


# ---------------------------------------------------------------------------
# LLMConfig.from_env precedence
# ---------------------------------------------------------------------------

def test_from_env_env_beats_config(capsys):
    model_config.save("zen", "https://opencode.ai/zen/v1", "glm-5.2",
                      api_key="cfg-key")
    os.environ["VELORA_LLM_BASE_URL"] = "http://env.test/v1"
    os.environ["VELORA_LLM_MODEL"] = "env-model"
    try:
        cfg = LLMConfig.from_env()
    finally:
        del os.environ["VELORA_LLM_BASE_URL"]
        del os.environ["VELORA_LLM_MODEL"]
    assert cfg.base_url == "http://env.test/v1" and cfg.model == "env-model"
    assert cfg.enabled and cfg.api_key == "sk-local"   # no env key, no fallback
    assert "using model" not in capsys.readouterr().err   # env complete -> silent


def test_from_env_fills_from_velora_config_and_announces(monkeypatch, capsys):
    monkeypatch.delenv("VELORA_SKIP_PROVIDER_FALLBACK")
    model_config.save("zen", "https://opencode.ai/zen/v1", "glm-5.2",
                      api_key="cfg-key")
    cfg = LLMConfig.from_env()
    assert cfg.enabled and cfg.base_url == "https://opencode.ai/zen/v1"
    assert cfg.model == "glm-5.2" and cfg.api_key == "cfg-key"
    err = capsys.readouterr().err
    assert "using model 'glm-5.2'" in err and "velora config" in err


def test_from_env_falls_back_to_opencode(tmp_path, monkeypatch):
    monkeypatch.delenv("VELORA_SKIP_PROVIDER_FALLBACK")
    _write_opencode(tmp_path)
    cfg = LLMConfig.from_env()
    assert cfg.enabled
    assert cfg.base_url == "https://openrouter.ai/api/v1"
    assert cfg.model == "qwen/qwen3-coder" and cfg.api_key == "sk-or-123"


def test_from_env_unchanged_when_nothing_configured():
    cfg = LLMConfig.from_env()      # conftest: SKIP on, no env, no config
    assert cfg.base_url == "" and cfg.model == ""
    assert not cfg.enabled and cfg.api_key == "sk-local"


# ---------------------------------------------------------------------------
# CLI: list / use / current / providers / import-opencode
# ---------------------------------------------------------------------------

def test_cli_list_default_and_free_json(capsys):
    assert main(["models"]) == 0
    out = capsys.readouterr().out
    assert "OpenCode Zen models" in out and "glm-5.2" in out
    assert main(["models", "list", "--free", "--format", "json"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["models"] and all(m["free"] for m in payload["models"])


def test_cli_list_query_filters(capsys):
    assert main(["models", "list", "--query", "glm"]) == 0
    out = capsys.readouterr().out
    assert "glm-5.2" in out and "kimi" not in out


def test_cli_list_registry_offline(monkeypatch, capsys):
    _write_registry_cache(monkeypatch)
    assert main(["models", "list", "--registry"]) == 0
    out = capsys.readouterr().out
    assert "models.dev registry" in out and "llama-3.3-70b" in out


def test_cli_use_zen_and_current(monkeypatch, capsys):
    monkeypatch.setenv("OPENCODE_API_KEY", "zk-1")
    assert main(["models", "use", "zen/glm-5.2"]) == 0
    out = capsys.readouterr().out
    assert "Active model set: zen/glm-5.2 -> https://opencode.ai/zen/v1" in out
    assert main(["models", "current"]) == 0
    assert "zen/glm-5.2" in capsys.readouterr().out
    assert model_config.get_credential("zen") == "zk-1"
    assert stat.S_IMODE(os.stat(model_config.credentials_path()).st_mode) == 0o600


def test_cli_use_bare_id_shorthand(capsys):
    assert main(["models", "use", "mimo-v2.6-flash-free",
                 "--api-key", "k", "--no-prompt"]) == 0
    assert model_config.active()["model"] == "mimo-v2.6-flash-free"


def test_cli_use_unknown_and_phase2_fail(capsys):
    assert main(["models", "use", "no-such-model"]) == 1
    assert "not in the Zen catalog" in capsys.readouterr().err
    assert main(["models", "use", "zen/claude-opus-5", "--api-key", "k"]) == 1
    assert "phase 2" in capsys.readouterr().err


def test_cli_use_opencode_ref(tmp_path, capsys):
    _write_opencode(tmp_path)
    assert main(["models", "use", "opencode/openrouter/qwen/qwen3-coder",
                 "--no-prompt"]) == 0
    cfg = model_config.active()
    assert cfg["provider"] == "openrouter"
    assert cfg["model"] == "qwen/qwen3-coder"
    assert cfg["base_url"] == "https://openrouter.ai/api/v1"
    assert model_config.get_credential("openrouter") == "sk-or-123"


def test_cli_use_generic_with_base_url_and_local_provider(capsys):
    assert main(["models", "use", "myprov/mymodel",
                 "--base-url", "http://localhost:9999/v1",
                 "--api-key", "k"]) == 0
    assert model_config.active()["base_url"] == "http://localhost:9999/v1"
    assert main(["models", "use", "weird/m"]) == 1
    assert "--base-url" in capsys.readouterr().err
    # local servers need no key -> sk-local, never prompts (stdin not a tty)
    assert main(["models", "use", "ollama/llama3"]) == 0
    assert model_config.get_credential("ollama") == "sk-local"


def test_cli_use_zen_without_key_non_tty_fails(capsys):
    assert main(["models", "use", "zen/glm-5.2", "--no-prompt"]) == 1
    assert "API key" in capsys.readouterr().err


def test_cli_providers_shows_compat_marks(tmp_path, capsys):
    _write_opencode(tmp_path)
    model_config.save("zen", "https://opencode.ai/zen/v1", "glm-5.2",
                      api_key="zk")
    os.environ["GROQ_API_KEY"] = "gk"
    try:
        assert main(["models", "providers"]) == 0
    finally:
        del os.environ["GROQ_API_KEY"]
    out = capsys.readouterr().out
    assert "zen/glm-5.2" in out
    assert "env:GROQ_API_KEY" in out
    assert "openrouter" in out and "✓" in out
    assert "anthropic" in out and "✗ phase 2" in out


def test_cli_import_opencode_happy_path(tmp_path, capsys):
    _write_opencode(tmp_path)
    assert main(["models", "import-opencode", "--no-prompt"]) == 0
    cfg = model_config.active()
    assert cfg["provider"] == "openrouter" and cfg["model"] == "qwen/qwen3-coder"
    assert "Imported opencode default" in capsys.readouterr().out


def test_cli_import_opencode_unusable_default_still_imports_keys(tmp_path, capsys):
    _write_opencode(tmp_path, config_text=json.dumps({
        "model": "anthropic/claude-sonnet",
        "provider": {
            "anthropic": {"npm": "@ai-sdk/anthropic",
                          "models": {"claude-sonnet": {}}},
            "openrouter": {"npm": "@ai-sdk/openai-compatible",
                           "options": {"baseURL": "https://openrouter.ai/api/v1"},
                           "models": {"m": {}}},
        }}))
    assert main(["models", "import-opencode", "--no-prompt"]) == 1
    err = capsys.readouterr().err
    assert "phase 2" in err and "velora models list --free" in err
    assert model_config.active() is None                       # nothing activated
    assert model_config.get_credential("openrouter") == "sk-or-123"


def test_cli_import_opencode_absent_fails(capsys):
    assert main(["models", "import-opencode"]) == 1
    assert "no opencode configuration" in capsys.readouterr().err


# ---------------------------------------------------------------------------
# auth-only providers (/connect) + key reuse (Phase 1: paid models)
# ---------------------------------------------------------------------------

def _write_models_dev(tmp_path, data):
    cache = tmp_path / "cache"
    cache.mkdir(parents=True, exist_ok=True)
    (cache / "models.dev.json").write_text(
        json.dumps({"fetched_at": time.time(), "data": data}))


def test_load_setup_merges_auth_only_provider(tmp_path):
    _write_opencode(tmp_path, config_text="{}",
                    auth={"google": {"type": "api", "key": "AIza-test"}})
    _write_models_dev(tmp_path, {"google": {
        "name": "Google", "npm": "@ai-sdk/google",
        "models": {"gemini-flash-latest": {"name": "Gemini Flash Latest"}}}})
    setup = load_setup()
    assert setup is not None
    assert "google" in setup.providers          # /connect key, never declared
    g = setup.providers["google"]
    assert g.api_key == "AIza-test"
    assert not g.compatible                     # native AI SDK -> phase 2
    assert g.models == {"gemini-flash-latest": "Gemini Flash Latest"}


def test_load_setup_config_declared_not_overwritten_by_models_dev(tmp_path):
    _write_opencode(tmp_path)                   # openrouter declared in config
    _write_models_dev(tmp_path, {"openrouter": {
        "npm": "@ai-sdk/google", "models": {"nope": {"name": "Nope"}}}})
    setup = load_setup()
    orouter = setup.providers["openrouter"]
    assert list(orouter.models) == ["qwen/qwen3-coder"]   # config wins
    assert orouter.npm == "@ai-sdk/openai-compatible"


def test_provider_reuse_key_order_and_keyless(tmp_path, monkeypatch):
    from velora.sil.model_config import provider_reuse_key

    assert provider_reuse_key("") == ""
    assert provider_reuse_key("ollama") == ""            # keyless local
    # velora credentials win over everything below
    model_config.save("openrouter", "https://openrouter.ai/api/v1", "m")
    model_config.save_credential("openrouter", "sk-velora")
    assert provider_reuse_key("openrouter") == "sk-velora"
    # env for zen
    monkeypatch.setenv("OPENCODE_API_KEY", "sk-zen-env")
    assert provider_reuse_key("zen") == "sk-zen-env"
    monkeypatch.delenv("OPENCODE_API_KEY")
    # opencode auth store when velora has nothing for the provider
    _write_opencode(tmp_path, config_text="{}")
    monkeypatch.setenv("OPENCODE_AUTH_CONTENT", json.dumps(
        {"groq": {"type": "api", "key": "sk-groq-auth"}}))
    assert provider_reuse_key("groq") == "sk-groq-auth"
    # zen accepts the opencode provider id too
    monkeypatch.setenv("OPENCODE_AUTH_CONTENT", json.dumps(
        {"opencode": {"type": "api", "key": "sk-zen-connect"}}))
    assert provider_reuse_key("zen") == "sk-zen-connect"


def test_resolve_reuses_opencode_key_when_velora_config_has_none(tmp_path,
                                                                 monkeypatch):
    monkeypatch.delenv("VELORA_SKIP_PROVIDER_FALLBACK")
    _write_opencode(tmp_path, config_text="{}",
                    auth={"groq": {"type": "api", "key": "sk-groq"}})
    model_config.save("groq", "https://api.groq.com/openai/v1", "llama-3.3-70b")
    hit = model_config.resolve_llm_settings()
    assert hit["api_key"] == "sk-groq"                   # reused, not copied
    assert hit["source"].startswith("velora config")
    assert "reused" in hit["source"]


def test_resolve_velora_key_still_wins_over_reuse(tmp_path, monkeypatch):
    monkeypatch.delenv("VELORA_SKIP_PROVIDER_FALLBACK")
    _write_opencode(tmp_path, config_text="{}",
                    auth={"groq": {"type": "api", "key": "sk-groq"}})
    model_config.save("groq", "https://api.groq.com/openai/v1", "llama-3.3-70b",
                      api_key="sk-velora")
    hit = model_config.resolve_llm_settings()
    assert hit["api_key"] == "sk-velora"
    assert "reused" not in hit["source"]
