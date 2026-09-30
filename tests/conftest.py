"""Shared fixtures: isolate model-provider state for every test.

A developer machine's real ``~/.config/velora``, ``~/.config/opencode``,
``~/.local/share/opencode/auth.json`` or ``VELORA_LLM_*`` env must never leak
into a test run. Each test gets:

* ``VELORA_CONFIG_HOME`` / ``VELORA_CACHE_HOME`` / ``XDG_DATA_HOME`` -> tmp dirs
* ``OPENCODE_CONFIG`` -> a nonexistent path (bridge finds no setup; the real
  global config is skipped because a set OPENCODE_CONFIG is authoritative)
* ``VELORA_SKIP_PROVIDER_FALLBACK=1`` -> opencode/config fallback disabled
  (tests that exercise fallback re-enable it with
  ``monkeypatch.delenv("VELORA_SKIP_PROVIDER_FALLBACK")``)
* LLM env vars cleared; the once-per-process fallback announcement reset
"""

import pytest

_LLM_ENV = (
    "VELORA_LLM_BASE_URL", "VELORA_LLM_MODEL", "VELORA_LLM_API_KEY",
    "FRAME_LLM_BASE_URL", "FRAME_LLM_MODEL", "FRAME_LLM_API_KEY",
    "OPENCODE_API_KEY", "OPENCODE_AUTH_CONTENT", "VELORA_SKIP_PROVIDER_FALLBACK",
)


@pytest.fixture(autouse=True)
def _isolate_provider_state(tmp_path, monkeypatch):
    from velora.sil import model_config

    for var in _LLM_ENV:
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setenv("VELORA_CONFIG_HOME", str(tmp_path / "velora-config"))
    monkeypatch.setenv("VELORA_CACHE_HOME", str(tmp_path / "cache"))
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "xdg"))
    monkeypatch.setenv("OPENCODE_CONFIG", str(tmp_path / "no-opencode.json"))
    monkeypatch.setenv("VELORA_SKIP_PROVIDER_FALLBACK", "1")
    model_config._announced = False
    yield
    model_config._announced = False
