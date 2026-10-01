"""Tests for `velora doctor` -- diagnosis, exit codes, fix hints."""

import argparse
import json
import os
import sys

import pytest

from velora import bridge_cli, doctor_cli
from velora.doctor_cli import FAIL, OK, WARN, Check, cmd_doctor, run_checks


def _args(probe=False, fmt="text"):
    return argparse.Namespace(probe=probe, format=fmt)


class TestIndividualChecks:
    def test_platform_ok_on_posix(self):
        if bridge_cli.is_windows():
            pytest.skip("windows host")
        assert doctor_cli._check_platform().status == OK

    def test_windows_platform_fails(self, monkeypatch):
        monkeypatch.setattr(bridge_cli, "is_windows", lambda: True)
        check = doctor_cli._check_platform()
        assert check.status == FAIL
        assert "WSL" in check.fix

    def test_node_missing_fails(self, monkeypatch):
        monkeypatch.setattr(bridge_cli, "find_node", lambda: None)
        check = doctor_cli._check_node()
        assert check.status == FAIL
        assert "velora setup" in check.fix

    def test_node_too_old_fails(self, monkeypatch):
        monkeypatch.setattr(bridge_cli, "find_node", lambda: "/x/node")
        monkeypatch.setattr(bridge_cli, "tool_version", lambda p: "v16.20.0")
        check = doctor_cli._check_node()
        assert check.status == FAIL
        assert "v16.20.0" in check.detail

    def test_node_good(self, monkeypatch):
        monkeypatch.setattr(bridge_cli, "find_node", lambda: "/x/node")
        monkeypatch.setattr(bridge_cli, "tool_version", lambda p: "v22.23.3")
        check = doctor_cli._check_node()
        assert check.status == OK

    def test_opencode_missing_fails(self, monkeypatch):
        monkeypatch.setattr(bridge_cli, "find_opencode", lambda: None)
        check = doctor_cli._check_opencode()
        assert check.status == FAIL
        assert "velora setup" in check.fix

    def test_sources_missing_fails(self, monkeypatch, tmp_path):
        monkeypatch.setattr(bridge_cli, "bridge_sources_dir", lambda: tmp_path)
        check = doctor_cli._check_sources()
        assert check.status == FAIL
        assert "pip install" in check.fix

    def test_runtime_not_seeded_fails(self, monkeypatch, tmp_path):
        monkeypatch.setenv("VELORA_BRIDGE_HOME", str(tmp_path))
        check = doctor_cli._check_runtime()
        assert check.status == FAIL
        assert "velora setup" in check.fix


class TestModelCheck:
    def test_no_model_fails(self, monkeypatch):
        monkeypatch.delenv("VELORA_LLM_BASE_URL", raising=False)
        monkeypatch.delenv("VELORA_LLM_MODEL", raising=False)
        check = doctor_cli._check_model()
        assert check.status == FAIL
        assert "velora models tui" in check.fix

    def test_model_from_config(self, monkeypatch, tmp_path):
        from velora.sil import model_config
        monkeypatch.delenv("VELORA_LLM_BASE_URL", raising=False)
        monkeypatch.delenv("VELORA_LLM_MODEL", raising=False)
        model_config.save(provider="optiq", base_url="http://localhost:47317/v1",
                          model="qwen", source="local")
        check = doctor_cli._check_model()
        assert check.status == OK
        assert "optiq/qwen" in check.detail
        assert "http://localhost:47317/v1" in check.detail

    def test_env_overrides_config(self, monkeypatch):
        from velora.sil import model_config
        monkeypatch.setenv("VELORA_LLM_BASE_URL", "http://env:1/v1")
        monkeypatch.setenv("VELORA_LLM_MODEL", "env-model")
        model_config.save(provider="optiq", base_url="http://cfg:2/v1",
                          model="cfg-model", source="local")
        check = doctor_cli._check_model()
        assert check.status == OK
        assert "http://env:1/v1" in check.detail
        assert "env-model" in check.detail

    def test_partial_env_merges_config_model(self, monkeypatch):
        from velora.sil import model_config
        monkeypatch.setenv("VELORA_LLM_BASE_URL", "http://env:1/v1")
        monkeypatch.delenv("VELORA_LLM_MODEL", raising=False)
        model_config.save(provider="optiq", base_url="http://cfg:2/v1",
                          model="cfg-model", source="local")
        check = doctor_cli._check_model()
        assert check.status == OK
        assert "http://env:1/v1" in check.detail
        assert "cfg-model" in check.detail


class TestBridgeChecks:
    def test_bridge_down_is_advisory(self, monkeypatch):
        monkeypatch.setattr(bridge_cli, "bridge_health",
                            lambda port=0, timeout=0: False)
        monkeypatch.setattr(bridge_cli, "_read_state", lambda: None)
        monkeypatch.setattr(bridge_cli, "_port_busy", lambda p: False)
        check = doctor_cli._check_bridge()
        assert check.status == WARN
        assert "--start" in check.fix

    def test_bridge_unhealthy_pid_fails(self, monkeypatch):
        monkeypatch.setattr(bridge_cli, "bridge_health",
                            lambda port=0, timeout=0: False)
        monkeypatch.setattr(bridge_cli, "_read_state",
                            lambda: {"pid": os.getpid()})
        check = doctor_cli._check_bridge()
        assert check.status == FAIL
        assert "--stop" in check.fix

    def test_bridge_healthy(self, monkeypatch):
        monkeypatch.setattr(bridge_cli, "bridge_health",
                            lambda port=0, timeout=0: True)
        monkeypatch.setattr(bridge_cli, "_read_state", lambda: {"pid": 1})
        check = doctor_cli._check_bridge()
        assert check.status == OK

    def test_bridge_required_down_fails(self, monkeypatch):
        from velora.sil import model_config
        monkeypatch.delenv("VELORA_LLM_BASE_URL", raising=False)
        monkeypatch.delenv("VELORA_LLM_MODEL", raising=False)
        model_config.save(provider="opencode-bridge",
                          base_url=bridge_cli.DEFAULT_BASE_URL,
                          model="opencode/mimo-v2.6-flash-free",
                          source="opencode-bridge")
        monkeypatch.setattr(bridge_cli, "bridge_health",
                            lambda port=0, timeout=0: False)
        check = doctor_cli._check_bridge_required()
        assert check.status == FAIL
        assert "--start" in check.fix

    def test_bridge_not_required_for_local_model(self, monkeypatch):
        from velora.sil import model_config
        monkeypatch.delenv("VELORA_LLM_BASE_URL", raising=False)
        monkeypatch.delenv("VELORA_LLM_MODEL", raising=False)
        model_config.save(provider="optiq", base_url="http://localhost:47317/v1",
                          model="qwen", source="local")
        check = doctor_cli._check_bridge_required()
        assert check.status == WARN
        assert check.fix == ""

    def test_probe_skipped_when_bridge_down(self, monkeypatch):
        monkeypatch.setattr(bridge_cli, "bridge_health",
                            lambda port=0, timeout=0: False)
        check = doctor_cli._check_probe()
        assert check.status == WARN
        assert "skipped" in check.detail


class TestCmdDoctor:
    def test_ready_exits_zero(self, monkeypatch, capsys):
        monkeypatch.setattr(doctor_cli, "run_checks",
                            lambda probe=False: [Check("node", OK, "fine")])
        assert cmd_doctor(_args()) == 0
        out = capsys.readouterr().out
        assert "ready for zero-key" in out

    def test_failure_exits_one_with_fix(self, monkeypatch, capsys):
        monkeypatch.setattr(doctor_cli, "run_checks",
                            lambda probe=False: [
                                Check("node", FAIL, "missing", "velora setup")])
        assert cmd_doctor(_args()) == 1
        out = capsys.readouterr().out
        assert "velora setup" in out
        assert "1 problem" in out

    def test_json_format(self, monkeypatch, capsys):
        monkeypatch.setattr(doctor_cli, "run_checks",
                            lambda probe=False: [Check("node", FAIL, "x", "fix")])
        assert cmd_doctor(_args(fmt="json")) == 1
        data = json.loads(capsys.readouterr().out)
        assert data["ready"] is False
        assert data["checks"][0]["id"] == "node"
        assert data["checks"][0]["fix"] == "fix"

    def test_probe_flag_forwarded(self, monkeypatch, capsys):
        seen = {}

        def fake(probe=False):
            seen["probe"] = probe
            return [Check("node", OK, "fine")]

        monkeypatch.setattr(doctor_cli, "run_checks", fake)
        assert cmd_doctor(_args(probe=True)) == 0
        assert seen["probe"] is True

    def test_run_checks_covers_expected_ids(self, monkeypatch, tmp_path):
        monkeypatch.setenv("VELORA_BRIDGE_HOME", str(tmp_path / "bridge"))
        monkeypatch.setenv("VELORA_STATE_HOME", str(tmp_path / "state"))
        ids = [c.id for c in run_checks(probe=False)]
        for expected in ("platform", "python", "node", "opencode",
                         "bridge-sources", "bridge-runtime", "bridge",
                         "model", "bridge-required", "endpoints"):
            assert expected in ids
        assert "probe" not in ids
