"""Tests for `velora setup` -- consent, planning, idempotency, installers."""

import argparse
import platform as _platform
import sys

import pytest

from velora import bridge_cli, doctor_cli, setup_cli
from velora.doctor_cli import FAIL, OK, WARN, Check


def _args(yes=False, no_start=True, no_probe=True):
    return argparse.Namespace(yes=yes, no_start=no_start, no_probe=no_probe)


def _green_checks(model_status=FAIL):
    return [
        Check("platform", OK, "linux"),
        Check("python", OK, "z3 ok"),
        Check("node", OK, "/x/node (v22.0.0)"),
        Check("opencode", OK, "/x/opencode"),
        Check("bridge-sources", OK, "src"),
        Check("bridge-runtime", OK, "rt"),
        Check("bridge", WARN, "not running"),
        Check("model", model_status, "no active model", "velora models tui"),
        Check("bridge-required", WARN, "skipped"),
        Check("endpoints", OK, "bridge: down"),
    ]


class TestConsent:
    def test_assume_yes_skips_prompt(self):
        def explode(_):
            raise AssertionError("prompt must not be called")
        assert setup_cli._confirm(["install node"], True, input_fn=explode) is True

    def test_non_tty_refuses_without_yes(self, monkeypatch, capsys):
        fake = type("Stream", (), {"isatty": lambda self: False})()
        monkeypatch.setattr(sys, "stdin", fake)
        assert setup_cli._confirm(["install node"], False) is False
        assert "--yes" in capsys.readouterr().err

    def test_prompt_yes(self, monkeypatch):
        fake = type("Stream", (), {"isatty": lambda self: True})()
        monkeypatch.setattr(sys, "stdin", fake)
        assert setup_cli._confirm(["x"], False, input_fn=lambda _: "y") is True
        assert setup_cli._confirm(["x"], False, input_fn=lambda _: "n") is False


class TestCmdSetup:
    def test_all_green_no_prompt_no_actions(self, monkeypatch, capsys):
        monkeypatch.setattr(doctor_cli, "run_checks",
                            lambda probe=False: _green_checks())
        called = []

        def explode(*a, **k):
            called.append(True)
            raise AssertionError("no installs on a green system")

        monkeypatch.setattr(setup_cli, "install_node", explode)
        monkeypatch.setattr(setup_cli, "install_opencode", explode)
        monkeypatch.setattr(bridge_cli, "ensure_bridge", lambda *a, **k: None)
        assert setup_cli.cmd_setup(_args()) == 0
        out = capsys.readouterr().out
        assert "already present" in out
        assert "velora models tui" in out
        assert not called

    def test_node_gap_install_with_yes(self, monkeypatch, capsys):
        checks = _green_checks()
        checks[2] = Check("node", FAIL, "not found", "velora setup")
        monkeypatch.setattr(doctor_cli, "run_checks",
                            lambda probe=False: checks)
        installs = []
        monkeypatch.setattr(
            setup_cli, "install_node",
            lambda report=print: (installs.append("node"),
                                  (True, "Node v22 -> ~/.local"))[1])
        monkeypatch.setattr(bridge_cli, "ensure_bridge", lambda *a, **k: None)
        assert setup_cli.cmd_setup(_args(yes=True)) == 0
        out = capsys.readouterr().out
        assert "Node v22 -> ~/.local" in out
        assert installs == ["node"]

    def test_install_failure_aborts(self, monkeypatch, capsys):
        checks = _green_checks()
        checks[2] = Check("node", FAIL, "not found", "velora setup")
        monkeypatch.setattr(doctor_cli, "run_checks",
                            lambda probe=False: checks)
        monkeypatch.setattr(setup_cli, "install_node",
                            lambda report=print: (False, "download failed"))
        monkeypatch.setattr(bridge_cli, "ensure_bridge", lambda *a, **k: None)
        assert setup_cli.cmd_setup(_args(yes=True)) == 1
        assert "setup incomplete" in capsys.readouterr().out

    def test_manual_blocker_not_touched(self, monkeypatch, capsys):
        checks = _green_checks()
        checks[0] = Check("platform", FAIL, "native Windows", "use WSL")
        monkeypatch.setattr(doctor_cli, "run_checks",
                            lambda probe=False: checks)
        assert setup_cli.cmd_setup(_args(yes=True)) == 1
        out = capsys.readouterr().out
        assert "manual fix" in out
        assert "use WSL" in out

    def test_missing_model_is_next_step_not_blocker(self, monkeypatch, capsys):
        monkeypatch.setattr(doctor_cli, "run_checks",
                            lambda probe=False: _green_checks())
        monkeypatch.setattr(bridge_cli, "ensure_bridge", lambda *a, **k: None)
        assert setup_cli.cmd_setup(_args(yes=True)) == 0
        out = capsys.readouterr().out
        assert "velora models tui" in out

    def test_starts_bridge_and_probes_when_asked(self, monkeypatch, capsys):
        monkeypatch.setattr(doctor_cli, "run_checks",
                            lambda probe=False: _green_checks())
        monkeypatch.setattr(bridge_cli, "ensure_bridge", lambda *a, **k: None)
        started = {"n": 0}
        healthy = {"v": False}

        def fake_health(*a, **k):
            return healthy["v"]

        def fake_start(*a, **k):
            started["n"] += 1
            healthy["v"] = True
            return 0

        monkeypatch.setattr(bridge_cli, "bridge_health", fake_health)
        monkeypatch.setattr(bridge_cli, "start_bridge", fake_start)
        monkeypatch.setattr(doctor_cli, "probe_chat",
                            lambda *a, **k: (True, "keyless chat OK in 3s"))
        args = argparse.Namespace(yes=True, no_start=False, no_probe=False)
        assert setup_cli.cmd_setup(args) == 0
        out = capsys.readouterr().out
        assert started["n"] == 1
        assert "keyless chat OK" in out

    def test_probe_failure_still_exits_zero(self, monkeypatch, capsys):
        monkeypatch.setattr(doctor_cli, "run_checks",
                            lambda probe=False: _green_checks())
        monkeypatch.setattr(bridge_cli, "bridge_health",
                            lambda port=0, timeout=0: True)
        monkeypatch.setattr(doctor_cli, "probe_chat",
                            lambda *a, **k: (False, "keyless chat FAILED: 403"))
        args = argparse.Namespace(yes=True, no_start=True, no_probe=False)
        assert setup_cli.cmd_setup(args) == 0
        out = capsys.readouterr().out
        assert "keyless chat FAILED" in out
        assert "retry later" in out

    def test_windows_refused(self, monkeypatch, capsys):
        monkeypatch.setattr(bridge_cli, "is_windows", lambda: True)
        assert setup_cli.cmd_setup(_args(yes=True)) == 1
        assert "wsl --install" in capsys.readouterr().err


class TestInstallers:
    def test_node_asset_arch_matrix(self, monkeypatch):
        monkeypatch.setattr(setup_cli.sys, "platform", "linux")
        monkeypatch.setattr(_platform, "machine", lambda: "aarch64")
        assert setup_cli._node_asset() == \
            f"node-{setup_cli.NODE_VERSION}-linux-arm64.tar.xz"
        monkeypatch.setattr(_platform, "machine", lambda: "x86_64")
        assert setup_cli._node_asset() == \
            f"node-{setup_cli.NODE_VERSION}-linux-x64.tar.xz"
        monkeypatch.setattr(setup_cli.sys, "platform", "darwin")
        monkeypatch.setattr(_platform, "machine", lambda: "arm64")
        assert setup_cli._node_asset() == \
            f"node-{setup_cli.NODE_VERSION}-darwin-arm64.tar.xz"
        monkeypatch.setattr(_platform, "machine", lambda: "ppc64le")
        assert setup_cli._node_asset() is None

    def test_install_node_skips_when_present(self, monkeypatch):
        monkeypatch.setattr(bridge_cli, "find_node", lambda: "/x/node")
        monkeypatch.setattr(bridge_cli, "tool_version", lambda p: "v22.1.0")
        ok, detail = setup_cli.install_node()
        assert ok and "already installed" in detail

    def test_install_opencode_skips_when_present(self, monkeypatch):
        monkeypatch.setattr(bridge_cli, "find_opencode", lambda: "/x/opencode")
        ok, detail = setup_cli.install_opencode()
        assert ok and "already installed" in detail

    def test_install_node_reports_unsupported_platform(self, monkeypatch):
        monkeypatch.setattr(bridge_cli, "find_node", lambda: None)
        monkeypatch.setattr(setup_cli.sys, "platform", "linux")
        monkeypatch.setattr(_platform, "machine", lambda: "riscv64")
        ok, detail = setup_cli.install_node()
        assert not ok and "unsupported platform" in detail
