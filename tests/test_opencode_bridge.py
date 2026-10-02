"""Tests for the zero-key opencode bridge: serve-bridge CLI, model TUI,
keyless model resolution, and the Node bridge unit tests."""

import argparse
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

import pytest

from velora.cli import create_parser, main
from velora import bridge_cli, models_tui
from velora.models_cli import _LOCAL_PROVIDERS, _resolve_generic
from velora.sil import model_config

BRIDGE_REF = "opencode-bridge/opencode/mimo-v2.6-flash-free"
BRIDGE_BASE = "http://127.0.0.1:8399/v1"


def _args(**kw):
    base = {"api_key": None, "no_prompt": True, "base_url": None}
    base.update(kw)
    return argparse.Namespace(**base)


class TestServeBridgeCLI:
    def test_parser_flags(self):
        args = create_parser().parse_args(
            ["serve-bridge", "--port", "8401", "--opencode-port", "4601",
             "--configure", "--model", "opencode/mimo-v2.6-flash-free"])
        assert args.command == "serve-bridge"
        assert args.port == 8401
        assert args.opencode_port == 4601
        assert args.configure is True
        assert args.model == "opencode/mimo-v2.6-flash-free"

    def test_parser_defaults(self):
        args = create_parser().parse_args(["serve-bridge"])
        assert args.port == bridge_cli.DEFAULT_PORT
        assert args.opencode_port == bridge_cli.DEFAULT_OC_PORT
        assert args.configure is False
        assert args.model is None

    def test_packaged_bridge_sources_shipped(self):
        src = bridge_cli.bridge_sources_dir()
        for name in bridge_cli.BRIDGE_FILES:
            assert (src / name).is_file(), f"missing packaged {name}"

    def test_seed_sources_idempotent(self, tmp_path, monkeypatch):
        runtime = tmp_path / "bridge"
        assert bridge_cli.seed_bridge_sources(runtime) is True
        assert (runtime / "server.js").is_file()
        assert bridge_cli.seed_bridge_sources(runtime) is False
        monkeypatch.setenv("VELORA_BRIDGE_HOME", str(runtime))
        assert bridge_cli.bridge_dir() == runtime
        assert (runtime / "package.json").is_file()

    def test_port_busy_detection(self):
        import socket
        with socket.socket() as probe:
            probe.bind(("127.0.0.1", 0))
            probe.listen(1)
            port = probe.getsockname()[1]
            assert bridge_cli._port_busy(port) is True
        assert bridge_cli._port_busy(port) is False

    def test_find_node_prefers_native(self, monkeypatch, tmp_path):
        monkeypatch.setenv("HOME", str(tmp_path))
        (tmp_path / ".local" / "bin").mkdir(parents=True)
        native = tmp_path / ".local" / "bin" / "node"
        native.write_text("#!/bin/sh\n")
        monkeypatch.setattr(shutil, "which",
                            lambda name: "/mnt/c/Program Files/nodejs/node.exe")
        assert bridge_cli.find_node() == str(native)

    def test_find_node_none_when_only_windows(self, monkeypatch, tmp_path):
        monkeypatch.setenv("HOME", str(tmp_path))
        monkeypatch.setattr(shutil, "which",
                            lambda name: "/mnt/c/Program Files/nodejs/node.exe")
        # find_node also falls back to hardcoded system paths
        # (/usr/local/bin/node, ...). Hide them so the assertion does not
        # depend on the machine -- CI images ship a node there.
        hardcoded = {"/opt/homebrew/bin/node", "/usr/local/bin/node",
                     "/usr/bin/node", "/opt/node/bin/node"}
        real_is_file = Path.is_file
        monkeypatch.setattr(
            Path, "is_file",
            lambda self: str(self) not in hardcoded and real_is_file(self))
        assert bridge_cli.find_node() is None

    def test_find_opencode_skips_exe(self, monkeypatch, tmp_path):
        monkeypatch.setenv("HOME", str(tmp_path))
        target = tmp_path / ".opencode" / "bin" / "opencode"
        target.parent.mkdir(parents=True)
        target.write_text("#!/bin/sh\n")
        monkeypatch.setattr(shutil, "which",
                            lambda name: "/mnt/c/tools/opencode/opencode.exe")
        assert bridge_cli.find_opencode() == str(target)


class TestModelsTuiRegistration:
    def test_tui_action_registered(self):
        args = create_parser().parse_args(["models", "tui", "--base-url", BRIDGE_BASE])
        assert args.models_action == "tui"
        assert args.base_url == BRIDGE_BASE

    def test_tui_unknown_action_still_rejected(self):
        with pytest.raises(SystemExit):
            create_parser().parse_args(["models", "bogus"])


class TestKeylessBridgeModel:
    def test_bridge_is_local_provider(self):
        assert "opencode-bridge" in _LOCAL_PROVIDERS

    def test_resolve_generic_is_keyless(self):
        entry = _resolve_generic("opencode-bridge/opencode/mimo-v2.6-flash-free",
                                 _args(base_url=BRIDGE_BASE))
        assert entry == {
            "provider": "opencode-bridge",
            "base_url": BRIDGE_BASE,
            "model": "opencode/mimo-v2.6-flash-free",
            "api_key": "sk-local",
            "source": "velora-models",
            "keyless": True,
        }

    def test_resolve_generic_default_bridge_endpoint(self):
        entry = _resolve_generic("opencode-bridge/opencode/mimo-v2.6-flash-free",
                                 _args(base_url=None))
        assert entry["base_url"] == bridge_cli.DEFAULT_BASE_URL
        assert entry["keyless"] is True

    def test_cmd_use_never_writes_credentials(self, capsys, tmp_path):
        rc = main(["models", "use", BRIDGE_REF, "--no-prompt"])
        assert rc == 0
        active = model_config.active()
        assert active["provider"] == "opencode-bridge"
        assert active["model"] == "opencode/mimo-v2.6-flash-free"
        assert active["base_url"] == BRIDGE_BASE
        assert not model_config.credentials_path().exists()

    def test_resolve_llm_settings_from_config(self, capsys, monkeypatch):
        monkeypatch.delenv("VELORA_SKIP_PROVIDER_FALLBACK", raising=False)
        assert main(["models", "use", BRIDGE_REF, "--no-prompt"]) == 0
        settings = model_config.resolve_llm_settings()
        assert settings["base_url"] == BRIDGE_BASE
        assert settings["model"] == "opencode/mimo-v2.6-flash-free"
        assert settings["api_key"] == ""   # keyless: transport falls back to sk-local
        from velora.sil.llm_client import LLMConfig
        cfg = LLMConfig.from_env()
        assert cfg.enabled
        assert cfg.base_url == BRIDGE_BASE
        assert cfg.model == "opencode/mimo-v2.6-flash-free"
        assert cfg.api_key == "sk-local"


class TestModelsTui:
    @staticmethod
    def _non_tty(monkeypatch):
        fake = type("Stream", (), {"isatty": lambda self: False})()
        monkeypatch.setattr(sys, "stdin", fake)

    @staticmethod
    def _entry(provider="optiq", model="qwen", url="http://localhost:47317/v1",
               source="local"):
        return {"provider": provider, "base_url": url, "model": model,
                "source": source, "label": f"[{provider}] {model}"}

    def test_no_sources_returns_error(self, monkeypatch, capsys):
        def boom(base_url, timeout=5.0):
            raise OSError("connection refused")
        monkeypatch.setattr(models_tui, "fetch_models", boom)
        self._non_tty(monkeypatch)
        assert models_tui.cmd_tui(_args()) == 1
        err = capsys.readouterr().err
        assert "velora serve-bridge" in err
        assert "bridge: down" in err

    def test_choose_prompt_selects_by_number(self, capsys):
        entries = [self._entry(model=m) for m in ("a", "b", "c")]
        idx = models_tui.choose_prompt(entries, None, input_fn=lambda _: "2")
        assert idx == 1

    def test_choose_prompt_out_of_range_retries_then_cancels(self, capsys):
        entries = [self._entry(model="a"), self._entry(model="b")]
        answers = iter(["9", ""])
        idx = models_tui.choose_prompt(entries, None,
                                       input_fn=lambda _: next(answers))
        assert idx is None

    def test_cmd_tui_saves_bridge_selection_keyless(self, monkeypatch, capsys):
        entries = [
            {"provider": "opencode-bridge",
             "base_url": models_tui.DEFAULT_BRIDGE,
             "model": "opencode/mimo-v2.6-flash-free",
             "source": "opencode-bridge",
             "label": "[bridge] opencode/mimo-v2.6-flash-free"},
            self._entry(),
        ]
        monkeypatch.setattr(models_tui, "discover",
                            lambda args=None: (entries, "bridge: 1; local: optiq"))
        monkeypatch.setattr(models_tui, "choose_prompt",
                            lambda ms, active, input_fn=input: 0)
        self._non_tty(monkeypatch)
        assert models_tui.cmd_tui(_args()) == 0
        active = model_config.active()
        assert active["provider"] == "opencode-bridge"
        assert active["model"] == "opencode/mimo-v2.6-flash-free"
        assert active["base_url"] == models_tui.DEFAULT_BRIDGE
        assert not model_config.credentials_path().exists()
        assert "velora scan --ai" in capsys.readouterr().out

    def test_cmd_tui_saves_local_selection_keyless(self, monkeypatch, capsys):
        entries = [self._entry(provider="optiq",
                               model="mlx-community/Qwen3.6-35B-A3B-OptiQ-4bit",
                               url="http://localhost:47317/v1")]
        monkeypatch.setattr(models_tui, "discover",
                            lambda args=None: (entries, "local: optiq"))
        monkeypatch.setattr(models_tui, "choose_prompt",
                            lambda ms, active, input_fn=input: 0)
        self._non_tty(monkeypatch)
        assert models_tui.cmd_tui(_args()) == 0
        active = model_config.active()
        assert active["provider"] == "optiq"
        assert active["model"] == "mlx-community/Qwen3.6-35B-A3B-OptiQ-4bit"
        assert active["base_url"] == "http://localhost:47317/v1"
        assert active["source"] == "local"
        assert not model_config.credentials_path().exists()

    def test_render_list_marks_active_and_cursor(self):
        entries = [self._entry(provider="p", model="a"),
                   self._entry(provider="p", model="b")]
        text = models_tui.render_list(entries, ("p", "b"), cursor=0)
        assert "> [p] a" in text
        assert "[p] b  [active]" in text

    def test_tui_autostarts_bridge_when_down(self, monkeypatch):
        started = {"n": 0}
        monkeypatch.setattr(models_tui.bridge_cli, "bridge_health",
                            lambda *a, **k: False)

        def fake_start(*a, **k):
            started["n"] += 1
            return 0

        monkeypatch.setattr(models_tui.bridge_cli, "start_bridge", fake_start)
        monkeypatch.setattr(models_tui, "discover",
                            lambda args=None: ([self._entry()], "bridge: 1"))
        monkeypatch.setattr(models_tui, "choose_prompt",
                            lambda ms, active, input_fn=input: None)
        self._non_tty(monkeypatch)
        assert models_tui.cmd_tui(_args()) == 0
        assert started["n"] == 1

    def test_tui_skips_autostart_when_bridge_up(self, monkeypatch):
        monkeypatch.setattr(models_tui.bridge_cli, "bridge_health",
                            lambda *a, **k: True)
        monkeypatch.setattr(models_tui.bridge_cli, "start_bridge",
                            lambda *a, **k: (_ for _ in ()).throw(
                                AssertionError("must not start")))
        monkeypatch.setattr(models_tui, "discover",
                            lambda args=None: ([self._entry()], "bridge: 1"))
        monkeypatch.setattr(models_tui, "choose_prompt",
                            lambda ms, active, input_fn=input: None)
        self._non_tty(monkeypatch)
        assert models_tui.cmd_tui(_args()) == 0

    def test_tui_skips_autostart_for_custom_bridge(self, monkeypatch):
        monkeypatch.setattr(models_tui.bridge_cli, "bridge_health",
                            lambda *a, **k: (_ for _ in ()).throw(
                                AssertionError("health must not be probed")))
        monkeypatch.setattr(models_tui, "discover",
                            lambda args=None: ([self._entry()], "x"))
        monkeypatch.setattr(models_tui, "choose_prompt",
                            lambda ms, active, input_fn=input: None)
        self._non_tty(monkeypatch)
        assert models_tui.cmd_tui(_args(
            base_url="http://other-host:9999/v1")) == 0

    def test_bridge_base_precedence(self, monkeypatch):
        monkeypatch.delenv("VELORA_BRIDGE_URL", raising=False)
        assert models_tui.bridge_base(_args(base_url=None)) == models_tui.DEFAULT_BRIDGE
        assert models_tui.bridge_base(_args(base_url="http://x:1/v1/")) == "http://x:1/v1"
        monkeypatch.setenv("VELORA_BRIDGE_URL", "http://env:2/v1")
        assert models_tui.bridge_base(_args(base_url=None)) == "http://env:2/v1"


class TestLocalEndpoints:
    def test_parse_endpoint_name_url(self):
        assert models_tui.parse_endpoint("optiq=http://localhost:47317/v1") == \
            ("optiq", "http://localhost:47317/v1")

    def test_parse_endpoint_bare_url(self):
        assert models_tui.parse_endpoint("http://localhost:47317/v1/") == \
            ("localhost-47317", "http://localhost:47317/v1")

    def test_parse_endpoint_rejects_bad_specs(self):
        with pytest.raises(ValueError):
            models_tui.parse_endpoint("")
        with pytest.raises(ValueError):
            models_tui.parse_endpoint("no-equals-or-url")
        with pytest.raises(ValueError):
            models_tui.parse_endpoint("name=not-a-url")

    def test_defaults_include_readme_optiq_setup(self, monkeypatch):
        monkeypatch.delenv("VELORA_LOCAL_URLS", raising=False)
        endpoints = models_tui.local_endpoints(_args())
        assert ("optiq", "http://localhost:47317/v1") in endpoints
        assert ("ollama", "http://localhost:11434/v1") in endpoints

    def test_env_and_args_extend_defaults(self, monkeypatch):
        monkeypatch.setenv("VELORA_LOCAL_URLS", "macbox=http://10.0.0.5:47317/v1")
        endpoints = models_tui.local_endpoints(
            _args(local_url=["myvllm=http://gpu-box:8000/v1"]))
        urls = dict((u, n) for n, u in endpoints)
        assert urls["http://10.0.0.5:47317/v1"] == "macbox"
        assert urls["http://gpu-box:8000/v1"] == "myvllm"
        assert urls["http://localhost:47317/v1"] == "optiq"

    def test_duplicate_names_get_suffixed(self, monkeypatch):
        monkeypatch.setenv("VELORA_LOCAL_URLS", "")
        endpoints = models_tui.local_endpoints(
            _args(local_url=["optiq=http://otherhost:9/v1"]))
        names = [n for n, _ in endpoints]
        assert len(names) == len(set(names))
        assert ("optiq-2", "http://otherhost:9/v1") in endpoints

    def test_cli_local_url_registered(self):
        args = create_parser().parse_args(
            ["models", "tui", "--local-url", "optiq=http://localhost:47317/v1"])
        assert args.models_action == "tui"
        assert args.local_url == ["optiq=http://localhost:47317/v1"]

    def test_discover_mixed_sources(self, monkeypatch):
        monkeypatch.setenv("VELORA_LOCAL_URLS", "")
        optiq_url = "http://localhost:47317/v1"

        def fake_fetch(base_url, timeout=5.0):
            base_url = base_url.rstrip("/")
            if base_url == models_tui.DEFAULT_BRIDGE:
                raise OSError("bridge down")
            if base_url == optiq_url:
                return ["mlx-community/Qwen3.6-35B-A3B-OptiQ-4bit"]
            raise OSError("not running")

        monkeypatch.setattr(models_tui, "fetch_models", fake_fetch)
        entries, summary = models_tui.discover(_args())
        assert len(entries) == 1
        entry = entries[0]
        assert entry["provider"] == "optiq"
        assert entry["model"] == "mlx-community/Qwen3.6-35B-A3B-OptiQ-4bit"
        assert entry["source"] == "local"
        assert "bridge: down" in summary
        assert "local: optiq" in summary

    def test_discover_bridge_up(self, monkeypatch):
        monkeypatch.setenv("VELORA_LOCAL_URLS", "")

        def fake_fetch(base_url, timeout=5.0):
            if base_url.rstrip("/") == models_tui.DEFAULT_BRIDGE:
                return ["mimo-v2.6-flash-free"]
            raise OSError("not running")

        monkeypatch.setattr(models_tui, "fetch_models", fake_fetch)
        entries, summary = models_tui.discover(_args())
        assert len(entries) == 1
        assert entries[0]["provider"] == "opencode-bridge"
        assert entries[0]["model"] == "opencode/mimo-v2.6-flash-free"
        assert "bridge: 1" in summary


FAKE_HEALTH_SERVER = '''
import sys, signal
from http.server import BaseHTTPRequestHandler, HTTPServer
class H(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path.startswith("/health"):
            body = b'{"ok": true}'
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        else:
            self.send_response(404)
            self.end_headers()
    def log_message(self, *a):
        pass
signal.signal(signal.SIGTERM, lambda *a: sys.exit(0))
HTTPServer(("127.0.0.1", int(sys.argv[1])), H).serve_forever()
'''


def _free_port():
    import socket
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


class TestDaemon:
    @staticmethod
    def _state_home(monkeypatch, tmp_path):
        home = tmp_path / "state"
        monkeypatch.setenv("VELORA_STATE_HOME", str(home))
        return home

    @staticmethod
    def _prep(tmp_path, port, oc_port):
        return {"node": "node", "opencode": "opencode",
                "env": dict(os.environ), "dst": str(tmp_path),
                "port": port, "oc_port": oc_port}

    @staticmethod
    def _launcher(script, port):
        def launch(cmd, env, dst):
            return subprocess.Popen([sys.executable, str(script), str(port)])
        return launch

    def test_start_status_stop_roundtrip(self, monkeypatch, tmp_path, capsys):
        self._state_home(monkeypatch, tmp_path)
        script = tmp_path / "fake_bridge.py"
        script.write_text(FAKE_HEALTH_SERVER)
        port, oc_port = _free_port(), _free_port()
        args = argparse.Namespace(port=port, opencode_port=oc_port,
                                  bridge_cmd=None, format="text")
        prep = self._prep(tmp_path, port, oc_port)
        launcher = self._launcher(script, port)

        assert bridge_cli.start_bridge(args, launcher=launcher, prep=prep) == 0
        state = bridge_cli._read_state()
        assert state and state["port"] == port and state["pid"]
        capsys.readouterr()
        assert bridge_cli.start_bridge(args, launcher=launcher, prep=prep) == 0
        assert "already running" in capsys.readouterr().out

        assert bridge_cli.status_bridge(args) == 0
        capsys.readouterr()
        assert bridge_cli.status_bridge(args, fmt="json") == 0
        import json as _json
        info = _json.loads(capsys.readouterr().out)
        assert info["healthy"] is True and info["pid"] == state["pid"]

        assert bridge_cli.stop_bridge(args) == 0
        assert bridge_cli._read_state() is None
        assert bridge_cli.status_bridge(args) == 1
        assert "not running" in capsys.readouterr().out

    def test_stop_without_state_is_noop(self, monkeypatch, tmp_path, capsys):
        self._state_home(monkeypatch, tmp_path)
        args = argparse.Namespace(port=_free_port(), format="text")
        assert bridge_cli.stop_bridge(args) == 0
        assert "not running" in capsys.readouterr().out

    def test_stale_pidfile_cleared_on_start(self, monkeypatch, tmp_path):
        self._state_home(monkeypatch, tmp_path)
        script = tmp_path / "fake_bridge.py"
        script.write_text(FAKE_HEALTH_SERVER)
        proc = subprocess.Popen([sys.executable, "-c", "pass"])
        proc.wait(timeout=10)
        bridge_cli._write_state({"pid": proc.pid, "port": _free_port(),
                                 "oc_port": _free_port()})
        port, oc_port = _free_port(), _free_port()
        args = argparse.Namespace(port=port, opencode_port=oc_port,
                                  format="text")
        prep = self._prep(tmp_path, port, oc_port)
        assert bridge_cli.start_bridge(args, launcher=self._launcher(script, port),
                                       prep=prep) == 0
        assert bridge_cli._read_state()["pid"] != proc.pid
        bridge_cli.stop_bridge(args)

    def test_status_json_not_running(self, monkeypatch, tmp_path, capsys):
        self._state_home(monkeypatch, tmp_path)
        import json as _json
        args = argparse.Namespace(port=_free_port(), format="json")
        assert bridge_cli.status_bridge(args, fmt="json") == 1
        info = _json.loads(capsys.readouterr().out)
        assert info["running"] is False and info["healthy"] is False


class TestNodeBridgeUnitTests:
    def test_node_test_suite(self, monkeypatch):
        node = bridge_cli.find_node()
        if node is None:
            pytest.skip("no native node on PATH")
        workspace = Path(tempfile.gettempdir()) / "velora-bridge-node-tests"
        monkeypatch.setenv("VELORA_BRIDGE_HOME", str(workspace))
        err = bridge_cli.ensure_bridge(node)
        if err:
            pytest.skip(f"bridge deps unavailable: {err}")
        proc = subprocess.run(
            [node, "--test", "server.test.js"],
            cwd=bridge_cli.bridge_dir(),
            capture_output=True, text=True, timeout=120,
        )
        assert proc.returncode == 0, proc.stdout + proc.stderr
