"""Tests for session dirs, crash-safe commits, resume (finalplan §8.5)."""

import json
import os

import pytest

from velora.cli import main
from velora.modes.common import MODE_SPECS, GrammarError, InputState
from velora.modes.session import (
    LOCK_NAME,
    Session,
    default_session_dir,
    resolve_session_path,
    session_hash,
)

WHITEBOX = MODE_SPECS["whitebox"]
BLACKBOX = MODE_SPECS["blackbox"]


@pytest.fixture(autouse=True)
def _isolated_cwd(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("VELORA_SESSION", raising=False)


def _session_with_stages(dirpath, mode="whitebox", stages=("ingest", "scan")):
    inputs = InputState(source="src")
    session = Session.open(dirpath)
    session.record_inputs(MODE_SPECS[mode], inputs)
    for stage in stages:
        session.commit_stage(MODE_SPECS[mode], inputs, stage, {})
    return session


class TestIdentity:
    def test_hash_is_stable_and_input_sensitive(self):
        base = session_hash("whitebox", InputState(source="src", target="https://x"))
        slash = session_hash("whitebox", InputState(source="src", target="https://x/"))
        other = session_hash("whitebox", InputState(source="other"))
        mode = session_hash("blackbox", InputState(source="src", target="https://x"))
        assert base == slash
        assert base != other
        assert base != mode

    def test_default_dir_shape(self):
        path = default_session_dir("whitebox", InputState(source="src"))
        assert path.parts[0] == ".velora"
        assert path.parts[1].startswith("whitebox-")

    def test_resolve_explicit_beats_hash(self, tmp_path):
        class A:
            session = str(tmp_path / "custom")
        path = resolve_session_path(A(), WHITEBOX, InputState(source="src"))
        assert path == tmp_path / "custom"

    def test_resolve_env(self, tmp_path, monkeypatch):
        monkeypatch.setenv("VELORA_SESSION", str(tmp_path / "envsess"))

        class A:
            session = None
        path = resolve_session_path(A(), WHITEBOX, InputState(source="src"))
        assert path == tmp_path / "envsess"

    def test_resolve_none_without_inputs(self):
        class A:
            session = None
        assert resolve_session_path(A(), WHITEBOX, InputState()) is None

    def test_resolve_hash_when_inputs_complete(self):
        class A:
            session = None
        path = resolve_session_path(A(), WHITEBOX, InputState(source="src"))
        assert path is not None and str(path).startswith(".velora/whitebox-")


class TestCommits:
    def test_stage_commit_writes_artifacts_then_meta(self):
        inputs = InputState(source="src")
        session = Session.open(default_session_dir("whitebox", inputs))
        session.record_inputs(WHITEBOX, inputs)
        session.commit_stage(
            WHITEBOX, inputs, "scan", {"findings.json": [{"title": "x"}]}
        )
        assert (session.path / "findings.json").is_file()
        assert session.completed_stages() == ["scan"]
        meta = json.loads((session.path / "session.json").read_text())
        assert meta["schema_version"] == 1
        assert meta["inputs"]["source"] == "src"

    def test_commit_is_idempotent_per_stage(self):
        inputs = InputState(source="src")
        session = Session.open(default_session_dir("whitebox", inputs))
        session.commit_stage(WHITEBOX, inputs, "verify", {})
        session.commit_stage(WHITEBOX, inputs, "verify", {})
        assert session.completed_stages() == ["verify"]

    def test_append_findings_dedupes(self):
        inputs = InputState(source="src")
        session = Session.open(default_session_dir("whitebox", inputs))
        session.append_findings([{"title": "a", "file": "f.py", "line": 1}])
        session.append_findings([
            {"title": "a", "file": "f.py", "line": 1},
            {"title": "b", "file": "g.py", "line": 2},
        ])
        stored = session.read_json("findings.json", [])
        assert len(stored) == 2

    def test_na_and_secrets_recorded(self):
        inputs = InputState(source="src")
        session = Session.open(default_session_dir("whitebox", inputs))
        session.record_inputs(WHITEBOX, inputs)
        session.record_na(WHITEBOX, inputs, ["exploit"])
        session.record_secret_ref("header", "Authorization", "env:TOKEN")
        meta = json.loads((session.path / "session.json").read_text())
        assert meta["na"] == ["exploit"]
        assert meta["secrets"] == [
            {"kind": "header", "name": "Authorization", "ref": "env:TOKEN"}
        ]
        assert "TOKEN" not in json.dumps(meta).replace("env:TOKEN", "")

    def test_merge_inputs_cli_wins(self):
        session = Session.open(default_session_dir(
            "whitebox", InputState(source="session-src", target="https://s")
        ))
        session.record_inputs(WHITEBOX, InputState(source="session-src", target="https://s"))
        merged = session.merge_inputs(InputState(source="cli-src"))
        assert merged.source == "cli-src"
        assert merged.target == "https://s"


class TestLock:
    def test_second_writer_refused(self):
        session = Session.open(default_session_dir("whitebox", InputState(source="src")))
        session.acquire_lock()
        other = Session.open(session.path)
        with pytest.raises(GrammarError) as exc:
            other.acquire_lock()
        assert exc.value.code == 1
        assert "in use" in exc.value.message
        session.release_lock()

    def test_release_then_reacquire(self):
        session = Session.open(default_session_dir("whitebox", InputState(source="src")))
        session.acquire_lock()
        session.release_lock()
        session.acquire_lock()
        session.release_lock()
        assert not (session.path / LOCK_NAME).exists()

    def test_stale_lock_taken_over(self):
        session = Session.open(default_session_dir("whitebox", InputState(source="src")))
        session.path.mkdir(parents=True)
        (session.path / LOCK_NAME).write_text("999999")
        session.acquire_lock()
        assert (session.path / LOCK_NAME).read_text() == str(os.getpid())
        session.release_lock()


class TestShellIntegration:
    def test_from_without_session_exits_1(self, capsys):
        rc = main(["whitebox", "--source", "src", "--from", "verify", "--dry-run"])
        assert rc == 1
        assert "session" in capsys.readouterr().err

    def test_from_with_session_artifacts_runs(self, capsys):
        inputs = InputState(source="src")
        path = default_session_dir("whitebox", inputs)
        _session_with_stages(path, stages=("verify",))
        rc = main(["whitebox", "--source", "src", "--from", "verify", "--dry-run"])
        assert rc == 0
        out = capsys.readouterr().out
        assert "VERIFY" in out
        assert "SCOPE" not in out.split("stages:")[1].split("→")[0]

    def test_session_path_shown_in_dry_run(self, capsys):
        main(["whitebox", "--source", "src", "--dry-run"])
        out = capsys.readouterr().out
        assert "session:  .velora/whitebox-" in out

    def test_cli_to_session_input_resolution(self, tmp_path, capsys):
        src = tmp_path / "src"
        src.mkdir()
        (src / "app.py").write_text("def add(a, b):\n    return a + b\n")
        inputs = InputState(source="src")
        path = default_session_dir("whitebox", inputs)
        _session_with_stages(path, stages=("ingest",))
        rc = main(["whitebox", "--session", str(path)])
        assert rc == 0
        err = capsys.readouterr().err
        assert "path not found" not in err
        assert "SCOPE" in err
        assert "REPORT" in err

    def test_env_session_resolution(self, tmp_path, monkeypatch, capsys):
        inputs = InputState(source="src")
        path = default_session_dir("whitebox", inputs)
        _session_with_stages(path, stages=("ingest",))
        monkeypatch.setenv("VELORA_SESSION", str(path))
        rc = main(["whitebox", "--dry-run"])
        assert rc == 0
        assert str(path) in capsys.readouterr().out

    def test_missing_input_still_exits_1(self, capsys):
        rc = main(["whitebox"])
        assert rc == 1
        assert "--source" in capsys.readouterr().err
