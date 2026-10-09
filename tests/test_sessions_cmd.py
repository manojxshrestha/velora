"""Tests for `velora sessions list|prune` (finalplan §14 #3: keep-all + prune)."""

import json
import os
from pathlib import Path

from velora.cli import main


def _mk_session(root: Path, name: str, mtime: int) -> Path:
    d = root / ".velora" / name
    d.mkdir(parents=True, exist_ok=True)
    (d / "session.json").write_text(json.dumps({"schema_version": 1}))
    os.utime(d, (mtime, mtime))
    return d


def test_list_empty_dir(monkeypatch, tmp_path, capsys):
    monkeypatch.chdir(tmp_path)
    assert main(["sessions"]) == 0
    assert "no sessions in .velora/" in capsys.readouterr().out


def test_list_newest_first(monkeypatch, tmp_path, capsys):
    monkeypatch.chdir(tmp_path)
    _mk_session(tmp_path, "blackbox-old", 1_700_000_000)
    _mk_session(tmp_path, "whitebox-new", 1_700_100_000)
    assert main(["sessions", "list"]) == 0
    out = capsys.readouterr().out.splitlines()
    assert out[0].startswith("whitebox-new")
    assert out[1].startswith("blackbox-old")
    assert "1700" not in out[0]  # mtime rendered human-readable


def test_prune_requires_keep_or_all(monkeypatch, tmp_path, capsys):
    monkeypatch.chdir(tmp_path)
    _mk_session(tmp_path, "blackbox-a", 1_700_000_000)
    assert main(["sessions", "prune"]) == 2
    err = capsys.readouterr().err
    assert "specify --keep N or --all" in err
    assert (tmp_path / ".velora" / "blackbox-a").is_dir()


def test_prune_keep_dry_run_deletes_nothing(monkeypatch, tmp_path, capsys):
    monkeypatch.chdir(tmp_path)
    _mk_session(tmp_path, "blackbox-old", 1_700_000_000)
    _mk_session(tmp_path, "blackbox-new", 1_700_100_000)
    assert main(["sessions", "prune", "--keep", "1", "--dry-run"]) == 0
    out = capsys.readouterr().out
    assert "would remove blackbox-old" in out
    assert "blackbox-new" not in out
    assert (tmp_path / ".velora" / "blackbox-old").is_dir()


def test_prune_keep_removes_oldest(monkeypatch, tmp_path, capsys):
    monkeypatch.chdir(tmp_path)
    _mk_session(tmp_path, "blackbox-old", 1_700_000_000)
    _mk_session(tmp_path, "blackbox-mid", 1_700_050_000)
    _mk_session(tmp_path, "blackbox-new", 1_700_100_000)
    assert main(["sessions", "prune", "--keep", "2"]) == 0
    out = capsys.readouterr().out
    assert "removed blackbox-old" in out
    assert not (tmp_path / ".velora" / "blackbox-old").exists()
    assert (tmp_path / ".velora" / "blackbox-mid").is_dir()
    assert (tmp_path / ".velora" / "blackbox-new").is_dir()


def test_prune_all_and_then_empty(monkeypatch, tmp_path, capsys):
    monkeypatch.chdir(tmp_path)
    _mk_session(tmp_path, "blackbox-a", 1_700_000_000)
    _mk_session(tmp_path, "bughunt-b", 1_700_100_000)
    assert main(["sessions", "prune", "--all"]) == 0
    out = capsys.readouterr().out
    assert "removed blackbox-a" in out and "removed bughunt-b" in out
    assert main(["sessions", "prune", "--all"]) == 0
    assert "nothing to prune" in capsys.readouterr().out
    assert main(["sessions"]) == 0
    assert "no sessions" in capsys.readouterr().out


def test_prune_all_dry_run_keeps_everything(monkeypatch, tmp_path, capsys):
    monkeypatch.chdir(tmp_path)
    _mk_session(tmp_path, "blackbox-a", 1_700_000_000)
    assert main(["sessions", "prune", "--all", "--dry-run"]) == 0
    assert "would remove blackbox-a" in capsys.readouterr().out
    assert (tmp_path / ".velora" / "blackbox-a").is_dir()


def test_non_session_dirs_never_touched(monkeypatch, tmp_path, capsys):
    monkeypatch.chdir(tmp_path)
    junk = tmp_path / ".velora" / "not-a-session"
    junk.mkdir(parents=True)
    (junk / "notes.txt").write_text("keep me")
    _mk_session(tmp_path, "blackbox-a", 1_700_000_000)
    assert main(["sessions"]) == 0
    out = capsys.readouterr().out
    assert "not-a-session" not in out
    assert main(["sessions", "prune", "--all"]) == 0
    assert "removed blackbox-a" in capsys.readouterr().out
    assert (junk / "notes.txt").is_file()


def test_prune_negative_keep_is_usage_error(monkeypatch, tmp_path, capsys):
    monkeypatch.chdir(tmp_path)
    _mk_session(tmp_path, "blackbox-a", 1_700_000_000)
    assert main(["sessions", "prune", "--keep", "-1"]) == 2
    assert "--keep must be >= 0" in capsys.readouterr().err
    assert (tmp_path / ".velora" / "blackbox-a").is_dir()
