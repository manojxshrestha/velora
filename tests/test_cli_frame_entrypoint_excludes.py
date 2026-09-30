"""The installed `frame` alias (`[project.scripts] frame = "velora.cli:main_legacy"`)
must also honor the default directory excludes and `--no-default-excludes`.

`velora/cli.py` and `velora/sil/cli.py` are two SEPARATE argparse parsers for
the same `scan` subcommand: `velora.cli.cmd_scan` delegates execution to
`velora.sil.cli.cmd_scan`, but `velora.cli.create_parser` parses the arguments
first, on its own parser. A flag registered on only one of them would make
`velora scan --no-default-excludes` (the actual, installed entry point) fail
with "unrecognized arguments" while `python -m velora.sil.cli scan ...
--no-default-excludes` worked fine.

tests/test_cli_no_default_excludes.py already covers `velora.sil.cli`
directly; this file is the companion that drives `velora.cli` -- the exact
regression this feature's own rationale names.
"""

import json

from velora.cli import create_parser, main


def _tree(tmp_path):
    (tmp_path / "app.py").write_text("x = 1\n")
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "app2.py").write_text("y = 2\n")
    git_dir = tmp_path / ".git"
    git_dir.mkdir()
    (git_dir / "hook.py").write_text("print('hook')\n")
    return git_dir / "hook.py"


def test_frame_cli_flag_parses_and_defaults_to_false():
    parser = create_parser()
    args = parser.parse_args(["scan", "app.py"])
    assert args.no_default_excludes is False

    args = parser.parse_args(["scan", "app.py", "--no-default-excludes"])
    assert args.no_default_excludes is True


def test_frame_cli_default_scan_skips_git_directory(tmp_path, capsys):
    hook = _tree(tmp_path)

    rc = main(["scan", str(tmp_path), "--no-verify", "-f", "json", "--fail-on", "none"])
    captured = capsys.readouterr()
    assert rc == 0

    data = json.loads(captured.out)
    filenames = {f["filename"] for f in data["files"]}
    assert str(hook) not in filenames
    assert any(name.endswith("app.py") for name in filenames)
    assert any(name.endswith("app2.py") for name in filenames)


def test_frame_cli_no_default_excludes_flag_scans_everything(tmp_path, capsys):
    hook = _tree(tmp_path)

    rc = main([
        "scan", str(tmp_path), "--no-verify", "--no-default-excludes",
        "-f", "json", "--fail-on", "none",
    ])
    captured = capsys.readouterr()
    assert rc == 0

    data = json.loads(captured.out)
    filenames = {f["filename"] for f in data["files"]}
    assert str(hook) in filenames
