"""Unit tests for auth material handling (finalplan §8.4 / §11 secrets-at-rest)."""

import pytest

from velora.active.session import (
    AuthFormatError,
    build_auth,
    load_auth_file,
    parse_header,
    replay_auth_refs,
)


def test_parse_header_ok():
    assert parse_header("Authorization: Bearer abc") == (
        "Authorization", "Bearer abc",
    )
    assert parse_header("X-Api-Key:   secret  ") == ("X-Api-Key", "secret")


@pytest.mark.parametrize("spec", ["NoColon", ": value", "Name:", " : x"])
def test_parse_header_malformed(spec):
    with pytest.raises(AuthFormatError) as exc:
        parse_header(spec)
    assert str(exc.value).startswith("--header")


def test_load_auth_file_headers_and_cookies(tmp_path):
    path = tmp_path / "auth.txt"
    path.write_text(
        "# comment\n"
        "Authorization: Bearer tok\n"
        "session=abc123\n"
        "other=value\n"
    )
    headers = load_auth_file(str(path))
    assert headers["Authorization"] == "Bearer tok"
    assert headers["Cookie"] == "session=abc123; other=value"


def test_load_auth_file_rejects_garbage(tmp_path):
    path = tmp_path / "auth.txt"
    path.write_text("???\n")
    with pytest.raises(AuthFormatError) as exc:
        load_auth_file(str(path))
    assert str(exc.value).startswith("--auth-file")


def test_load_auth_file_missing(tmp_path):
    with pytest.raises(AuthFormatError) as exc:
        load_auth_file(str(tmp_path / "nope.txt"))
    assert str(exc.value).startswith("--auth-file")


def test_build_auth_cli_wins_and_refs_only(tmp_path):
    path = tmp_path / "auth.txt"
    secret = "file-secret-value"
    path.write_text(f"X-Api-Key: {secret}\n")
    material = build_auth(["X-Api-Key: cli-secret"], str(path))
    assert material.headers["X-Api-Key"] == "cli-secret"
    assert material.names == ["X-Api-Key"]
    refs_text = str(material.refs)
    assert "file:" + str(path) in refs_text
    # Secrets-at-rest: neither the file value nor the CLI value is stored.
    assert secret not in refs_text
    assert "cli-secret" not in refs_text


def test_replay_auth_file_ref(tmp_path):
    path = tmp_path / "auth.txt"
    path.write_text("X-Api-Key: replayed\n")
    stored = [{"kind": "auth-file", "name": str(path), "ref": f"file:{path}"}]
    extra, unreplayable = replay_auth_refs(stored, build_auth(None, None))
    assert extra == {"X-Api-Key": "replayed"}
    assert unreplayable == []


def test_replay_cli_header_ref_is_unreplayable():
    current = build_auth(["Authorization: Bearer x"], None)
    extra, unreplayable = replay_auth_refs(current.refs, build_auth(None, None))
    assert extra == {}
    assert unreplayable == ["Authorization"]


def test_replay_skips_when_header_already_current():
    current = build_auth(["Authorization: Bearer x"], None)
    stored = [{"kind": "header", "name": "Authorization", "ref": "cli:--header"}]
    extra, unreplayable = replay_auth_refs(stored, current)
    assert extra == {}
    assert unreplayable == []


def test_replay_missing_file_is_unreplayable(tmp_path):
    stored = [{
        "kind": "auth-file",
        "name": str(tmp_path / "gone.txt"),
        "ref": f"file:{tmp_path / 'gone.txt'}",
    }]
    extra, unreplayable = replay_auth_refs(stored, build_auth(None, None))
    assert extra == {}
    assert unreplayable


def test_parse_role_spec():
    from velora.active.session import parse_role_spec

    assert parse_role_spec("admin=/tmp/a.txt") == ("admin", "/tmp/a.txt")
    assert parse_role_spec("/tmp/b.txt") == ("default", "/tmp/b.txt")
    assert parse_role_spec("a=b=c") == ("a", "b=c")
    assert parse_role_spec("ROLE-1=x") == ("ROLE-1", "x")
    # not a role token: whole string is the path
    assert parse_role_spec("my file.txt") == ("default", "my file.txt")
    with pytest.raises(AuthFormatError) as exc:
        parse_role_spec("", "--auth-script")
    assert str(exc.value).startswith("--auth-script")


def test_build_auth_multiple_files_with_roles(tmp_path):
    default_file = tmp_path / "user.txt"
    default_file.write_text("X-User-Key: user-value\n")
    admin_file = tmp_path / "admin.txt"
    admin_file.write_text("X-Admin-Key: admin-value\n")
    material = build_auth(None, [str(default_file), f"admin={admin_file}"])
    assert material.headers == {"X-User-Key": "user-value"}
    assert material.roles["admin"] == {"X-Admin-Key": "admin-value"}
    assert sorted(material.roles) == ["admin", "default"]
    roles = {ref["role"] for ref in material.refs}
    assert roles == {"admin", "default"}
    refs_text = str(material.refs)
    assert "user-value" not in refs_text
    assert "admin-value" not in refs_text


def test_replay_named_role_file_merges_into_roles(tmp_path):
    admin_file = tmp_path / "admin.txt"
    admin_file.write_text("X-Admin-Key: replayed-admin\n")
    stored = [{
        "kind": "auth-file",
        "name": str(admin_file),
        "ref": f"file:{admin_file}",
        "role": "admin",
    }]
    current = build_auth(None, None)
    extra, unreplayable = replay_auth_refs(stored, current)
    assert extra == {}
    assert unreplayable == []
    assert current.roles["admin"] == {"X-Admin-Key": "replayed-admin"}


def test_replay_role_file_never_clobbers_current(tmp_path):
    admin_file = tmp_path / "admin.txt"
    admin_file.write_text("X-Key: from-file\n")
    current = build_auth(["X-Key: live"], None)
    current.roles.setdefault("admin", {})["X-Key"] = "live-admin"
    stored = [{
        "kind": "auth-file",
        "name": str(admin_file),
        "ref": f"file:{admin_file}",
        "role": "admin",
    }]
    replay_auth_refs(stored, current)
    assert current.roles["admin"]["X-Key"] == "live-admin"


def test_replay_auth_script_ref_is_unreplayable(tmp_path):
    script = tmp_path / "login.json"
    script.write_text('{"steps": [{"get": "/login"}]}')
    stored = [{
        "kind": "auth-script",
        "name": str(script),
        "ref": f"file:{script}",
        "role": "default",
    }]
    extra, unreplayable = replay_auth_refs(stored, build_auth(None, None))
    assert extra == {}
    assert unreplayable == [str(script)]


def test_replay_auth_script_skipped_when_repassed(tmp_path):
    script = tmp_path / "login.json"
    script.write_text('{"steps": [{"get": "/login"}]}')
    current = build_auth(None, None)
    current.refs.append({
        "kind": "auth-script",
        "name": str(script),
        "ref": f"file:{script}",
        "role": "default",
    })
    stored = [{
        "kind": "auth-script",
        "name": str(script),
        "ref": f"file:{script}",
        "role": "default",
    }]
    extra, unreplayable = replay_auth_refs(stored, current)
    assert extra == {}
    assert unreplayable == []
