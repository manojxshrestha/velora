"""Auth material: refs-only cookies/headers + scripted login flows (§14.1, §8.4).

Values live only in memory for the run. The session records *references*
(``kind``, ``name``, ``ref``, ``role``) — never values — so the secrets-at-rest
audit (grep the session dir, §11) always comes back clean.

Accepted inputs:
  --header "Name: value"     repeatable; CLI wins over files; default role
  --auth-file [ROLE=]FILE    repeatable cookie/header file; optional ``ROLE=``
                             prefix selects a named jar (>=2 roles for
                             authz comparisons), default role ``default``
  --auth-script [ROLE=]FILE  repeatable JSON login-flow script executed once
                             at AUTH (velora/active/loginflow.py); captured
                             cookies/headers land in that role in memory
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Sequence, Tuple, Union

_HEADER_LINE = re.compile(r"^([^:=\s]+)\s*:\s*(.*)$")
_COOKIE_PAIR = re.compile(r"^[^:=\s]+\s*=\s*.+$")
_ROLE_TOKEN = re.compile(r"^[A-Za-z0-9_-]+$")


class AuthFormatError(ValueError):
    """Malformed --header spec, auth-file line, or role/path spec."""


@dataclass
class AuthMaterial:
    roles: Dict[str, Dict[str, str]] = field(default_factory=dict)
    refs: List[Dict[str, str]] = field(default_factory=list)

    @property
    def headers(self) -> Dict[str, str]:
        """Default-role headers — what the run's HTTP client sends."""
        return self.roles.setdefault("default", {})

    @property
    def names(self) -> List[str]:
        return sorted(self.headers)


def parse_role_spec(spec: str, flag: str = "--auth-file") -> Tuple[str, str]:
    """Split ``[ROLE=]PATH`` into ``(role, path)``; default role ``default``."""
    if not isinstance(spec, str):
        raise AuthFormatError(f"{flag}: expected [ROLE=]PATH, got {spec!r}")
    raw = spec.strip()
    if not raw:
        raise AuthFormatError(f"{flag}: empty [ROLE=]PATH spec")
    head, sep, tail = raw.partition("=")
    if sep and _ROLE_TOKEN.match(head) and tail.strip():
        return head, tail.strip()
    return "default", raw


def parse_header(spec: str) -> Tuple[str, str]:
    """Parse a --header 'Name: value' spec."""
    if ":" not in (spec or ""):
        raise AuthFormatError(
            f"--header: expected 'Name: value', got {spec!r}"
        )
    name, _, value = spec.partition(":")
    name, value = name.strip(), value.strip()
    if not name or not value:
        raise AuthFormatError(
            f"--header: expected 'Name: value', got {spec!r}"
        )
    return name, value


def load_auth_file(path: str) -> Dict[str, str]:
    """Parse an auth file into header pairs (cookie lines merged into Cookie)."""
    try:
        text = Path(path).read_text(encoding="utf-8")
    except OSError as exc:
        raise AuthFormatError(f"--auth-file: cannot read {path}: {exc}") from exc
    headers: Dict[str, str] = {}
    cookies: List[str] = []
    for number, raw in enumerate(text.splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        header_match = _HEADER_LINE.match(line)
        if header_match and ("=" not in header_match.group(1)):
            headers[header_match.group(1)] = header_match.group(2).strip()
            continue
        if _COOKIE_PAIR.match(line):
            cookies.append(line)
            continue
        raise AuthFormatError(
            f"--auth-file: {path}: line {number}: expected 'Name: value' "
            f"or 'name=value', got {raw!r}"
        )
    if cookies:
        headers["Cookie"] = "; ".join(
            cookies if "Cookie" not in headers else [headers["Cookie"], *cookies]
        )
    return headers


def build_auth(
    header_specs: Optional[Sequence[str]],
    auth_file: Optional[Union[str, Sequence[str]]],
) -> AuthMaterial:
    """Merge auth-file jar(s) with --header specs (CLI wins on conflict).

    ``auth_file`` accepts a single path or a repeatable ``--auth-file``
    list; entries may carry a ``ROLE=`` prefix to land in a named jar.
    """
    material = AuthMaterial()
    if auth_file:
        raw_files = [auth_file] if isinstance(auth_file, str) else list(auth_file)
        for raw in raw_files:
            role, path = parse_role_spec(str(raw), "--auth-file")
            loaded = load_auth_file(path)
            material.roles.setdefault(role, {}).update(loaded)
            material.refs.append({
                "kind": "auth-file",
                "name": str(path),
                "ref": f"file:{path}",
                "role": role,
            })
    for spec in header_specs or ():
        name, value = parse_header(spec)
        material.headers[name] = value
        material.refs.append({
            "kind": "header",
            "name": name,
            "ref": "cli:--header",
            "role": "default",
        })
    return material


def replay_auth_refs(
    entries: Iterable[Dict],
    current: AuthMaterial,
) -> Tuple[Dict[str, str], List[str]]:
    """Resume support: rebuild file-backed auth from session references.

    Returns ``(extra_default_headers, unreplayable)``. File refs re-read the
    file when it still exists: default-role extras come back for the caller
    to ``setdefault`` into the run headers, while named-role jars merge
    straight into ``current.roles`` (current values always win).
    ``cli:--header`` refs carry no value by design and ``auth-script`` refs
    cannot be replayed without the live target — both come back as
    unreplayable names the caller should warn about.
    """
    extra: Dict[str, str] = {}
    unreplayable: List[str] = []
    for entry in entries or ():
        if not isinstance(entry, dict):
            continue
        kind = entry.get("kind")
        name = str(entry.get("name") or "")
        ref = str(entry.get("ref") or "")
        role = str(entry.get("role") or "default")
        if kind == "auth-file" and ref.startswith("file:"):
            path = ref[len("file:"):]
            already = any(
                r.get("kind") == "auth-file" and str(r.get("name")) == path
                for r in current.refs
            )
            if already:
                continue
            try:
                loaded = load_auth_file(path)
            except AuthFormatError:
                unreplayable.append(name or path)
                continue
            if role == "default":
                extra.update(loaded)
            else:
                target = current.roles.setdefault(role, {})
                for key, value in loaded.items():
                    target.setdefault(key, value)
        elif kind == "auth-script":
            re_passed = any(
                r.get("kind") == "auth-script" and str(r.get("name")) == name
                for r in current.refs
            )
            if not re_passed and (name or ref):
                unreplayable.append(name or ref)
        elif kind == "header" and name and name not in current.names:
            unreplayable.append(name)
    return extra, unreplayable
