"""Scripted login flows: the AUTH adapter's JSON step DSL (finalplan §8.4, §14.1).

A flow file is a small JSON document: ordered steps that GET/POST, capture
variables, and assert expectations. Secrets come from ``${ENV_VAR}``
(environment) or ``$capture`` (extract results), so credentials never live
in the script, the session, or evidence — the session records only a
``file:`` reference (secrets-at-rest, §8.5). Steps run through the scoped
HTTP client (scope + rate + budget enforced) with responses unrecorded,
because login bodies can contain tokens.

Example::

    {"steps": [
      {"get": "/login", "expect": {"status": 200}},
      {"extract": {"name": "csrf", "pattern": "csrf=([0-9a-f]+)"}},
      {"post": "/login", "form": {"user": "${VELORA_USER}", "csrf": "$csrf"},
       "expect": {"status": [200, 302], "cookie": "session"}},
      {"get": "/account", "expect": {"status": 200, "body_contains": "Welcome"}}
    ]}

Step actions: ``get`` / ``post`` (optionally with ``form`` and ``expect``),
``extract`` (regex capture from the previous response) and ``set_header``
(outgoing and returned headers). Expectations evaluate against the final
response after redirects. Relative step URLs resolve against the first
TARGET origin; absolute URLs must be in scope or the step fails.
"""

from __future__ import annotations

import json
import os
import re
import urllib.parse
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Mapping, Optional

from velora.active.client import BudgetExhausted, InertVerbRefused, ScopeRefused

MAX_STEPS = 25
_ACTIONS = ("get", "post", "extract", "set_header")
_ENV = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)\}")
_CAPTURE = re.compile(r"\$([A-Za-z_][A-Za-z0-9_]*)")
_NAME = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
_HEADER_NAME = re.compile(r"^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$")


class FlowFormatError(ValueError):
    """Malformed --auth-script file (unreadable, bad JSON, schema violation)."""


class FlowRunError(ValueError):
    """A flow step failed while running against the target."""


@dataclass
class Flow:
    source: str
    name: str
    steps: List[dict] = field(default_factory=list)


def load_flow(path: str) -> Flow:
    """Read and validate a flow file. Raises :class:`FlowFormatError`."""
    try:
        text = Path(path).read_text(encoding="utf-8")
    except OSError as exc:
        raise FlowFormatError(f"--auth-script: cannot read {path}: {exc}") from exc
    try:
        data = json.loads(text)
    except ValueError as exc:
        raise FlowFormatError(
            f"--auth-script: {path}: invalid JSON: {exc}"
        ) from exc
    if not isinstance(data, dict):
        raise FlowFormatError(f"--auth-script: {path}: expected a JSON object")
    unknown = sorted(set(data) - {"name", "steps"})
    if unknown:
        raise FlowFormatError(
            f"--auth-script: {path}: unknown key(s): {', '.join(unknown)}"
        )
    name = data.get("name")
    if name is not None and not isinstance(name, str):
        raise FlowFormatError(f"--auth-script: {path}: 'name' must be a string")
    raw_steps = data.get("steps")
    if not isinstance(raw_steps, list) or not raw_steps:
        raise FlowFormatError(
            f"--auth-script: {path}: 'steps' must be a non-empty list"
        )
    if len(raw_steps) > MAX_STEPS:
        raise FlowFormatError(
            f"--auth-script: {path}: {len(raw_steps)} steps exceed the "
            f"{MAX_STEPS}-step limit"
        )
    steps = [
        _validate_step(path, index, step)
        for index, step in enumerate(raw_steps, 1)
    ]
    return Flow(source=str(path), name=name or Path(path).stem, steps=steps)


def _fail(path: str, where: str, message: str) -> FlowFormatError:
    return FlowFormatError(f"--auth-script: {path}: {where}: {message}")


def _validate_step(path: str, index: int, step: object) -> dict:
    where = f"step {index}"
    if not isinstance(step, dict):
        raise _fail(path, where, "expected an object")
    actions = [key for key in step if key in _ACTIONS]
    if len(actions) != 1:
        raise _fail(
            path, where, f"expected exactly one of {', '.join(_ACTIONS)}"
        )
    action = actions[0]
    allowed = {action}
    if action in ("get", "post"):
        allowed |= {"expect", "form"}
    unknown = sorted(set(step) - allowed)
    if unknown:
        raise _fail(path, where, f"unknown key(s): {', '.join(unknown)}")
    target = step[action]
    if action in ("get", "post"):
        if not isinstance(target, str) or not target.strip():
            raise _fail(path, where, f"{action!r} must be a non-empty string")
    if action == "post":
        form = step.get("form")
        if form is not None:
            if not isinstance(form, dict):
                raise _fail(path, where, "'form' must be an object")
            for key, value in form.items():
                if not isinstance(key, str) or not isinstance(value, str):
                    raise _fail(
                        path, where, "'form' keys and values must be strings"
                    )
    elif action == "extract":
        spec = target
        if not isinstance(spec, dict):
            raise _fail(path, where, "'extract' must be an object")
        unknown = sorted(set(spec) - {"name", "pattern", "from"})
        if unknown:
            raise _fail(path, where, f"unknown key(s): {', '.join(unknown)}")
        capture_name = spec.get("name")
        if not isinstance(capture_name, str) or not _NAME.match(capture_name):
            raise _fail(
                path, where, "'extract.name' must match [A-Za-z_][A-Za-z0-9_]*"
            )
        pattern = spec.get("pattern")
        if not isinstance(pattern, str) or not pattern:
            raise _fail(path, where, "'extract.pattern' must be a regex string")
        try:
            re.compile(pattern)
        except re.error as exc:
            raise _fail(path, where, f"bad regex: {exc}") from exc
        origin = spec.get("from", "body")
        if not isinstance(origin, str) or not (
            origin in ("body", "set-cookie")
            or (origin.startswith("header:") and len(origin) > len("header:"))
        ):
            raise _fail(
                path, where,
                "'extract.from' must be 'body', 'set-cookie' or 'header:NAME'",
            )
    elif action == "set_header":
        if not isinstance(target, dict) or not target:
            raise _fail(path, where, "'set_header' must be a non-empty object")
        for key, value in target.items():
            if not isinstance(key, str) or not _HEADER_NAME.match(key):
                raise _fail(path, where, f"bad header name {key!r}")
            if not isinstance(value, str):
                raise _fail(path, where, f"header {key!r} value must be a string")
    if "expect" in step:
        _validate_expect(path, where, step["expect"])
    return step


def _validate_expect(path: str, where: str, expect: object) -> None:
    if not isinstance(expect, dict) or not expect:
        raise _fail(path, where, "'expect' must be a non-empty object")
    unknown = sorted(set(expect) - {"status", "body_contains", "cookie"})
    if unknown:
        raise _fail(path, where, f"unknown expect key(s): {', '.join(unknown)}")
    if "status" in expect:
        statuses = expect["status"]
        values = statuses if isinstance(statuses, list) else [statuses]
        if not values or not all(
            isinstance(code, int) and not isinstance(code, bool)
            and 100 <= code <= 599
            for code in values
        ):
            raise _fail(
                path, where, "'expect.status' must be a status code or list"
            )
    if "body_contains" in expect:
        needles = expect["body_contains"]
        values = needles if isinstance(needles, list) else [needles]
        if not values or not all(
            isinstance(item, str) and item for item in values
        ):
            raise _fail(
                path, where, "'expect.body_contains' must be a string or list"
            )
    if "cookie" in expect:
        cookie = expect["cookie"]
        if not isinstance(cookie, str) or not cookie:
            raise _fail(path, where, "'expect.cookie' must be a cookie name")


def _substitute(
    value: str,
    captures: Mapping[str, str],
    env: Mapping[str, str],
    where: str,
) -> str:
    """Expand ``${ENV}`` (environment) then ``$capture`` (extract results)."""

    def env_repl(match: "re.Match[str]") -> str:
        key = match.group(1)
        if key not in env:
            raise FlowRunError(
                f"{where}: environment variable {key} is not set"
            )
        return str(env[key])

    def capture_repl(match: "re.Match[str]") -> str:
        key = match.group(1)
        if key not in captures:
            raise FlowRunError(f"{where}: capture {key!r} is not set")
        return captures[key]

    return _CAPTURE.sub(capture_repl, _ENV.sub(env_repl, value))


def _raw_set_cookies(response) -> List[str]:
    single = response.headers.get("set-cookie")
    return [single] if single else []


def _jar_cookie_names(client) -> set:
    jar = getattr(client, "cookie_jar", None)
    if jar is None:
        return set()
    try:
        return {cookie.name for cookie in jar}
    except Exception:  # pragma: no cover - defensive
        return set()


def _cookie_header(client, local: Mapping[str, str]) -> str:
    jar = getattr(client, "cookie_jar", None)
    if jar is not None:
        pairs = [
            (cookie.name, cookie.value)
            for cookie in jar
            if cookie.value is not None
        ]
        if pairs:
            return "; ".join(f"{name}={value}" for name, value in pairs)
    return "; ".join(f"{name}={value}" for name, value in local.items())


def _check_expect(
    expect: Mapping[str, object],
    response,
    client,
    local_cookies: Mapping[str, str],
    captures: Mapping[str, str],
    env: Mapping[str, str],
    where: str,
) -> None:
    if "status" in expect:
        wanted = expect["status"]
        wanted_list = wanted if isinstance(wanted, list) else [wanted]
        if response.status not in wanted_list:
            raise FlowRunError(
                f"{where}: expected status {wanted_list}, got {response.status}"
            )
    if "body_contains" in expect:
        needles = expect["body_contains"]
        for needle in needles if isinstance(needles, list) else [needles]:
            resolved = _substitute(str(needle), captures, env, where)
            if resolved not in response.text:
                raise FlowRunError(
                    f"{where}: expected response body to contain {resolved!r}"
                )
    if "cookie" in expect:
        name = _substitute(str(expect["cookie"]), captures, env, where)
        if name not in local_cookies and name not in _jar_cookie_names(client):
            raise FlowRunError(f"{where}: expected cookie {name!r} to be set")


def run_flow(
    client,
    flow: Flow,
    base_url: str,
    *,
    env: Optional[Mapping[str, str]] = None,
) -> Dict[str, str]:
    """Execute a flow; return the resulting auth headers (values in memory).

    Raises :class:`FlowRunError` when a step fails — callers surface it as a
    hard stage failure so a broken login never continues silently.
    """
    env_map = os.environ if env is None else env
    captures: Dict[str, str] = {}
    local_cookies: Dict[str, str] = {}
    out_headers: Dict[str, str] = {}
    last = None
    base = urllib.parse.urlsplit(str(base_url))
    origin = f"{base.scheme}://{base.netloc}"
    for index, step in enumerate(flow.steps, 1):
        where = f"--auth-script: {flow.source}: step {index}"
        action = next(key for key in step if key in _ACTIONS)
        if action == "extract":
            if last is None:
                raise FlowRunError(f"{where}: extract needs a preceding request")
            spec = step["extract"]
            origin_kind = spec.get("from", "body")
            if origin_kind == "body":
                haystack = last.text
            elif origin_kind == "set-cookie":
                haystack = "\n".join(_raw_set_cookies(last))
            else:
                haystack = last.headers.get(
                    origin_kind[len("header:"):].lower(), ""
                )
            match = re.search(spec["pattern"], haystack)
            if match is None:
                raise FlowRunError(
                    f"{where}: pattern for {spec['name']!r} not found"
                )
            captures[spec["name"]] = (
                match.group(1) if match.groups() else match.group(0)
            )
            continue
        if action == "set_header":
            for name, value in step["set_header"].items():
                out_headers[name] = _substitute(value, captures, env_map, where)
            continue
        target = _substitute(step[action], captures, env_map, where)
        if "://" in target:
            url = target
        else:
            url = origin + (target if target.startswith("/") else f"/{target}")
        request_headers = dict(out_headers)
        data = None
        if action == "post":
            form = step.get("form") or {}
            payload = {
                key: _substitute(value, captures, env_map, where)
                for key, value in form.items()
            }
            data = urllib.parse.urlencode(payload).encode("utf-8")
            request_headers.setdefault(
                "Content-Type", "application/x-www-form-urlencoded"
            )
        try:
            # record=False: login bodies and form values can hold secrets and
            # must never land in evidence (§8.5)
            response = client.request(
                "POST" if action == "post" else "GET",
                url,
                data=data,
                headers=request_headers,
                record=False,
            )
        except (ScopeRefused, BudgetExhausted, InertVerbRefused) as exc:
            raise FlowRunError(f"{where}: {type(exc).__name__}: {exc}") from exc
        last = response
        for single in _raw_set_cookies(response):
            pair = single.split(";", 1)[0]
            name, sep, value = pair.partition("=")
            if sep and name.strip():
                local_cookies[name.strip()] = value.strip()
        if response.error:
            raise FlowRunError(f"{where}: {response.error}")
        if "expect" in step:
            _check_expect(
                step["expect"], response, client, local_cookies,
                captures, env_map, where,
            )
    result = dict(out_headers)
    cookie_header = _cookie_header(client, local_cookies)
    if cookie_header:
        existing = next(
            (key for key in result if key.lower() == "cookie"), None
        )
        if existing is not None:
            result[existing] = f"{result[existing]}; {cookie_header}"
        else:
            result["Cookie"] = cookie_header
    return result
