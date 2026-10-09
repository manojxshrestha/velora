"""Session dirs, crash-safe stage commits, resume (finalplan §8.5).

Layout under the session dir (default `.velora/<mode>-<hash>`):

    session.json    completed stages, budgets spent, inputs resolved
    assets.json     ASSET MODEL output
    surface.json    SURFACE view + enumeration data
    findings.json   append/update contract for every stage
    hypotheses.json bughunt ledger
    trace.json      agent transcripts (CAPTURE)
    report.md       REPORT output (also -o FILE)
    session.lock    in-use marker; second writer refuses (exit 1)

A stage's outputs are committed atomically *before* the next stage starts,
so `--from` and `resume` are always safe. Secrets (header values, tokens)
are stored as references only, never as values.
"""

from __future__ import annotations

import hashlib
import json
import os
import time
from pathlib import Path
from typing import Dict, List, Optional

from velora.modes.common import (
    EXIT_FINDINGS,
    GrammarError,
    InputState,
    ModeSpec,
)

SCHEMA_VERSION = 1
SESSION_ENV = "VELORA_SESSION"
LOCK_NAME = "session.lock"
SESSION_JSON = "session.json"

ARTIFACT_FILES = (
    "assets.json",
    "surface.json",
    "findings.json",
    "hypotheses.json",
    "trace.json",
    "report.md",
)


def _normalize_target(target: Optional[str]) -> str:
    if not target:
        return ""
    value = target.strip()
    while value.endswith("/"):
        value = value[:-1]
    return value


def session_hash(
    mode: str,
    inputs: InputState,
    scope: Optional[List[str]] = None,
) -> str:
    source = os.path.abspath(inputs.source) if inputs.source else ""
    payload = json.dumps(
        {
            "mode": mode,
            "target": _normalize_target(inputs.target),
            "source": source,
            "scope": sorted(scope or []),
        },
        sort_keys=True,
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()[:12]


def default_session_dir(
    mode: str,
    inputs: InputState,
    scope: Optional[List[str]] = None,
) -> Path:
    return Path(".velora") / f"{mode}-{session_hash(mode, inputs, scope)}"


def _mode_input_satisfied(mode: ModeSpec, inputs: InputState) -> bool:
    dep = mode.mode_input_dep
    if dep == "source":
        return inputs.has_source
    if dep == "target":
        return inputs.has_target
    return inputs.has_source or inputs.has_target


def resolve_session_path(
    args,
    mode: ModeSpec,
    inputs: InputState,
    scope: Optional[List[str]] = None,
) -> Optional[Path]:
    explicit = getattr(args, "session", None) or os.environ.get(SESSION_ENV)
    if explicit:
        return Path(explicit)
    if not _mode_input_satisfied(mode, inputs):
        return None
    return default_session_dir(mode.id, inputs, scope)


def _atomic_write(path: Path, data: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text(data, encoding="utf-8")
    os.replace(tmp, path)


def _pid_alive(pid: int) -> bool:
    if pid <= 0:
        return False
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


class Session:
    def __init__(self, path: Path):
        self.path = Path(path)
        self.data: Dict = {}
        self._locked_by_me = False

    # -- lifecycle -------------------------------------------------------

    @classmethod
    def open(cls, path: Optional[Path]) -> Optional["Session"]:
        if path is None:
            return None
        session = cls(path)
        meta = session.path / SESSION_JSON
        if meta.is_file():
            try:
                session.data = json.loads(meta.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError) as exc:
                raise GrammarError(
                    EXIT_FINDINGS,
                    f"session is unreadable ({meta}: {exc}) — pass a "
                    f"different --session or delete the directory",
                )
        return session

    @property
    def exists(self) -> bool:
        return (self.path / SESSION_JSON).is_file()

    def completed_stages(self) -> List[str]:
        return [c.get("stage", "") for c in self.data.get("completed", [])]

    def has_completed(self) -> bool:
        return bool(self.completed_stages())

    def load_inputs(self) -> InputState:
        stored = self.data.get("inputs", {}) or {}
        return InputState(
            source=stored.get("source") or None,
            target=stored.get("target") or None,
        )

    def merge_inputs(self, cli_inputs: InputState) -> InputState:
        stored = self.load_inputs()
        return InputState(
            source=cli_inputs.source or stored.source,
            target=cli_inputs.target or stored.target,
        )

    # -- locking ---------------------------------------------------------

    def acquire_lock(self) -> None:
        self.path.mkdir(parents=True, exist_ok=True)
        lock = self.path / LOCK_NAME
        for attempt in (0, 1):
            try:
                fd = os.open(str(lock), os.O_CREAT | os.O_EXCL | os.O_WRONLY)
                with os.fdopen(fd, "w", encoding="utf-8") as handle:
                    handle.write(str(os.getpid()))
                self._locked_by_me = True
                return
            except FileExistsError:
                try:
                    holder = int(lock.read_text(encoding="utf-8").strip() or "0")
                except (OSError, ValueError):
                    holder = 0
                if holder and _pid_alive(holder):
                    if attempt == 0:
                        time.sleep(0.05)
                        continue
                    raise GrammarError(
                        EXIT_FINDINGS,
                        f"session in use (pid {holder}): {self.path} — "
                        f"wait for it or pass a different --session",
                    )
                try:
                    lock.unlink()
                except OSError:
                    pass
        raise GrammarError(
            EXIT_FINDINGS, f"could not lock session: {self.path}"
        )

    def release_lock(self) -> None:
        if not self._locked_by_me:
            return
        lock = self.path / LOCK_NAME
        try:
            if lock.is_file() and lock.read_text(encoding="utf-8").strip() == str(
                os.getpid()
            ):
                lock.unlink()
        except OSError:
            pass
        self._locked_by_me = False

    # -- commits ---------------------------------------------------------

    def _write_meta(self) -> None:
        self.data["schema_version"] = SCHEMA_VERSION
        self.data["updated_at"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        _atomic_write(self.path / SESSION_JSON, json.dumps(self.data, indent=2))

    def _ensure_meta(self, mode: ModeSpec, inputs: InputState) -> None:
        if not self.data:
            self.data = {
                "schema_version": SCHEMA_VERSION,
                "mode": mode.id,
                "created_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "inputs": {
                    "source": inputs.source,
                    "target": inputs.target,
                },
                "completed": [],
                "na": [],
                "budgets": {"spent": 0},
                "secrets": [],
            }

    def record_inputs(self, mode: ModeSpec, inputs: InputState) -> None:
        self._ensure_meta(mode, inputs)
        stored = self.data.setdefault("inputs", {})
        stored["source"] = inputs.source or stored.get("source")
        stored["target"] = inputs.target or stored.get("target")
        self._write_meta()

    def record_na(self, mode: ModeSpec, inputs: InputState, stages: List[str]) -> None:
        self._ensure_meta(mode, inputs)
        self.data["na"] = list(stages)
        self._write_meta()

    def record_secret_ref(self, kind: str, name: str, ref: str) -> None:
        secrets = self.data.setdefault("secrets", [])
        entry = {"kind": kind, "name": name, "ref": ref}
        if entry not in secrets:
            secrets.append(entry)
            self._write_meta()

    def commit_stage(
        self,
        mode: ModeSpec,
        inputs: InputState,
        stage: str,
        artifacts: Optional[Dict[str, object]] = None,
    ) -> None:
        """Commit one stage's outputs, then mark it completed (crash-safe).

        Artifact files land first (atomic replace), session.json second — a
        crash between the two leaves the stage uncommitted, which is safe.
        """
        self.path.mkdir(parents=True, exist_ok=True)
        self._ensure_meta(mode, inputs)
        for name, payload in (artifacts or {}).items():
            target = self.path / name
            if isinstance(payload, str):
                _atomic_write(target, payload)
            else:
                _atomic_write(target, json.dumps(payload, indent=2))
        already = self.completed_stages()
        if stage not in already:
            self.data.setdefault("completed", []).append(
                {"stage": stage, "at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}
            )
        self._write_meta()

    # -- artifact access -------------------------------------------------

    def read_json(self, name: str, default):
        path = self.path / name
        if not path.is_file():
            return default
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return default

    def append_findings(self, findings: List[dict]) -> List[dict]:
        existing = self.read_json("findings.json", [])
        if not isinstance(existing, list):
            existing = []
        seen = {self._finding_key(f) for f in existing}
        for finding in findings:
            key = self._finding_key(finding)
            if key in seen:
                continue
            seen.add(key)
            existing.append(finding)
        self.path.mkdir(parents=True, exist_ok=True)
        _atomic_write(self.path / "findings.json", json.dumps(existing, indent=2))
        return existing

    @staticmethod
    def _finding_key(finding: dict) -> str:
        return json.dumps(
            [
                finding.get("title") or finding.get("rule") or finding.get("description"),
                finding.get("file") or finding.get("path"),
                finding.get("line"),
                finding.get("parameter") or finding.get("param"),
            ],
            sort_keys=True,
        )
