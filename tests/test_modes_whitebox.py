"""End-to-end tests for the whitebox orchestrator (finalplan §4 / §8)."""

import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from velora.modes.common import EXIT_FINDINGS, EXIT_OK, EXIT_USAGE
from velora.modes.whitebox import run

CLEAN = "def add(a, b):\n    return a + b\n"

VULN = (
    "def vulnerable():\n"
    "    user_id = input()\n"
    '    query = "SELECT * FROM users WHERE id=" + user_id\n'
    "    cursor.execute(query)\n"
)


def make_args(source, session, **overrides):
    defaults = dict(
        source=str(source),
        target=None,
        session=str(session),
        format="text",
        output=None,
        severity=None,
        fail_on=None,
        min_severity=None,
        ai=False,
        guidance=None,
        goal=None,
        success_check=None,
        scope=None,
        scope_file=None,
        budget=None,
        trace_out=None,
        dry_run=False,
        list_stages=False,
        only=None,
        until=None,
        from_=None,
        skip=None,
        language=None,
        pattern=None,
        no_default_excludes=False,
        no_verify=True,
        llm_detect=False,
        llm_triage=False,
        repo_scale=False,
        timeout=None,
        context_lines=20,
        in_place=False,
        diff=False,
        max_steps=None,
        exec_timeout=None,
        verbose=False,
    )
    defaults.update(overrides)
    return SimpleNamespace(**defaults)


@pytest.fixture
def clean_repo(tmp_path):
    src = tmp_path / "src"
    src.mkdir()
    (src / "app.py").write_text(CLEAN)
    return src


@pytest.fixture
def vuln_repo(tmp_path):
    src = tmp_path / "src"
    src.mkdir()
    (src / "app.py").write_text(VULN)
    return src


def session_stages(session_path):
    data = json.loads((Path(session_path) / "session.json").read_text())
    return [c["stage"] for c in data["completed"]], data.get("na", [])


def json_vulns(payload):
    if "files" in payload:
        return [
            v for f in payload["files"] for v in f.get("vulnerabilities", [])
        ]
    return payload.get("vulnerabilities", [])


class TestCleanRun:
    def test_reaches_report_exit_0(self, clean_repo, tmp_path, capsys):
        session = tmp_path / "sess"
        code = run(make_args(clean_repo, session))
        assert code == EXIT_OK
        completed, na = session_stages(session)
        assert "report" in completed
        assert "static-scan" in completed
        assert (session / "report.md").exists()
        out = capsys.readouterr().out
        assert "No vulnerabilities found" in out

    def test_exploit_is_rule6_na_without_target(self, clean_repo, tmp_path, capsys):
        session = tmp_path / "sess"
        run(make_args(clean_repo, session))
        _, na = session_stages(session)
        assert "exploit" in na
        err = capsys.readouterr().err
        assert "EXPLOIT (missing a target" in err

    def test_finding_gated_stages_na_without_findings(
        self, clean_repo, tmp_path
    ):
        session = tmp_path / "sess"
        run(make_args(clean_repo, session))
        _, na = session_stages(session)
        assert "fix" in na
        assert "rescan" in na
        assert "validate" in na


class TestVulnerableRun:
    def test_gate_exits_1_and_records_everything(self, vuln_repo, tmp_path):
        session = tmp_path / "sess"
        code = run(make_args(vuln_repo, session))
        assert code == EXIT_FINDINGS
        findings = json.loads((session / "findings.json").read_text())
        assert len(findings) == 1
        assert findings[0]["type"] == "sql_injection"
        completed, na = session_stages(session)
        for stage in (
            "scope", "ingest", "asset-model", "code-model", "static-scan",
            "dataflow", "hypothesize", "triage", "plan", "verify",
            "validate", "report",
        ):
            assert stage in completed, stage
        assert "fix" in na
        assert "validate" not in na

    def test_fix_na_reason_is_ai_disabled(self, vuln_repo, tmp_path, capsys):
        session = tmp_path / "sess"
        run(make_args(vuln_repo, session))
        err = capsys.readouterr().err
        assert "FIX (AI stage disabled" in err

    def test_validate_reproduced(self, vuln_repo, tmp_path):
        session = tmp_path / "sess"
        run(make_args(vuln_repo, session))
        data = json.loads((session / "validate.json").read_text())
        assert data["checked"] == 1
        assert data["reproduced"] == 1

    def test_dataflow_found_taint(self, vuln_repo, tmp_path):
        session = tmp_path / "sess"
        run(make_args(vuln_repo, session))
        data = json.loads((session / "dataflow.json").read_text())
        assert data["findings_with_taint"] >= 1

    def test_hypothesis_opened(self, vuln_repo, tmp_path):
        session = tmp_path / "sess"
        run(make_args(vuln_repo, session))
        data = json.loads((session / "hypotheses.json").read_text())
        assert data["count"] == 1
        assert data["hypotheses"][0]["status"] == "open"

    def test_plan_writes_source_slices(self, vuln_repo, tmp_path):
        session = tmp_path / "sess"
        run(make_args(vuln_repo, session))
        guidance = json.loads((session / "guidance.json").read_text())
        assert guidance["leads"]
        slices = guidance["leads"][0]["source_slices"]
        assert slices
        assert slices[0]["center_line"] == 4
        assert "user_id" in slices[0]["text"]

    def test_plan_respects_context_lines(self, vuln_repo, tmp_path):
        session = tmp_path / "sess"
        run(make_args(vuln_repo, session, context_lines=1))
        guidance = json.loads((session / "guidance.json").read_text())
        text = guidance["leads"][0]["source_slices"][0]["text"]
        assert text.count("\n") <= 4


class TestResumeAndRerun:
    def test_rerun_skips_committed_but_rerenders_report(
        self, vuln_repo, tmp_path, capsys
    ):
        session = tmp_path / "sess"
        assert run(make_args(vuln_repo, session)) == EXIT_FINDINGS
        capsys.readouterr()
        assert run(make_args(vuln_repo, session)) == EXIT_FINDINGS
        captured = capsys.readouterr()
        assert "already committed" in captured.err
        assert "STATIC SCAN" in captured.err
        assert "Vulnerabilities Found" in captured.out

    def test_from_report_reruns_only_report(self, vuln_repo, tmp_path, capsys):
        session = tmp_path / "sess"
        run(make_args(vuln_repo, session))
        capsys.readouterr()
        code = run(make_args(vuln_repo, session, from_="report"))
        assert code == EXIT_FINDINGS
        err = capsys.readouterr().err
        assert "stage 1/1: REPORT" in err

    def test_from_report_without_session_exits_1(self, vuln_repo, tmp_path):
        code = run(make_args(vuln_repo, tmp_path / "missing", from_="report"))
        assert code == EXIT_FINDINGS


class TestGrammarExitCodes:
    def test_only_fix_without_findings_exits_1(
        self, clean_repo, tmp_path, capsys
    ):
        code = run(make_args(clean_repo, tmp_path / "sess", only="fix"))
        assert code == EXIT_FINDINGS
        assert "requires findings" in capsys.readouterr().err

    def test_exploit_without_target_exits_1(self, vuln_repo, tmp_path):
        code = run(make_args(vuln_repo, tmp_path / "sess", only="exploit"))
        assert code == EXIT_FINDINGS

    def test_missing_source_path_exits_1(self, tmp_path, capsys):
        code = run(make_args(tmp_path / "nope", tmp_path / "sess"))
        assert code == EXIT_FINDINGS
        assert "path not found" in capsys.readouterr().err

    def test_positive_flag_conflict_exits_2(self, vuln_repo, tmp_path):
        args = make_args(
            vuln_repo, tmp_path / "sess", stage_static_scan=True,
            skip="triage",
        )
        assert run(args) == EXIT_USAGE

    def test_invalid_stage_exits_2(self, vuln_repo, tmp_path, capsys):
        code = run(
            make_args(vuln_repo, tmp_path / "sess", only="not-a-stage")
        )
        assert code == EXIT_USAGE
        assert "not a stage" in capsys.readouterr().err


class TestOutputFormats:
    def test_json_format_on_fresh_run(self, vuln_repo, tmp_path, capsys):
        code = run(
            make_args(
                vuln_repo, tmp_path / "sess", format="json", fail_on="none",
            )
        )
        assert code == EXIT_OK
        payload = json.loads(capsys.readouterr().out)
        assert json_vulns(payload)

    def test_json_format_on_rerun_uses_session_results(
        self, vuln_repo, tmp_path, capsys
    ):
        session = tmp_path / "sess"
        run(make_args(vuln_repo, session))
        capsys.readouterr()
        code = run(
            make_args(
                vuln_repo, session, format="json", fail_on="none",
            )
        )
        assert code == EXIT_OK
        payload = json.loads(capsys.readouterr().out)
        assert json_vulns(payload)[0]["type"] == "sql_injection"

    def test_output_file_written(self, vuln_repo, tmp_path, capsys):
        out = tmp_path / "report.txt"
        run(make_args(vuln_repo, tmp_path / "sess", output=str(out),
                      fail_on="none"))
        assert "Vulnerabilities Found" in out.read_text()
        assert capsys.readouterr().out == ""

    def test_severity_sugar_and_explicit_fail_on_precedence(
        self, vuln_repo, tmp_path
    ):
        code = run(make_args(vuln_repo, tmp_path / "s1", severity="critical"))
        assert code == EXIT_FINDINGS
        code = run(
            make_args(
                vuln_repo, tmp_path / "s2", severity="critical",
                fail_on="none",
            )
        )
        assert code == EXIT_OK


class TestSessionArtifacts:
    def test_all_expected_artifacts_written(self, vuln_repo, tmp_path):
        session = tmp_path / "sess"
        run(make_args(vuln_repo, session))
        for name in (
            "session.json", "scope.json", "assets.json", "code-model.json",
            "scan-results.json", "findings.json", "dataflow.json",
            "hypotheses.json", "triage.json", "guidance.json", "verify.json",
            "validate.json", "report.md",
        ):
            assert (session / name).exists(), name

    def test_assets_graph_has_symbols(self, vuln_repo, tmp_path):
        session = tmp_path / "sess"
        run(make_args(vuln_repo, session))
        assets = json.loads((session / "assets.json").read_text())
        kinds = {n["kind"] for n in assets["nodes"]}
        assert "file" in kinds
        assert "code_symbol" in kinds

    def test_ingest_manifest_and_iac_assets(self, vuln_repo, tmp_path, capsys):
        (vuln_repo / "requirements.txt").write_text("flask==2.0.1\n")
        (vuln_repo / "Dockerfile").write_text("FROM python:3.12-slim\n")
        session = tmp_path / "sess"
        run(make_args(vuln_repo, session))
        assets = json.loads((session / "assets.json").read_text())
        by_kind = {}
        for node in assets["nodes"]:
            by_kind.setdefault(node["kind"], []).append(node)
        deps = by_kind.get("dependency", [])
        assert any(d["props"]["name"] == "flask" and
                   d["props"]["version"] == "==2.0.1" for d in deps)
        assert any(w["label"] == "python:3.12-slim"
                   for w in by_kind.get("workload", []))
        assert any(e["kind"] == "depends_on" for e in assets["edges"])
        err = capsys.readouterr().err
        assert "ingest: containers=1, dependencies=1" in err

    def test_verify_records_proof_kind(self, vuln_repo, tmp_path):
        session = tmp_path / "sess"
        run(make_args(vuln_repo, session))
        verify = json.loads((session / "verify.json").read_text())
        assert verify["proofs"]
        assert verify["proofs"][0]["proof"] in (
            "z3-witness", "taint-proven", "pending",
        )

    def test_scope_records_hosts(self, vuln_repo, tmp_path):
        session = tmp_path / "sess"
        run(
            make_args(
                vuln_repo, session,
                scope=["a.example", "a.example", "b.example"],
            )
        )
        scope = json.loads((session / "scope.json").read_text())
        assert scope["hosts"] == ["a.example", "b.example"]
