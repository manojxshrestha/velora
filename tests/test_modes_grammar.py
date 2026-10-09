"""Tests for the three-mode stage framework (finalplan §8)."""

from types import SimpleNamespace

import argparse
import pytest

from velora.modes.common import (
    CANONICAL_ORDER,
    EXIT_FINDINGS,
    EXIT_USAGE,
    GrammarError,
    GrammarOptions,
    InputState,
    MODE_SPECS,
    StageSelection,
    add_stage_flags,
    check_dynamic_inputs,
    gate_exit_code,
    grammar_options_from_ns,
    resolve_severity_flags,
    select_stages,
)

WHITEBOX = MODE_SPECS["whitebox"]
BLACKBOX = MODE_SPECS["blackbox"]
BUGHUNT = MODE_SPECS["bughunt"]


def sel(mode, opts, session_ok=False, **inputs):
    return select_stages(mode, opts, InputState(**inputs), session_ok=session_ok)


def raises_code(mode, opts, code, session_ok=False, **inputs):
    with pytest.raises(GrammarError) as exc:
        sel(mode, opts, session_ok=session_ok, **inputs)
    assert exc.value.code == code, exc.value.message
    return exc.value


class TestRegistry:
    def test_pipelines_match_membership(self):
        for mode in MODE_SPECS.values():
            defaults = [s for s in mode.stages if mode.membership[s] == "default"]
            assert tuple(defaults) == mode.pipeline

    def test_pipeline_counts(self):
        assert len(WHITEBOX.pipeline) == 15
        assert len(BLACKBOX.pipeline) == 14
        assert len(BUGHUNT.pipeline) == 16

    def test_membership_matches_matrix(self):
        assert set(WHITEBOX.unavailable) == {"auth", "intel", "osint"}
        assert set(BLACKBOX.unavailable) == {"ingest", "code-model", "static-scan", "dataflow"}
        assert set(BUGHUNT.unavailable) == {"asset-discovery", "service-mapping"}

    def test_off_default_membership(self):
        off = {s for s in WHITEBOX.stages if WHITEBOX.membership[s] == "off"}
        assert off == {"recon", "surface", "enumerate", "hunt", "deepthink", "capture", "search"}
        off = {s for s in BLACKBOX.stages if BLACKBOX.membership[s] == "off"}
        assert off == {"intel", "osint", "asset-model", "hypothesize", "deepthink",
                       "plan", "fix", "rescan", "search"}

    def test_pipelines_are_canonical_subsequences(self):
        pos = {s: i for i, s in enumerate(CANONICAL_ORDER)}
        for mode in MODE_SPECS.values():
            positions = [pos[s] for s in mode.pipeline]
            assert positions == sorted(positions), mode.id

    def test_scope_is_guard_without_flags(self):
        p = argparse.ArgumentParser()
        sub = p.add_subparsers(dest="mode")
        sp = sub.add_parser("whitebox")
        add_stage_flags(sp, WHITEBOX)
        assert not any("--scope" in a.option_strings for a in sp._actions)

    def test_all_selectable_stages_have_flags(self):
        p = argparse.ArgumentParser()
        sub = p.add_subparsers(dest="mode")
        sp = sub.add_parser("blackbox")
        add_stage_flags(sp, BLACKBOX)
        flags = {o for a in sp._actions for o in a.option_strings}
        assert "--scan" in flags
        assert "--asset-discovery" in flags
        assert "--with-fix" in flags
        assert "--no-exploit" in flags


class TestLevel1Defaults:
    def test_whitebox_source_only_truncates_exploit(self):
        s = sel(WHITEBOX, GrammarOptions(), source="src")
        assert s.plan == [x for x in WHITEBOX.pipeline if x != "exploit"]
        assert s.na == ["exploit"]
        assert s.conditional == ["fix", "rescan", "validate"]

    def test_whitebox_source_only_reaches_report(self):
        s = sel(WHITEBOX, GrammarOptions(), source="src")
        assert "report" in s.plan
        assert "report" not in s.na

    def test_whitebox_with_target_runs_exploit(self):
        s = sel(WHITEBOX, GrammarOptions(), source="src", target="https://x")
        assert "exploit" in s.plan
        assert "exploit" not in s.na

    def test_blackbox_default(self):
        s = sel(BLACKBOX, GrammarOptions(), target="https://x")
        assert s.plan == list(BLACKBOX.pipeline)
        assert not s.na

    def test_bughunt_source_only(self):
        s = sel(BUGHUNT, GrammarOptions(), source="src")
        assert set(s.na) == {"auth", "intel", "osint", "recon", "exploit"}
        assert "report" in s.plan
        assert "asset-model" in s.plan
        assert "surface" in s.plan

    def test_bughunt_target_only(self):
        s = sel(BUGHUNT, GrammarOptions(), target="https://x")
        assert s.na == []
        assert "ingest" not in s.plan
        assert "exploit" in s.plan


class TestRule1Conflicts:
    def test_positive_conflicts_with_skip(self):
        raises_code(WHITEBOX, GrammarOptions(positive=("static-scan",), skip=("fix",)), EXIT_USAGE)

    def test_positive_conflicts_with_only(self):
        raises_code(WHITEBOX, GrammarOptions(positive=("scan",), only=("triage",)), EXIT_USAGE)

    def test_positive_conflicts_with_ranges_and_with(self):
        for opts in (
            GrammarOptions(positive=("scan",), until="triage"),
            GrammarOptions(positive=("scan",), from_="triage"),
            GrammarOptions(positive=("scan",), with_=("fix",)),
        ):
            raises_code(WHITEBOX, opts, EXIT_USAGE)

    def test_with_combines_with_ranges(self):
        s = sel(BLACKBOX, GrammarOptions(until="surface", with_=("fix",)), target="t")
        assert s.plan == ["scope", "auth", "recon", "asset-discovery", "surface", "fix"]


class TestRule2FromSession:
    def test_without_session_exits_1(self):
        err = raises_code(BLACKBOX, GrammarOptions(from_="recon"), EXIT_FINDINGS, target="t")
        assert "session" in err.message
        assert "--dry-run" in err.message

    def test_with_session_resumes(self):
        s = sel(BLACKBOX, GrammarOptions(from_="surface"), session_ok=True, target="t")
        assert s.plan[0] == "surface"
        assert "scope" not in s.plan


class TestRule3InvalidStage:
    def test_not_in_union_exits_2_with_valid_list(self):
        err = raises_code(WHITEBOX, GrammarOptions(only=("asset-discovery",)), EXIT_USAGE)
        assert "not a stage of mode 'whitebox'" in err.message
        assert "valid stages" in err.message
        assert "scan" in err.message

    def test_guard_not_selectable(self):
        err = raises_code(WHITEBOX, GrammarOptions(only=("scope",)), EXIT_USAGE)
        assert "guard" in err.message

    def test_skip_invalid_stage(self):
        raises_code(BLACKBOX, GrammarOptions(skip=("not-a-stage",)), EXIT_USAGE, target="t")


class TestRule4Unavailable:
    def test_whitebox_auth(self):
        err = raises_code(WHITEBOX, GrammarOptions(positive=("auth",)), EXIT_USAGE, source="s")
        assert "unavailable" in err.message
        assert "'network'" in err.message or "asset kind" in err.message

    def test_bughunt_service_mapping(self):
        err = raises_code(
            BUGHUNT, GrammarOptions(only=("service-mapping",)), EXIT_USAGE,
            source="s", target="t",
        )
        assert "unavailable" in err.message
        assert "service-mapping" in err.message

    def test_blackbox_code_model(self):
        err = raises_code(BLACKBOX, GrammarOptions(only=("code-model",)), EXIT_USAGE, target="t")
        assert "'code'" in err.message

    def test_unavailable_never_silent(self):
        for stage in WHITEBOX.unavailable:
            raises_code(WHITEBOX, GrammarOptions(positive=(stage,)), EXIT_USAGE, source="s")


class TestRule5MissingInput:
    def test_exploit_without_target(self):
        err = raises_code(WHITEBOX, GrammarOptions(positive=("exploit",)), EXIT_FINDINGS, source="s")
        assert "target" in err.message

    def test_hypothesize_without_source_or_target(self):
        err = raises_code(BUGHUNT, GrammarOptions(positive=("hypothesize",)), EXIT_FINDINGS)
        assert "--source" in err.message
        assert "target" in err.message

    def test_recon_without_target_in_whitebox(self):
        raises_code(WHITEBOX, GrammarOptions(positive=("recon",)), EXIT_FINDINGS, source="s")

    def test_explicit_never_na(self):
        raises_code(
            WHITEBOX, GrammarOptions(positive=("exploit", "report")), EXIT_FINDINGS, source="s"
        )

    def test_dynamic_findings_gate(self):
        with pytest.raises(GrammarError) as exc:
            check_dynamic_inputs(
                WHITEBOX,
                StageSelection(plan=["fix"], explicit=["fix"]),
                InputState(source="s", findings=0),
            )
        assert exc.value.code == EXIT_FINDINGS

    def test_dynamic_findings_gate_passes(self):
        check_dynamic_inputs(
            WHITEBOX,
            StageSelection(plan=["fix"], explicit=["fix"]),
            InputState(source="s", findings=2),
        )


class TestTokenTranslation:
    def test_flag_names_resolve_to_stage_ids(self):
        ns = SimpleNamespace(
            only="scan,triage", skip="exploit", until="surface", from_=None,
            **{f"stage_{s.replace('-', '_')}": False for s in CANONICAL_ORDER},
        )
        opts = grammar_options_from_ns(ns, WHITEBOX)
        assert opts.only == ("static-scan", "triage")
        assert opts.skip == ("exploit",)
        assert opts.until == "surface"


class TestLevel2Ranges:
    def test_until_blackbox(self):
        s = sel(BLACKBOX, GrammarOptions(until="surface"), target="https://x")
        assert s.plan == ["scope", "auth", "recon", "asset-discovery", "surface"]

    def test_only_canonical_order_ignores_user_order(self):
        s = sel(BLACKBOX, GrammarOptions(only=("verify", "recon", "hunt")), target="t")
        assert s.plan == ["recon", "hunt", "verify"]

    def test_only_single_stage(self):
        s = sel(WHITEBOX, GrammarOptions(only=("scan",)), source="src")
        assert s.plan == ["static-scan"]


class TestLevel3ExactLists:
    def test_whitebox_static_only(self):
        s = sel(WHITEBOX, GrammarOptions(positive=("static-scan", "triage")), source="src")
        assert s.plan == ["static-scan", "triage"]

    def test_whitebox_fix_tail(self):
        s = sel(WHITEBOX, GrammarOptions(positive=("fix", "rescan")), source="src")
        assert s.plan == ["fix", "rescan"]

    def test_blackbox_surface_trio(self):
        s = sel(
            BLACKBOX,
            GrammarOptions(positive=("recon", "surface", "enumerate")),
            target="https://x",
        )
        assert s.plan == ["recon", "surface", "enumerate"]

    def test_bughunt_aimed_hunt(self):
        s = sel(
            BUGHUNT,
            GrammarOptions(positive=("hunt", "deepthink", "verify", "validate")),
            source="s", target="https://x",
        )
        assert s.plan == ["hunt", "deepthink", "verify", "validate"]


class TestNegativeFlags:
    def test_no_flags_shape_default(self):
        s = sel(WHITEBOX, GrammarOptions(no=("exploit", "validate")), source="src")
        assert "exploit" not in s.plan
        assert "validate" not in s.plan
        assert "report" in s.plan

    def test_skip_equals_no_flags(self):
        a = sel(WHITEBOX, GrammarOptions(no=("exploit", "validate")), source="src")
        b = sel(WHITEBOX, GrammarOptions(skip=("exploit", "validate")), source="src")
        assert a.plan == b.plan


class TestArgparseIntegration:
    def _parser(self, mode):
        p = argparse.ArgumentParser()
        sub = p.add_subparsers(dest="mode")
        sp = sub.add_parser(mode.id)
        add_stage_flags(sp, mode)
        return p, sp

    def test_positive_flags(self):
        _, sp = self._parser(WHITEBOX)
        ns = sp.parse_args(["--scan", "--triage", "--dry-run"])
        opts = grammar_options_from_ns(ns, WHITEBOX)
        assert opts.positive == ("static-scan", "triage")
        assert ns.dry_run is True

    def test_empty_args(self):
        _, sp = self._parser(WHITEBOX)
        ns = sp.parse_args([])
        opts = grammar_options_from_ns(ns, WHITEBOX)
        assert opts.positive == ()
        assert opts.only is None
        assert opts.until is None

    def test_with_and_no_flags(self):
        _, sp = self._parser(BLACKBOX)
        ns = sp.parse_args(["--with-fix", "--no-hunt"])
        opts = grammar_options_from_ns(ns, BLACKBOX)
        assert opts.with_ == ("fix",)
        assert opts.no == ("hunt",)


class TestSeverityGate:
    def test_severity_sugar_sets_both(self):
        args = SimpleNamespace(severity="critical", min_severity=None, fail_on=None)
        resolve_severity_flags(args)
        assert args.min_severity == "critical"
        assert args.fail_on == "critical"

    def test_explicit_fail_on_not_overridden(self):
        args = SimpleNamespace(severity="medium", min_severity=None, fail_on="high")
        resolve_severity_flags(args)
        assert args.min_severity == "medium"
        assert args.fail_on == "high"

    def test_fail_on_defaults_to_high(self):
        args = SimpleNamespace(severity=None, min_severity=None, fail_on=None)
        resolve_severity_flags(args)
        assert args.fail_on == "high"
        assert args.min_severity is None

    class F:
        def __init__(self, severity):
            self.severity = severity

    def test_gate_triggers(self):
        findings = [self.F("low"), self.F("critical")]
        assert gate_exit_code(findings, "high") == EXIT_FINDINGS

    def test_gate_silent(self):
        findings = [self.F("low"), self.F("medium")]
        assert gate_exit_code(findings, "high") == 0

    def test_gate_findings_with_dict(self):
        assert gate_exit_code([{"severity": "high"}], "high") == EXIT_FINDINGS
        assert gate_exit_code([], "high") == 0
