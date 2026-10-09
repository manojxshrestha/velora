"""Hypothesis engine units: falsifiability gate + elimination ledger (§10)."""

import json

import pytest

from velora.sil.hypotheses import (
    SCHEMA_VERSION,
    derive_from_finding,
    empty_ledger,
    fingerprint,
    load_seed_file,
    merge_entries,
    next_id,
    normalize_ledger,
    recount,
    set_verdicts,
    validate_hypothesis,
)


# ---------------------------------------------------------------------------
# validate_hypothesis: vague claims must die at ingest
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("claim", [
    "there might be a security issue here",
    "the login form could be insecure somehow",
    "something seems off about the token handling",
    "this endpoint is not secure",
    "maybe the payment flow has some issues",
    "i think there is a potential problem with auth",
    "kind of broken and unclear",
    "",
])
def test_vague_claims_are_rejected(claim):
    errors = validate_hypothesis({"claim": claim, "location": "/x"})
    assert errors, claim


def test_vague_rejection_names_the_phrase():
    errors = validate_hypothesis(
        {"claim": "there might be a security issue somewhere on the login"}
    )
    assert any("vague wording" in e for e in errors)


def test_short_claim_rejected():
    errors = validate_hypothesis({"claim": "xss here", "location": "/a"})
    assert any("too short" in e for e in errors)


def test_long_claim_rejected():
    claim = "the endpoint reflects input " * 40  # > 600 chars
    errors = validate_hypothesis({"claim": claim, "location": "/a"})
    assert any("too long" in e for e in errors)


def test_no_subject_rejected():
    errors = validate_hypothesis(
        {"claim": "an attacker injects script and executes it reliably "
                  "during playback of the response"}
    )
    assert any("subject" in e for e in errors)


def test_no_assertion_rejected():
    errors = validate_hypothesis(
        {"claim": "the /admin endpoint listing", "location": "/admin"}
    )
    assert any("assertion" in e for e in errors)


def test_falsifier_can_stand_in_for_assertion():
    errors = validate_hypothesis({
        "claim": "the /admin endpoint exposes the user table",
        "location": "/admin",
        "falsifier": "a read of /admin returns 403 for anon callers",
    })
    assert errors == []


def test_concrete_claim_accepted():
    errors = validate_hypothesis({
        "claim": "GET /search?q reflects unencoded into HTML, so an "
                 "attacker injects script through q (CWE-79)",
        "location": "/search",
    })
    assert errors == []


def test_bare_string_claim_supported():
    assert validate_hypothesis(
        "GET /search?q reflects unencoded into HTML so an attacker "
        "injects script through q"
    ) == []


# ---------------------------------------------------------------------------
# Fingerprints: stable identity for elimination memory
# ---------------------------------------------------------------------------

def test_fingerprint_stable_across_case_and_spacing():
    a = fingerprint({"claim": "the /api token is  leaked   to logs!",
                     "location": "/api"})
    b = fingerprint({"claim": "The /api token is leaked to logs!",
                     "location": "/api"})
    assert a == b
    assert a.startswith("H") and len(a) == 13


def test_fingerprint_differs_by_subject():
    claim = "an attacker injects script through the q parameter reliably"
    a = fingerprint({"claim": claim, "location": "/search"})
    b = fingerprint({"claim": claim, "location": "/login"})
    assert a != b


def test_derive_from_finding_is_valid_and_deterministic():
    finding = {
        "type": "reflected-input-unencoded",
        "location": "http://127.0.0.1:8080/search",
        "parameter": "q",
        "cwe_id": "79",
    }
    first = derive_from_finding(finding, 1)
    second = derive_from_finding(finding, 99)
    assert validate_hypothesis(first) == []
    assert first["fingerprint"] == second["fingerprint"]
    assert first["status"] == "open"
    assert "falsifier" in first and first["based_on"]["location"]


# ---------------------------------------------------------------------------
# merge_entries: dedupe, reject, never re-derive
# ---------------------------------------------------------------------------

def _claim(text, subject="/s"):
    return {"claim": text, "location": subject}


def test_merge_adds_then_skips_duplicate_fingerprint():
    ledger = empty_ledger()
    entry = derive_from_finding(
        {"type": "x", "location": "http://h/p", "parameter": "q",
         "cwe_id": "79"}, 0)
    entry.pop("id", None)
    ledger, added, skipped, rejected = merge_entries(ledger, [entry])
    assert len(added) == 1 and not skipped and not rejected
    dup = dict(entry, id="H77")
    ledger, added, skipped, rejected = merge_entries(ledger, [dup])
    assert added == [] and len(skipped) == 1


def test_merge_rejects_vague_with_reason():
    ledger = empty_ledger()
    ledger, added, skipped, rejected = merge_entries(
        ledger, [_claim("there might be a security issue somewhere")]
    )
    assert added == [] and skipped == []
    assert len(rejected) == 1
    assert any("vague" in e for e in rejected[0][1])


def test_eliminated_entry_is_never_re_derived():
    ledger = empty_ledger()
    entry = derive_from_finding(
        {"type": "x", "location": "http://h/p", "parameter": "q",
         "cwe_id": "79"}, 0)
    entry.pop("id", None)
    ledger, added, _, _ = merge_entries(ledger, [entry])
    fingerprint_of = added[0]["fingerprint"]
    set_verdicts(ledger, [], [fingerprint_of])
    assert ledger["hypotheses"][0]["status"] == "eliminated"
    ledger, added, skipped, _ = merge_entries(ledger, [dict(entry)])
    assert added == [] and len(skipped) == 1
    assert recount(ledger)["counts"]["eliminated"] == 1


def test_ids_are_unique_across_merges():
    ledger = empty_ledger()
    first = derive_from_finding(
        {"type": "a", "location": "http://h/1"}, 0)
    first.pop("id", None)
    second = derive_from_finding(
        {"type": "b", "location": "http://h/2"}, 0)
    second.pop("id", None)
    ledger, added, _, _ = merge_entries(ledger, [first, second])
    ids = [e["id"] for e in ledger["hypotheses"]]
    assert ids == ["H1", "H2"]
    assert next_id(ledger) == 3


def test_set_verdicts_only_moves_open_entries():
    ledger = empty_ledger()
    entry = derive_from_finding(
        {"type": "x", "location": "http://h/p", "parameter": "q"}, 0)
    entry.pop("id", None)
    ledger, added, _, _ = merge_entries(ledger, [entry])
    fp = added[0]["fingerprint"]
    set_verdicts(ledger, [fp], [])
    assert ledger["hypotheses"][0]["status"] == "proven"
    # a later contradicting verdict must not flip a proven entry
    set_verdicts(ledger, [], [fp])
    assert ledger["hypotheses"][0]["status"] == "proven"
    assert recount(ledger)["counts"] == {
        "open": 0, "proven": 1, "eliminated": 0,
    }


# ---------------------------------------------------------------------------
# normalize_ledger: whitebox shapes fold into ours
# ---------------------------------------------------------------------------

def test_normalize_accepts_whitebox_candidate_list():
    ledger = normalize_ledger([
        {"claim": "the /admin route leaks user records when called "
                  "without auth (CWE-306)", "location": "/admin"},
    ])
    assert ledger["schema_version"] == SCHEMA_VERSION
    assert ledger["hypotheses"][0]["status"] == "open"
    assert ledger["hypotheses"][0]["fingerprint"]


def test_normalize_accepts_single_object_and_bare_claim():
    one = normalize_ledger({"claim": "GET /a returns a debug stacktrace "
                                     "that discloses filesystem paths"})
    assert len(one["hypotheses"]) == 1
    assert one["counts"]["open"] == 1


def test_normalize_drops_entries_without_claim():
    ledger = normalize_ledger({"hypotheses": [{"location": "/x"}, "junk"]})
    assert ledger["hypotheses"] == []


# ---------------------------------------------------------------------------
# Seed file loading
# ---------------------------------------------------------------------------

def test_seed_file_json_list(tmp_path):
    path = tmp_path / "seed.json"
    path.write_text(json.dumps([
        {"claim": "GET /search?q reflects unencoded into HTML so an "
                  "attacker injects script through q", "location": "/search"},
        "the /api path exposes tokens in query strings that leak to logs",
    ]))
    seeds = load_seed_file(str(path))
    assert len(seeds) == 2
    assert seeds[0]["location"] == "/search"


def test_seed_file_plain_text_lines(tmp_path):
    path = tmp_path / "seed.txt"
    path.write_text(
        "GET /search?q reflects unencoded into HTML so an attacker "
        "injects script through q\n"
        "# a comment-like line still becomes a claim candidate\n"
    )
    seeds = load_seed_file(str(path))
    assert len(seeds) == 2
    assert all("claim" in s for s in seeds)


def test_seed_file_ledger_shape(tmp_path):
    path = tmp_path / "ledger.json"
    path.write_text(json.dumps({"hypotheses": [
        {"claim": "the /a endpoint executes commands because input is "
                  "concatenated into a shell string", "location": "/a"},
    ]}))
    assert len(load_seed_file(str(path))) == 1


def test_seed_file_empty(tmp_path):
    path = tmp_path / "empty.json"
    path.write_text("")
    assert load_seed_file(str(path)) == []


def test_seed_file_bad_json_raises_valueerror(tmp_path):
    path = tmp_path / "bad.json"
    path.write_text("{not json")
    with pytest.raises(ValueError):
        load_seed_file(str(path))
