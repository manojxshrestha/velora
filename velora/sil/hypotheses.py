"""Falsifiable-hypothesis engine + elimination ledger (finalplan §4 / §10).

A hypothesis is a *testable claim*: concrete subject (endpoint / parameter /
location), a mechanism-level assertion, and a falsifier (what observation
would refute it). Vague suspicions are rejected at ingest (seed files and
derivation both go through ``validate_hypothesis``), and every accepted
entry carries a fingerprint so the loop never re-derives an eliminated or
already-proven claim.

Ledger shape (``hypotheses.json`` in the session, §8.5)::

    {"schema_version": 1,
     "hypotheses": [{"id": "H1", "claim": "...", "subject": "...",
                     "falsifier": "...", "status": "open" | "proven"
                     | "eliminated", "fingerprint": "...", ...}],
     "counts": {"open": n, "proven": n, "eliminated": n}}
"""

from __future__ import annotations

import hashlib
import json
import re
import time
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Tuple

SCHEMA_VERSION = 1
STATUSES = ("open", "proven", "eliminated")

# Phrase-level hedges: whole phrases that make a claim unfalsifiable.
_VAGUE_PHRASES = re.compile(
    r"(?i)\b("
    r"might be (?:an? )?(?:security |vuln|insecure|broken|wrong|issue|problem)"
    r"|could be (?:an? )?(?:security |vuln|insecure|broken|wrong|issue|problem)"
    r"|security (?:issue|problem|concern|weakness)"
    r"|potential (?:issue|problem|concern)"
    r"|possible (?:issue|problem|concern)"
    r"|something (?:is |seems )?(?:wrong|off|broken|insecure)"
    r"|not secure"
    r"|has (?:some )?(?:issues|problems)"
    r"|might have (?:a |an )?(?:bug|issue|problem|vuln)"
    r"|could have (?:a |an )?(?:bug|issue|problem|vuln)"
    r"|somehow"
    r"|kind of|sort of"
    r"|unsure|unclear|not sure|i think|i guess|maybe"
    r")\b"
)

# Mechanism words: a falsifiable claim says WHAT happens, not that something
# is fishy.
_ASSERTION = re.compile(
    r"(?i)\b("
    r"allow(?:s|ed)?|bypass(?:es|ed)?|leak(?:s|ed)?|exposes?|expose"
    r"|executes?|reflects?|injected?|inject(?:s|ion)?"
    r"|predictable|forge(?:s|d)?|forged|replay(?:s|ed)?|race"
    r"|escalat(?:es|ion)|over-?permissi(?:on|ve)"
    r"|returns?|accepts?|fails? to|does not|doesn'?t|without"
    r"|missing|unguarded|unauthenticated|unauthori[sz]ed|enumerat(?:es|ion)"
    r"|concatenat(?:es|ed|ion)|deserializ(?:es|ation)|overwrit(?:es|ing)"
    r"|enables?|reads?|writes?|decodes?|travers(?:es|al)|crashes?"
    r"|vulnerable to|impact(?:s|ed)?|discloses?|verifi(?:es|ed|cation) fails"
    r")\b"
)

# Concrete subject: a URL/path/endpoint/parameter/field callout.
_SUBJECT = re.compile(
    r"(?i)(https?://\S+|/[a-z0-9_\-./]*[a-z0-9_\-/]|\bendpoint\b|\broute\b"
    r"|\bparameter\b|\bparam\b|\bfield\b|\bheader\b|\bcookie\b|\btoken\b"
    r"|\bquery\b|\bform\b|\bmethod\b|\bheader[s]?\b|\bpath\b)"
)

_MIN_LEN = 20
_MAX_LEN = 600


def _normalized_claim(claim: str) -> str:
    return re.sub(r"\s+", " ", (claim or "").strip().lower()).rstrip(".!")


def fingerprint(entry: Dict) -> str:
    """Stable identity for elimination memory (claim + subject)."""
    seed = _normalized_claim(str(entry.get("claim") or "")) + "|" + str(
        entry.get("subject") or entry.get("location") or ""
    ).strip().lower()
    return "H" + hashlib.sha1(seed.encode("utf-8")).hexdigest()[:12]


def validate_hypothesis(entry, *, subject: Optional[str] = None) -> List[str]:
    """Return a list of problems; empty list = falsifiable enough to accept.

    `entry` is a dict ({claim, subject/location, falsifier?}) or a bare
    claim string.
    """
    if isinstance(entry, str):
        entry = {"claim": entry}
    claim = str(entry.get("claim") or "").strip()
    subj = (
        subject
        or entry.get("subject")
        or entry.get("location")
        or ""
    )
    falsifier = str(entry.get("falsifier") or "").strip()
    errors: List[str] = []
    if not claim:
        return ["empty claim"]
    if len(claim) < _MIN_LEN:
        errors.append(f"claim too short to falsify ({len(claim)} < {_MIN_LEN})")
    if len(claim) > _MAX_LEN:
        errors.append(f"claim too long ({len(claim)} > {_MAX_LEN})")
    vague = _VAGUE_PHRASES.search(claim)
    if vague:
        errors.append(f"vague wording: '{vague.group(0)}'")
    if not (str(subj).strip() or _SUBJECT.search(claim)):
        errors.append("no concrete subject (endpoint/parameter/location)")
    if not (_ASSERTION.search(claim) or falsifier):
        errors.append("no testable assertion (mechanism or falsifier missing)")
    return errors


def derive_from_finding(finding: Dict, index: int) -> Dict:
    """Build a falsifiable hypothesis from a dynamic/static finding."""
    location = str(finding.get("location") or "")
    ftype = str(finding.get("type") or finding.get("cwe_id") or "finding")
    cwe = finding.get("cwe_id") or finding.get("cwe") or ""
    param = finding.get("parameter")
    subject = location
    if param:
        subject = f"{location} (param: {param})"
    claim = (
        f"{ftype} at {location or 'the target'}"
        + (f" via parameter '{param}'" if param else "")
        + f" reproduces deterministically ({cwe or 'CWE unknown'}); "
        "an independent re-probe returns the same vulnerable response"
    )
    entry = {
        "claim": claim,
        "subject": subject,
        "falsifier": (
            "re-probe the same request twice: if the vulnerable marker is "
            "absent or the response normalizes, the claim is refuted"
        ),
        "based_on": {
            "type": finding.get("type"),
            "location": location,
            "line": finding.get("line"),
            "detector": finding.get("detector"),
            "cwe_id": cwe or None,
        },
    }
    entry["fingerprint"] = fingerprint(entry)
    entry["id"] = f"H{index}"
    entry["status"] = "open"
    return entry


def empty_ledger() -> Dict:
    return {
        "schema_version": SCHEMA_VERSION,
        "hypotheses": [],
        "counts": {"open": 0, "proven": 0, "eliminated": 0},
    }


def recount(ledger: Dict) -> Dict:
    counts = {status: 0 for status in STATUSES}
    for entry in ledger.get("hypotheses") or []:
        status = str(entry.get("status") or "open")
        counts[status if status in counts else "open"] += 1
    ledger["counts"] = counts
    return ledger


def normalize_ledger(payload) -> Dict:
    """Accept the whitebox hypothesize shape or ours; always our shape."""
    ledger = empty_ledger()
    entries = []
    if isinstance(payload, dict):
        entries = payload.get("hypotheses") or []
        if not entries and payload.get("claim"):
            entries = [payload]
    elif isinstance(payload, list):
        entries = payload
    for item in entries:
        if not isinstance(item, dict) or not item.get("claim"):
            continue
        entry = dict(item)
        entry.setdefault("status", "open")
        if entry["status"] not in STATUSES:
            entry["status"] = "open"
        entry["fingerprint"] = entry.get("fingerprint") or fingerprint(entry)
        entry.setdefault("id", "")
        ledger["hypotheses"].append(entry)
    return recount(ledger)


def next_id(ledger: Dict) -> int:
    """Highest H<number> already used, plus one (collision-free ids)."""
    max_id = 0
    for entry in ledger.get("hypotheses") or []:
        match = re.match(r"H(\d+)$", str(entry.get("id") or ""))
        if match:
            max_id = max(max_id, int(match.group(1)))
    return max_id + 1


def merge_entries(
    ledger: Dict,
    candidates: Iterable[Dict],
    *,
    now: Optional[str] = None,
) -> Tuple[Dict, List[Dict], List[Dict], List[Tuple[Dict, List[str]]]]:
    """Merge candidates into the ledger.

    Returns ``(ledger, added, skipped_duplicate, rejected)`` where
    `rejected` pairs each candidate with its validation errors. Entries
    whose fingerprint already exists (open/proven/eliminated) are skipped —
    the loop never re-derives eliminated hypotheses.
    """
    existing = {
        str(e.get("fingerprint") or fingerprint(e))
        for e in ledger.get("hypotheses") or []
    }
    rejected: List[Tuple[Dict, List[str]]] = []
    added: List[Dict] = []
    skipped: List[Dict] = []
    stamp = now or time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    for candidate in candidates:
        errors = validate_hypothesis(candidate)
        if errors:
            rejected.append((candidate, errors))
            continue
        entry = dict(candidate)
        entry["fingerprint"] = entry.get("fingerprint") or fingerprint(entry)
        if entry["fingerprint"] in existing:
            skipped.append(entry)
            continue
        entry.setdefault("status", "open")
        entry["status"] = "open"
        entry["created_at"] = stamp
        if not entry.get("id"):
            entry["id"] = f"H{next_id(ledger)}"
        ledger.setdefault("hypotheses", []).append(entry)
        existing.add(entry["fingerprint"])
        added.append(entry)
    recount(ledger)
    return ledger, added, skipped, rejected


def set_verdicts(
    ledger: Dict,
    proven_fingerprints: Iterable[str],
    eliminated_fingerprints: Iterable[str],
    *,
    now: Optional[str] = None,
) -> Dict:
    """Record verify/validate outcomes; only `open` entries move."""
    stamp = now or time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    proven = {str(fp) for fp in proven_fingerprints}
    eliminated = {str(fp) for fp in eliminated_fingerprints}
    for entry in ledger.get("hypotheses") or []:
        if entry.get("status") != "open":
            continue
        fp = str(entry.get("fingerprint") or fingerprint(entry))
        if fp in proven:
            entry["status"] = "proven"
            entry["verdict_at"] = stamp
        elif fp in eliminated:
            entry["status"] = "eliminated"
            entry["verdict_at"] = stamp
    return recount(ledger)


def load_seed_file(path: str) -> List[Dict]:
    """Read a --hypotheses seed file: JSON list/object or one claim/line."""
    if path == "-":
        import sys

        text = sys.stdin.read()
    else:
        text = Path(path).read_text(encoding="utf-8")
    text = text.strip()
    if not text:
        return []
    if text.lstrip().startswith(("[", "{")):
        payload = json.loads(text)
        if isinstance(payload, dict) and "hypotheses" in payload:
            raw = payload.get("hypotheses") or []
        elif isinstance(payload, list):
            raw = payload
        else:
            raw = [payload]
        return [dict(item) if isinstance(item, dict) else {"claim": str(item)}
                for item in raw]
    return [{"claim": line.strip()} for line in text.splitlines() if line.strip()]
