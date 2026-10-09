"""Enumeration + differential detection with ≥2 reproductions (finalplan §9).

Every probe is inert (GET/HEAD/OPTIONS only) and rides the scoped client, so
scope/rate/budget/`--active` policy apply. A finding is emitted only when the
delta reproduces across ≥2 independent probes (§12 dynamic false positives);
evidence carries the request/response pair with ``reproduced`` (§7.1).

``RECHECK`` re-runs each detector's predicate once for VERIFY/VALIDATE — an
independent confirmation, fresh markers included.
"""

from __future__ import annotations

import re
import secrets
import urllib.parse
from typing import Callable, Dict, List, Optional, Tuple

from velora.active.client import (
    BudgetExhausted,
    HttpClient,
    ScopeRefused,
    format_reqresp,
    origin_of,
)
from velora.assets.surface import (
    endpoint_key,
    endpoint_urls,
    finalize,
    html_endpoints,
    query_endpoints,
)

DEFAULT_ENUM_LIMIT = 40
REFLECT_CANDIDATES = 8
COOKIE_CANDIDATES = 4
ERROR_CANDIDATES = 6
MAX_ERRORS = 8

_REQUIRED_HEADERS = (
    "content-security-policy",
    "x-frame-options",
    "x-content-type-options",
)
_HSTS_HEADER = "strict-transport-security"
_BANNER_VALUE = re.compile(r"\d+\.\d+")
_ERROR_PATTERNS = (
    "Traceback (most recent call last)",
    "werkzeug debugger",
    "java.lang.",
    "System.ArgumentException",
    "Microsoft .NET Framework",
    "PHP Fatal error",
    "SQLSTATE[",
    "Stack trace:",
)

_SEV_RUBRIC = {
    "critical": 9.0,
    "high": 7.5,
    "medium": 5.0,
    "low": 2.5,
    "info": 0.5,
}


def make_finding(
    *,
    detector: str,
    type: str,
    title: str,
    severity: str,
    confidence: float,
    cwe: str,
    url: str,
    description: str,
    request: str,
    response: str,
    reproduced: int,
    param: Optional[str] = None,
    detail: Optional[Dict] = None,
) -> Dict:
    """Build one §7.1 dynamic finding (mode/provenance/asset/evidence)."""
    finding: Dict = {
        "type": type,
        "title": title,
        "severity": severity,
        "confidence": confidence,
        "cwe_id": cwe,
        "score": {
            "value": _SEV_RUBRIC.get(severity, 0.0),
            "from": "rubric",
            "rubric": {
                "impact": severity,
                "exploitability": "network",
                "scope": "unchanged",
            },
        },
        "mode": "blackbox",
        "provenance": "dynamic",
        "asset": {"kind": "web", "id": origin_of(url)},
        "location": url,
        "path": url,
        "line": None,
        "parameter": param,
        "description": description,
        "detector": detector,
        "reproduced": reproduced,
        "evidence": {
            "kind": "reqresp",
            "request": request,
            "response": response,
            "reproduced": reproduced,
            "replay": {"method": "GET", "url": url},
        },
    }
    if detail:
        finding.update(detail)
    return finding


def _evidence_pair(client: HttpClient) -> Tuple[str, str]:
    if not client.evidence:
        return ("", "")
    return format_reqresp(client.evidence[-1])


def _title_of(url: str) -> str:
    parts = urllib.parse.urlparse(url)
    return f"{parts.path or '/'}{('#' + parts.fragment) if parts.fragment else ''}"


# ---------------------------------------------------------------------------
# Enumeration
# ---------------------------------------------------------------------------

def enumerate_surface(
    client: HttpClient, surface: Dict, *, limit: int = DEFAULT_ENUM_LIMIT
) -> Dict:
    """Deepen each surface node: OPTIONS → Allow methods; GET when unknown."""
    stats = {"probed": 0, "gets": 0, "errors": 0, "stopped": None}
    for url in endpoint_urls(surface)[:limit]:
        entry = surface["endpoints"][url]
        try:
            options = client.request("OPTIONS", url)
        except BudgetExhausted:
            stats["stopped"] = "budget"
            break
        except ScopeRefused:
            stats["errors"] += 1
            continue
        stats["probed"] += 1
        allow = options.headers.get("allow") or ""
        for method in allow.split(","):
            method = method.strip().upper()
            if method and method not in entry["methods"]:
                entry["methods"].append(method)
        if options.status == 0:
            stats["errors"] += 1
        need_get = entry.get("status") is None or not entry.get("methods")
        if need_get:
            try:
                got = client.get(url)
            except BudgetExhausted:
                stats["stopped"] = "budget"
                break
            except ScopeRefused:
                stats["errors"] += 1
                continue
            if got.status:
                entry["status"] = got.status
                if got.content_type:
                    entry["content_type"] = got.content_type
                if got.headers.get("set-cookie") or got.headers.get("www-authenticate"):
                    entry["auth_seen"] = True
                stats["gets"] += 1
            else:
                stats["errors"] += 1
    finalize(surface)
    return stats


# ---------------------------------------------------------------------------
# Detectors — each runs its check twice and only emits on an identical delta
# ---------------------------------------------------------------------------

def _missing_security_headers(
    client: HttpClient, url: str
) -> Tuple[set, Optional[object]]:
    samples: List[set] = []
    last = None
    for _ in range(2):
        response = client.get(url)
        if response.status == 0:
            return set(), None
        required = list(_REQUIRED_HEADERS)
        if urllib.parse.urlparse(url).scheme == "https":
            required.append(_HSTS_HEADER)
        samples.append({h for h in required if h not in response.headers})
        last = response
    if not samples or samples[0] != samples[1] or not samples[0]:
        return set(), None
    return samples[0], last


def detect_missing_headers(client: HttpClient, surface: Dict) -> List[Dict]:
    findings: List[Dict] = []
    for url in html_endpoints(surface, limit=1):
        missing, response = _missing_security_headers(client, url)
        if not missing:
            continue
        request, body = _evidence_pair(client)
        findings.append(
            make_finding(
                detector="security-headers",
                type="missing-security-headers",
                title=f"Missing security headers on {_title_of(url)}",
                severity="low",
                confidence=0.9,
                cwe="CWE-693",
                url=url,
                description=(
                    "Response is missing defensive headers: "
                    + ", ".join(sorted(missing))
                    + ". Reproduced on two independent fetches."
                ),
                request=request,
                response=body,
                reproduced=2,
                detail={"missing": sorted(missing)},
            )
        )
    return findings


def _cookie_flags_issue(client: HttpClient, url: str) -> Tuple[Optional[set], Optional[object]]:
    observed: List[Optional[set]] = []
    last = None
    for _ in range(2):
        response = client.get(url)
        if response.status == 0:
            return None, None
        raw = response.headers.get("set-cookie")
        if not raw:
            observed.append(None)
            last = response
            continue
        lower = raw.lower()
        issues = set()
        if "httponly" not in lower:
            issues.add("HttpOnly")
        if urllib.parse.urlparse(url).scheme == "https" and "secure" not in lower:
            issues.add("Secure")
        observed.append(issues)
        last = response
    if len(observed) != 2 or observed[0] is None or observed[0] != observed[1]:
        return None, None
    if not observed[0]:
        return set(), None  # cookie present and properly flagged
    return observed[0], last


def detect_cookie_flags(client: HttpClient, surface: Dict) -> List[Dict]:
    findings: List[Dict] = []
    for url in html_endpoints(surface, limit=COOKIE_CANDIDATES):
        issues, response = _cookie_flags_issue(client, url)
        if not issues:
            continue
        request, body = _evidence_pair(client)
        entry = surface.setdefault("endpoints", {}).get(endpoint_key(url))
        if entry is not None:
            entry["auth_seen"] = True
        findings.append(
            make_finding(
                detector="cookie-flags",
                type="cookie-missing-flags",
                title=f"Cookie without {'/'.join(sorted(issues))} on {_title_of(url)}",
                severity="low",
                confidence=0.9,
                cwe="CWE-1004",
                url=url,
                description=(
                    "Session cookie is set without "
                    + "/".join(sorted(issues))
                    + " flags (reproduced on two fetches)."
                ),
                request=request,
                response=body,
                reproduced=2,
                detail={"flags_missing": sorted(issues)},
            )
        )
    return findings


def _banner_issue(client: HttpClient, url: str) -> Tuple[Optional[Dict], None]:
    seen: List[Optional[Dict]] = []
    for _ in range(2):
        response = client.get(url)
        if response.status == 0:
            return None, None
        leak = {}
        for header in ("server", "x-powered-by"):
            value = response.headers.get(header)
            if value and (_BANNER_VALUE.search(value) or header == "x-powered-by"):
                leak[header] = value
        seen.append(leak or None)
    if len(seen) == 2 and seen[0] and seen[0] == seen[1]:
        return seen[0], None
    return None, None


def detect_server_banner(client: HttpClient, surface: Dict) -> List[Dict]:
    findings: List[Dict] = []
    for url in html_endpoints(surface, limit=1):
        leak, _ = _banner_issue(client, url)
        if not leak:
            continue
        request, body = _evidence_pair(client)
        findings.append(
            make_finding(
                detector="server-banner",
                type="server-banner-disclosure",
                title=f"Server banner discloses versions on {_title_of(url)}",
                severity="info",
                confidence=0.8,
                cwe="CWE-200",
                url=url,
                description=(
                    "Response headers disclose server technology versions: "
                    + ", ".join(f"{k}={v}" for k, v in sorted(leak.items()))
                    + " (reproduced on two fetches)."
                ),
                request=request,
                response=body,
                reproduced=2,
                detail={"banner": leak},
            )
        )
    return findings


def _raw_reflection(client: HttpClient, url: str, param: str) -> Tuple[Optional[str], Optional[object]]:
    """Two probes with distinct HTML-sensitive markers; raw echo both times."""
    markers: List[str] = []
    last = None
    for _ in range(2):
        marker = f"<velora{secrets.token_hex(4)}>"
        query = urllib.parse.urlencode({param: marker})
        probe = f"{url}?{query}"
        response = client.get(probe)
        if response.status == 0:
            return None, None
        if marker in response.text:
            markers.append(marker)
        else:
            markers.append("")
        last = response
    if len(markers) == 2 and all(markers):
        return markers[1], last
    return None, None


def detect_reflection(client: HttpClient, surface: Dict) -> List[Dict]:
    findings: List[Dict] = []
    for url, params in query_endpoints(surface, limit=REFLECT_CANDIDATES):
        for param in params:
            marker, response = _raw_reflection(client, url, param)
            if not marker:
                continue
            request, body = _evidence_pair(client)
            findings.append(
                make_finding(
                    detector="reflected-input",
                    type="reflected-input-unencoded",
                    title=f"Unencoded HTML reflection of '{param}' on {_title_of(url)}",
                    severity="medium",
                    confidence=0.8,
                    cwe="CWE-79",
                    url=url,
                    param=param,
                    description=(
                        f"Query parameter '{param}' is reflected into the HTML "
                        "response without output encoding (raw marker observed "
                        "on two independent probes)."
                    ),
                    request=request,
                    response=body,
                    reproduced=2,
                    detail={"marker": marker},
                )
            )
    return findings


def _error_pattern(client: HttpClient, url: str) -> Tuple[Optional[str], Optional[object]]:
    hits: List[str] = []
    last = None
    for _ in range(2):
        response = client.get(url)
        if response.status == 0:
            return None, None
        found = next(
            (p for p in _ERROR_PATTERNS if p.lower() in response.text.lower()), ""
        )
        hits.append(found)
        last = response
    if len(hits) == 2 and hits[0] and hits[0] == hits[1]:
        return hits[0], last
    return None, None


def _body_candidates(surface: Dict, limit: int = ERROR_CANDIDATES) -> List[str]:
    out: List[str] = []
    for url in endpoint_urls(surface):
        entry = surface["endpoints"][url]
        status = entry.get("status")
        if status is not None and not (200 <= status < 300):
            continue
        ctype = entry.get("content_type") or ""
        if ctype.startswith("text/") or (not ctype and entry.get("title")):
            out.append(url)
        if len(out) >= limit:
            break
    return out


def detect_error_disclosure(client: HttpClient, surface: Dict) -> List[Dict]:
    findings: List[Dict] = []
    for url in _body_candidates(surface):
        pattern, response = _error_pattern(client, url)
        if not pattern:
            continue
        request, body = _evidence_pair(client)
        findings.append(
            make_finding(
                detector="error-disclosure",
                type="verbose-error-disclosure",
                title=f"Verbose error output on {_title_of(url)}",
                severity="medium",
                confidence=0.7,
                cwe="CWE-209",
                url=url,
                description=(
                    f"Response body exposes debugging detail (pattern: "
                    f"{pattern!r}) — reproduced on two fetches."
                ),
                request=request,
                response=body,
                reproduced=2,
                detail={"pattern": pattern},
            )
        )
        if len(findings) >= MAX_ERRORS:
            break
    return findings


DETECTORS: Tuple[Callable[[HttpClient, Dict], List[Dict]], ...] = (
    detect_missing_headers,
    detect_cookie_flags,
    detect_server_banner,
    detect_reflection,
    detect_error_disclosure,
)


def detect(client: HttpClient, surface: Dict) -> List[Dict]:
    """Run every detector; each finding already carries ≥2 reproductions."""
    findings: List[Dict] = []
    for detector in DETECTORS:
        findings.extend(detector(client, surface))
    return findings


# ---------------------------------------------------------------------------
# Independent re-check (VERIFY / VALIDATE)
# ---------------------------------------------------------------------------

def _recheck_missing_headers(client: HttpClient, finding: Dict) -> bool:
    missing, _ = _missing_security_headers(client, finding.get("location") or "")
    expected = set(finding.get("missing") or [])
    return bool(missing) and expected.issubset(missing)


def _recheck_cookie_flags(client: HttpClient, finding: Dict) -> bool:
    issues, _ = _cookie_flags_issue(client, finding.get("location") or "")
    expected = set(finding.get("flags_missing") or [])
    return bool(issues) and expected.issubset(issues)


def _recheck_banner(client: HttpClient, finding: Dict) -> bool:
    leak, _ = _banner_issue(client, finding.get("location") or "")
    return bool(leak)


def _recheck_reflection(client: HttpClient, finding: Dict) -> bool:
    url, param = finding.get("location"), finding.get("parameter")
    if not url or not param:
        return False
    marker, _ = _raw_reflection(client, url, param)
    return bool(marker)


def _recheck_error(client: HttpClient, finding: Dict) -> bool:
    pattern, _ = _error_pattern(client, finding.get("location") or "")
    return bool(pattern)


RECHECK: Dict[str, Callable[[HttpClient, Dict], bool]] = {
    "security-headers": _recheck_missing_headers,
    "cookie-flags": _recheck_cookie_flags,
    "server-banner": _recheck_banner,
    "reflected-input": _recheck_reflection,
    "error-disclosure": _recheck_error,
}


def recheck(client: HttpClient, finding: Dict) -> bool:
    handler = RECHECK.get(str(finding.get("detector") or ""))
    if handler is None:
        return False
    try:
        return bool(handler(client, finding))
    except BudgetExhausted:
        raise
    except Exception:
        return False
