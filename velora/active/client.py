"""Active HTTP client: scope-enforced, rate-limited, budgeted (finalplan §9).

Safety posture (§12 Blackbox probing misused):
  * scope default same-origin — every request AND every redirect hop must
    target a host on the SCOPE allow-list; refused requests raise
    :class:`ScopeRefused` and are never sent.
  * non-destructive default — only inert verbs (GET/HEAD/OPTIONS) are sent
    unless ``allow_active`` (`--active`) explicitly opts into state-changing
    methods; blocked calls raise :class:`InertVerbRefused`.
  * rate caps (`--rate`) and a request budget (`--budget`, default cap)
    bound every run; exhaustion raises :class:`BudgetExhausted`, which the
    stages treat as a normal stop (never an error exit).
  * secrets never enter evidence — Authorization/Cookie request header
    values and Set-Cookie *values* (attributes kept, they are detector
    signal) are redacted wherever a request is recorded.

Reuses the opener rules established in ``sil/llm_client`` (dedicated opener,
never ``install_opener``; strip Authorization on cross-origin redirects) and
adds scope enforcement on every hop.
"""

from __future__ import annotations

import ssl
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Optional, Sequence, Set

INERT_VERBS = frozenset({"GET", "HEAD", "OPTIONS"})
DEFAULT_BUDGET = 500          # HTTP requests (§8.4: blackbox default cap)
DEFAULT_TIMEOUT = 10.0        # seconds, per request
DEFAULT_MAX_REDIRECTS = 5
DEFAULT_USER_AGENT = "velora"
EVIDENCE_BODY_CHARS = 2000    # per-request body snippet kept in evidence
MAX_BODY_BYTES = 2 * 1024 * 1024
EVIDENCE_LIMIT = 1000

_REDACT_HEADERS = frozenset({
    "authorization", "proxy-authorization", "cookie",
    "x-api-key", "x-auth-token", "x-csrf-token",
})


class ScopeRefused(Exception):
    """Request (or a redirect hop) targets a host outside the SCOPE allow-list."""

    def __init__(self, url: str):
        super().__init__(f"out of scope (host not on the SCOPE allow-list): {url}")
        self.url = url


class BudgetExhausted(Exception):
    """The request budget (--budget, default cap) is spent. A normal stop."""

    def __init__(self, budget: int):
        super().__init__(f"request budget exhausted ({budget} requests)")
        self.budget = budget


class InertVerbRefused(Exception):
    """State-changing verb attempted while the run is inert (default)."""

    def __init__(self, method: str):
        super().__init__(
            f"{method} refused: default is inert (GET/HEAD/OPTIONS only) — "
            "pass --active to allow state-changing verbs"
        )
        self.method = method


@dataclass
class Response:
    url: str
    status: int = 0
    headers: Dict[str, str] = field(default_factory=dict)
    body: bytes = b""
    text: str = ""
    final_url: str = ""
    elapsed_ms: int = 0
    error: Optional[str] = None

    @property
    def ok(self) -> bool:
        return self.error is None and 200 <= self.status < 400

    @property
    def content_type(self) -> str:
        return (self.headers.get("content-type") or "").split(";")[0].strip().lower()

    @property
    def truncated(self) -> bool:
        return len(self.body) >= MAX_BODY_BYTES


def normalize_host(entry: str) -> str:
    """Normalize a --scope host / target host to a bare lowercase hostname.

    ``https://example.com:8443/path`` → ``example.com``; ``example.com:8080``
    → ``example.com``; anything else passes through lowercased.
    """
    value = (entry or "").strip().lower()
    if not value:
        return ""
    if "://" in value:
        host = urllib.parse.urlparse(value).hostname or ""
        return host.strip("[]")
    if value.startswith("["):  # [::1]:port
        end = value.find("]")
        return value[1:end] if end > 0 else value
    host = value.split("/", 1)[0]
    if host.count(":") == 1:
        name, _, port = host.partition(":")
        if port.isdigit():
            host = name
    return host


def host_of(url: str) -> str:
    return (urllib.parse.urlparse(url).hostname or "").lower().strip("[]")


def origin_of(url: str) -> str:
    parts = urllib.parse.urlparse(url)
    netloc = parts.netloc or ""
    return f"{parts.scheme}://{netloc}"


def normalize_url(url: str) -> str:
    """Crawl identity: fragment dropped, empty path → /, default port dropped."""
    parts = urllib.parse.urlparse(url)
    scheme = parts.scheme.lower()
    host = (parts.hostname or "").lower()
    port = parts.port
    netloc = host
    if port is not None and not (
        (scheme == "http" and port == 80) or (scheme == "https" and port == 443)
    ):
        netloc = f"{host}:{port}"
    path = parts.path or "/"
    return urllib.parse.urlunparse((scheme, netloc, path, "", parts.query, ""))


def _redact_headers(headers: Dict[str, str]) -> Dict[str, str]:
    out: Dict[str, str] = {}
    for key, value in headers.items():
        lower = key.lower()
        if lower in _REDACT_HEADERS:
            out[key] = "***"
        elif lower == "set-cookie":
            # keep detector signal (HttpOnly/Secure/Path attrs), hide the value
            head, sep, tail = value.partition("=")
            value = head + sep + "***" + (tail[tail.find(";"):] if ";" in tail else "")
            out[key] = value
        else:
            out[key] = value
    return out


def format_reqresp(entry: Dict) -> tuple:
    """Evidence entry → (request, response) display strings for findings."""
    method = entry.get("method", "GET")
    url = entry.get("url", "")
    req = f"{method} {url}"
    req_headers = entry.get("request_headers") or {}
    if req_headers:
        req += "\n" + "\n".join(f"{k}: {v}" for k, v in req_headers.items())
    resp = f"HTTP {entry.get('status', 0)} {entry.get('final_url') or url}"
    for key, value in (entry.get("response_headers") or {}).items():
        resp += f"\n{key}: {value}"
    body = entry.get("body") or ""
    if body:
        resp += "\n\n" + body
    return req, resp


class _ScopeRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Redirect policy: scope-check every hop, cap hops, strip Authorization
    cross-origin (same rule as sil/llm_client's opener), throttle per hop."""

    max_redirections = DEFAULT_MAX_REDIRECTS

    def __init__(self, client: "HttpClient"):
        self._client = client

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        url = urllib.parse.urljoin(getattr(req, "full_url", "") or "", newurl)
        self._client._check_scope(url)
        self._client._throttle()
        newreq = super().redirect_request(req, fp, code, msg, headers, newurl)
        if newreq is None:
            return None
        if host_of(url) != host_of(getattr(req, "full_url", "") or ""):
            for hdr in [h for h in list(getattr(newreq, "headers", {}) or {})
                        if h.lower() == "authorization"]:
                newreq.headers.pop(hdr, None)
            unred = getattr(newreq, "unredirected_hdrs", None)
            if isinstance(unred, dict):
                for hdr in [h for h in unred if h.lower() == "authorization"]:
                    unred.pop(hdr, None)
        return newreq


class HttpClient:
    """One scoped, rate- and budget-bounded HTTP client for a mode run."""

    def __init__(
        self,
        allow_hosts: Iterable[str],
        *,
        rate: Optional[float] = None,
        budget: Optional[int] = None,
        timeout: float = DEFAULT_TIMEOUT,
        proxy: Optional[str] = None,
        insecure: bool = False,
        user_agent: Optional[str] = None,
        headers: Optional[Dict[str, str]] = None,
        allow_active: bool = False,
        max_redirects: int = DEFAULT_MAX_REDIRECTS,
        cookie_jar: bool = False,
        evidence_limit: int = EVIDENCE_LIMIT,
        sleep=time.sleep,
        clock=time.monotonic,
    ):
        self.allow_hosts: Set[str] = {
            h for h in (normalize_host(h) for h in allow_hosts) if h
        }
        self.rate = rate
        self.budget = DEFAULT_BUDGET if budget is None else int(budget)
        self.requests_made = 0
        self.timeout = timeout
        self.allow_active = allow_active
        self.evidence_limit = evidence_limit
        self.evidence: List[Dict] = []
        self.evidence_dropped = 0
        self.budget_exhausted = False
        self._last_request_at: Optional[float] = None
        self._sleep = sleep
        self._clock = clock
        self._headers: Dict[str, str] = {"User-Agent": user_agent or DEFAULT_USER_AGENT}
        for key, value in (headers or {}).items():
            self._headers[key] = value
        handlers: List[urllib.request.BaseHandler] = [
            # always construct: an explicit ProxyHandler (empty map when no
            # --proxy) suppresses urllib's default env-var proxy handler, so
            # HTTP_PROXY in the environment can never reroute scoped traffic
            urllib.request.ProxyHandler(
                {"http": proxy, "https": proxy} if proxy else {}
            )
        ]
        handlers.append(_ScopeRedirectHandler(self))
        # opt-in jar: scripted login flows need Set-Cookie (including on
        # redirect hops) captured and replayed; off by default so plain runs
        # keep purely static headers
        self.cookie_jar: Optional[Any] = None
        if cookie_jar:
            import http.cookiejar

            jar = http.cookiejar.CookieJar()
            handlers.append(urllib.request.HTTPCookieProcessor(jar))
            self.cookie_jar = jar
        self._opener = urllib.request.build_opener(*handlers)
        self._insecure_context = ssl._create_unverified_context() if insecure else None

    # -- guards ----------------------------------------------------------

    def _check_scope(self, url: str) -> None:
        host = host_of(url)
        if not host or host not in self.allow_hosts:
            raise ScopeRefused(url)

    def _throttle(self) -> None:
        if self.requests_made >= self.budget:
            self.budget_exhausted = True
            raise BudgetExhausted(self.budget)
        if self.rate and self.rate > 0 and self._last_request_at is not None:
            wait = (1.0 / self.rate) - (self._clock() - self._last_request_at)
            if wait > 0:
                self._sleep(wait)
        self.requests_made += 1
        self._last_request_at = self._clock()

    def remaining_budget(self) -> int:
        return max(0, self.budget - self.requests_made)

    # -- requests --------------------------------------------------------

    def request(
        self,
        method: str,
        url: str,
        *,
        data: Optional[bytes] = None,
        headers: Optional[Dict[str, str]] = None,
        timeout: Optional[float] = None,
        record: bool = True,
    ) -> Response:
        method = (method or "GET").upper()
        if method not in INERT_VERBS and not self.allow_active:
            raise InertVerbRefused(method)
        self._check_scope(url)
        self._throttle()
        merged = dict(self._headers)
        for key, value in (headers or {}).items():
            merged[key] = value
        req = urllib.request.Request(url, data=data, method=method)
        for key, value in merged.items():
            req.add_header(key, value)
        started = self._clock()
        response = Response(url=url, final_url=url)
        try:
            open_kwargs = {"timeout": timeout or self.timeout}
            if self._insecure_context is not None:
                open_kwargs["context"] = self._insecure_context
            with self._opener.open(req, **open_kwargs) as resp:
                response.status = getattr(resp, "status", None) or resp.getcode()
                response.headers = {k.lower(): v for k, v in resp.headers.items()}
                response.final_url = resp.geturl() or url
                response.body = resp.read(MAX_BODY_BYTES)
        except urllib.error.HTTPError as exc:
            response.status = exc.code
            response.headers = {
                k.lower(): v for k, v in (exc.headers or {}).items()
            }
            response.final_url = getattr(exc, "url", None) or url
            try:
                response.body = exc.read(MAX_BODY_BYTES) if exc.fp else b""
            except OSError:
                response.body = b""
        except (ScopeRefused, BudgetExhausted, InertVerbRefused):
            raise
        except Exception as exc:  # URLError, timeout, ssl, ConnectionReset...
            response.error = f"{type(exc).__name__}: {exc}"
        response.text = response.body.decode("utf-8", errors="replace")
        response.elapsed_ms = int((self._clock() - started) * 1000)
        if record:
            self._record(method, url, req, response, data)
        return response

    def get(self, url: str, **kwargs) -> Response:
        return self.request("GET", url, **kwargs)

    def in_scope(self, url: str) -> bool:
        host = host_of(url)
        return bool(host) and host in self.allow_hosts

    # -- evidence --------------------------------------------------------

    def _record(
        self,
        method: str,
        url: str,
        req: urllib.request.Request,
        response: Response,
        data: Optional[bytes],
    ) -> None:
        if len(self.evidence) >= self.evidence_limit:
            self.evidence_dropped += 1
            return
        req_headers = {k: v for k, v in req.header_items()}
        entry = {
            "method": method,
            "url": url,
            "final_url": response.final_url,
            "status": response.status,
            "request_headers": _redact_headers(req_headers),
            "response_headers": _redact_headers(dict(response.headers)),
            "body": response.text[:EVIDENCE_BODY_CHARS],
            "elapsed_ms": response.elapsed_ms,
        }
        if data:
            entry["request_body"] = (
                data.decode("utf-8", errors="replace")
                if isinstance(data, (bytes, bytearray))
                else str(data)
            )[:500]
        if response.error:
            entry["error"] = response.error
        self.evidence.append(entry)

    def evidence_for(self, url: str) -> Optional[Dict]:
        for entry in reversed(self.evidence):
            if entry.get("url") == url:
                return entry
        return None

    def export_evidence(self) -> List[Dict]:
        return list(self.evidence)
