"""Bounded active recon: crawl + robots/sitemap/JS/OpenAPI → assets (§9).

Depth- and page-bounded BFS over the same-origin surface seeded by the
targets. Everything goes through the scoped :class:`HttpClient`, so scope,
rate, budget, and inert-verb policy apply uniformly; budget exhaustion is a
normal partial stop (exit-code neutral), never an error.

Detected inputs (all best-effort, each within the page budget):
  robots.txt     Disallow/Allow paths → candidate URLs
  sitemap.xml    <loc> entries → candidate URLs
  HTML           links, forms (method+params), script srcs, <title>
  JS files       quoted path/URL literals → candidate API endpoints
  OpenAPI        /openapi.json, /swagger.json paths+methods+params
"""

from __future__ import annotations

import json
import re
import urllib.parse
from collections import deque
from dataclasses import dataclass, field
from html.parser import HTMLParser
from typing import Dict, List, Optional, Set, Tuple

from velora.active.apiops import (
    MAX_OPERATIONS as MAX_API_OPERATIONS,
    parse_api_operations,
)
from velora.active.client import BudgetExhausted, HttpClient, origin_of
from velora.assets.surface import add_tech, endpoint_key

DEFAULT_DEPTH = 2
DEFAULT_PAGES = 50
MAX_LINKS_PER_PAGE = 60
MAX_JS_ENDPOINTS_PER_FILE = 10
MAX_EXTERNAL = 50
OPENAPI_CANDIDATES = ("/openapi.json", "/swagger.json")

_SKIP_EXT = (
    ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".css", ".woff",
    ".woff2", ".ttf", ".map", ".mp4", ".webp", ".eot", ".otf",
)
_HTTP_METHODS = {"GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS", "TRACE"}
_JS_LITERAL = re.compile(
    r"""["']((?:https?://[^\s"']+)|(?:/[A-Za-z0-9_\-./~%]{1,200}))["']"""
)
_ROBOTS_LINE = re.compile(r"^(Disallow|Allow|Sitemap)\s*:\s*(.+)$", re.I)
_SITEMAP_LOC = re.compile(r"<loc>\s*([^<]+?)\s*</loc>", re.I)


@dataclass
class ReconResult:
    origins: List[str] = field(default_factory=list)
    pages: List[Dict] = field(default_factory=list)
    endpoints: Dict[str, Dict] = field(default_factory=dict)
    discovered: List[str] = field(default_factory=list)
    external: List[str] = field(default_factory=list)
    js_files: List[str] = field(default_factory=list)
    openapi: List[str] = field(default_factory=list)
    api_ops: List[Dict] = field(default_factory=list)
    robots: Dict = field(default_factory=dict)
    sitemap_urls: List[str] = field(default_factory=list)
    tech: Dict[str, str] = field(default_factory=dict)
    errors: List[str] = field(default_factory=list)
    budget_exhausted: bool = False
    requests: int = 0


class _PageParser(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.links: List[str] = []
        self.scripts: List[str] = []
        self.forms: List[Dict] = []
        self.title_parts: List[str] = []
        self._form: Optional[Dict] = None
        self._in_title = False

    def handle_starttag(self, tag: str, attrs) -> None:
        attrs = dict(attrs)
        if tag in ("a", "area", "iframe", "frame") and attrs.get("href"):
            self.links.append(attrs["href"])
        elif tag == "link" and attrs.get("href") and attrs.get("rel") == "stylesheet":
            self.links.append(attrs["href"])
        elif tag == "script" and attrs.get("src"):
            self.scripts.append(attrs["src"])
            if attrs["src"]:
                self.links.append(attrs["src"])
        elif tag == "form":
            self._form = {
                "action": attrs.get("action") or "",
                "method": (attrs.get("method") or "GET").upper(),
                "params": {},
            }
            self.forms.append(self._form)
        elif tag in ("input", "select", "textarea") and self._form is not None:
            name = attrs.get("name")
            if name:
                where = "query" if self._form["method"] == "GET" else "form"
                self._form["params"][name] = where
        elif tag == "title":
            self._in_title = True

    def handle_endtag(self, tag: str) -> None:
        if tag == "form":
            self._form = None
        elif tag == "title":
            self._in_title = False

    def handle_data(self, data: str) -> None:
        if self._in_title:
            self.title_parts.append(data)

    @property
    def title(self) -> str:
        return "".join(self.title_parts).strip()[:200]


def _is_html(content_type: str, url: str) -> bool:
    if content_type:
        return content_type.startswith(("text/html", "application/xhtml"))
    path = urllib.parse.urlparse(url).path.lower()
    return not path.endswith((".txt", ".xml", ".json", ".js") + _SKIP_EXT)


def _parse_robots(text: str) -> Dict:
    disallow: List[str] = []
    allow: List[str] = []
    sitemaps: List[str] = []
    for raw in text.splitlines():
        line = raw.split("#", 1)[0].strip()
        match = _ROBOTS_LINE.match(line)
        if not match:
            continue
        key, value = match.group(1).lower(), match.group(2).strip()
        if key == "disallow" and value:
            disallow.append(value)
        elif key == "allow" and value:
            allow.append(value)
        elif key == "sitemap" and value:
            sitemaps.append(value)
    return {"disallow": disallow, "allow": allow, "sitemaps": sitemaps}


def _parse_sitemap(text: str) -> List[str]:
    locs = _SITEMAP_LOC.findall(text)
    if not locs:
        # plain-text sitemaps: one URL per line
        locs = [
            line.strip() for line in text.splitlines()
            if line.strip().startswith(("http://", "https://"))
        ]
    return [loc.strip() for loc in locs if loc.strip()]


def _js_endpoints(text: str) -> List[str]:
    out: List[str] = []
    for match in _JS_LITERAL.finditer(text):
        literal = match.group(1)
        path = urllib.parse.urlparse(literal)
        if path.path.lower().endswith(_SKIP_EXT):
            continue
        if literal.startswith("/") and len(literal) > 1:
            out.append(literal)
            if len(out) >= MAX_JS_ENDPOINTS_PER_FILE:
                break
    return out


def _parse_openapi(text: str) -> Dict[str, Dict]:
    try:
        spec = json.loads(text)
    except (ValueError, TypeError):
        return {}
    if not isinstance(spec, dict) or not isinstance(spec.get("paths"), dict):
        return {}
    endpoints: Dict[str, Dict] = {}
    for path, ops in spec["paths"].items():
        if not isinstance(path, str) or not path.startswith("/"):
            continue
        if not isinstance(ops, dict):
            continue
        methods = [
            m.upper() for m in ops if m.upper() in _HTTP_METHODS
        ]
        params: Dict[str, str] = {}
        for op in ops.values():
            if not isinstance(op, dict):
                continue
            for param in op.get("parameters") or []:
                if isinstance(param, dict) and param.get("name"):
                    where = param.get("in") or "query"
                    params[str(param["name"])] = str(where)
        endpoints[path] = {"methods": methods or ["GET"], "params": params}
    return endpoints


def _merge_api_ops(result: "ReconResult", text: str) -> None:
    """Fold rich operation records from a fetched spec (dedup, capped)."""
    seen = {(str(op.get("method")), str(op.get("path")))
            for op in result.api_ops}
    for op in parse_api_operations(text):
        key = (str(op.get("method")), str(op.get("path")))
        if key in seen or len(result.api_ops) >= MAX_API_OPERATIONS:
            continue
        seen.add(key)
        result.api_ops.append(op)


def crawl(
    client: HttpClient,
    seeds: List[str],
    *,
    depth: Optional[int] = None,
    pages: Optional[int] = None,
) -> ReconResult:
    depth = DEFAULT_DEPTH if depth is None else max(0, int(depth))
    pages = DEFAULT_PAGES if pages is None else max(1, int(pages))
    seeds = [s for s in dict.fromkeys(seeds) if s]
    origins = list(dict.fromkeys(origin_of(s) for s in seeds))
    result = ReconResult(origins=origins)

    queue: deque = deque((seed, 0) for seed in seeds)
    for origin in origins:
        queue.append((origin.rstrip("/") + "/robots.txt", 0))
        queue.append((origin.rstrip("/") + "/sitemap.xml", 0))

    visited: Set[str] = set()
    discovered: Set[str] = set()
    external: Set[str] = set()
    fetched = 0

    def note_candidate(url: str, from_depth: int, base: str) -> None:
        if url.startswith(("mailto:", "javascript:", "tel:", "#")):
            return
        if url.startswith(("http://", "https://")):
            absolute = urllib.parse.urldefrag(url).url
        else:
            absolute = urllib.parse.urljoin(base + "/", url)
            absolute = urllib.parse.urldefrag(absolute).url
        if not absolute.startswith(("http://", "https://")):
            return
        if client.in_scope(absolute):
            key = endpoint_key(absolute)
            if key not in discovered:
                discovered.add(key)
            if from_depth <= depth:
                queue.append((absolute, from_depth))
        else:
            if absolute not in external and len(external) < MAX_EXTERNAL:
                external.add(absolute)

    while queue:
        if fetched >= pages:
            break
        url, level = queue.popleft()
        key = endpoint_key(url)
        if key in visited:
            continue
        visited.add(key)
        try:
            response = client.get(url)
        except BudgetExhausted:
            result.budget_exhausted = True
            break
        except Exception as exc:  # scope refusals never reach here (filtered)
            result.errors.append(f"{url}: {type(exc).__name__}: {exc}")
            continue
        fetched += 1
        final_url = response.final_url or url
        path = urllib.parse.urlparse(final_url).path
        page = {
            "url": url,
            "final_url": final_url,
            "status": response.status,
            "depth": level,
            "content_type": response.content_type,
        }
        result.pages.append(page)
        if response.status == 0:
            if len(result.errors) < 20:
                result.errors.append(f"{url}: {response.error or 'network error'}")
            continue
        add_tech(result.tech, response.headers)

        if path.endswith("/robots.txt") or path == "/robots.txt":
            parsed = _parse_robots(response.text)
            result.robots = parsed
            origin = origin_of(final_url)
            for hint in parsed.get("disallow", []) + parsed.get("allow", []):
                if hint.startswith("/"):
                    note_candidate(origin + hint, level + 1, origin)
            for sitemap in parsed.get("sitemaps", []):
                note_candidate(sitemap, level + 1, origin)
            continue
        if path.endswith("sitemap.xml"):
            origin = origin_of(final_url)
            for loc in _parse_sitemap(response.text):
                result.sitemap_urls.append(loc)
                note_candidate(loc, level + 1, origin)
            continue
        if path.endswith(_SKIP_EXT):
            continue
        ctype = response.content_type
        if ctype in ("application/json",) or path.endswith(
            ("openapi.json", "swagger.json")
        ):
            spec = _parse_openapi(response.text)
            if spec:
                result.openapi.append(url)
                _merge_api_ops(result, response.text)
                origin = origin_of(final_url)
                for subpath, data in spec.items():
                    absolute = origin + subpath
                    result.endpoints.setdefault(absolute, {
                        "methods": [], "params": {},
                    })
                    methods = result.endpoints[absolute].setdefault("methods", [])
                    for method in data.get("methods", []):
                        if method not in methods:
                            methods.append(method)
                    result.endpoints[absolute].setdefault("params", {}).update(
                        data.get("params", {})
                    )
                    note_candidate(absolute, level + 1, origin)
            continue
        if ctype.startswith("application/javascript") or ctype.startswith(
            "text/javascript"
        ) or path.endswith(".js"):
            result.js_files.append(url)
            origin = origin_of(final_url)
            for literal in _js_endpoints(response.text):
                note_candidate(literal, level + 1, origin)
            continue
        if _is_html(ctype, final_url):
            parser = _PageParser()
            try:
                parser.feed(response.text)
            except Exception:
                pass
            page["title"] = parser.title
            origin = origin_of(final_url)
            for href in parser.links[:MAX_LINKS_PER_PAGE]:
                note_candidate(href, level + 1, final_url)
            for form in parser.forms:
                action = urllib.parse.urljoin(final_url, form.get("action") or final_url)
                if not client.in_scope(action):
                    if action not in external and len(external) < MAX_EXTERNAL:
                        external.add(action)
                    continue
                entry = result.endpoints.setdefault(
                    endpoint_key(action), {"methods": [], "params": {}}
                )
                method = form.get("method") or "GET"
                if method not in entry["methods"]:
                    entry["methods"].append(method)
                entry["params"].update(form.get("params") or {})
                note_candidate(action, level + 1, final_url)
            result.discovered.append(endpoint_key(final_url))

    # OpenAPI probe: best-effort spec discovery for the primary origin
    if not result.openapi and not result.budget_exhausted and fetched < pages:
        for origin in origins[:1]:
            for candidate in OPENAPI_CANDIDATES:
                if fetched >= pages:
                    break
                url = origin.rstrip("/") + candidate
                if endpoint_key(url) in visited:
                    continue
                visited.add(endpoint_key(url))
                try:
                    response = client.get(url)
                except BudgetExhausted:
                    result.budget_exhausted = True
                    break
                fetched += 1
                result.pages.append({
                    "url": url,
                    "final_url": response.final_url or url,
                    "status": response.status,
                    "depth": 1,
                    "content_type": response.content_type,
                })
                if response.status == 200:
                    spec = _parse_openapi(response.text)
                    if spec:
                        result.openapi.append(url)
                        _merge_api_ops(result, response.text)
                        for subpath, data in spec.items():
                            absolute = origin + subpath
                            entry = result.endpoints.setdefault(
                                absolute, {"methods": [], "params": {}}
                            )
                            for method in data.get("methods", []):
                                if method not in entry["methods"]:
                                    entry["methods"].append(method)
                            entry["params"].update(data.get("params") or {})
                    break
            if result.openapi:
                break

    result.discovered = sorted(discovered | {
        endpoint_key(p["final_url"]) for p in result.pages if p.get("status")
    })
    result.external = sorted(external)
    return result
