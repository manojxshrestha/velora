"""Reachable-surface view + enumeration store (finalplan §7.2).

``surface.json`` is the web-shaped slice of the asset graph: endpoints with
methods, params, auth seen, and the tech fingerprint — rebuilt each run and
archivable for re-runs. Workers receive slices of ``assets.json`` keyed by
asset kind; this module also folds recon output *into* an AssetGraph so
ASSET DISCOVERY and SURFACE share one vocabulary.
"""

from __future__ import annotations

import re
import socket
import urllib.parse
from typing import Dict, Iterable, List, Optional, Tuple

SCHEMA_VERSION = 1
_MAX_GRAPH_URLS = 200
_TECH_HEADERS = (
    "server",
    "x-powered-by",
    "x-aspnet-version",
    "x-generator",
    "x-drupal-cache",
)


def endpoint_key(url: str) -> str:
    """Endpoint identity: absolute URL with query/fragment stripped."""
    parts = urllib.parse.urlparse(url)
    scheme = parts.scheme.lower()
    netloc = (parts.netloc or "").lower()
    path = parts.path or "/"
    return urllib.parse.urlunparse((scheme, netloc, path, "", "", ""))


def new_surface(origins: Iterable[str]) -> Dict:
    return {
        "schema_version": SCHEMA_VERSION,
        "origins": list(dict.fromkeys(origins)),
        "tech": {},
        "endpoints": {},
        "api_ops": [],
        "external": [],
        "counts": {},
    }


def upsert_endpoint(
    surface: Dict,
    url: str,
    *,
    method: Optional[str] = None,
    methods: Optional[Iterable[str]] = None,
    params: Optional[Dict[str, str]] = None,
    status: Optional[int] = None,
    depth: Optional[int] = None,
    content_type: Optional[str] = None,
    title: Optional[str] = None,
    auth_seen: Optional[bool] = None,
) -> Dict:
    key = endpoint_key(url)
    endpoints = surface.setdefault("endpoints", {})
    entry = endpoints.get(key)
    if entry is None:
        entry = {
            "url": key,
            "sample_url": url,
            "methods": [],
            "params": {},
            "status": None,
            "depth": None,
            "content_type": None,
            "title": None,
            "auth_seen": False,
        }
        endpoints[key] = entry
    if url and ("?" in url) and not entry.get("sample_url"):
        entry["sample_url"] = url
    for m in filter(None, ([method] if method else []) + list(methods or [])):
        m = m.upper()
        if m and m not in entry["methods"]:
            entry["methods"].append(m)
    for name, where in (params or {}).items():
        if name:
            entry["params"].setdefault(str(name), where)
    if status is not None:
        entry["status"] = int(status)
    if depth is not None:
        current = entry.get("depth")
        entry["depth"] = depth if current is None else min(current, depth)
    if content_type:
        entry["content_type"] = content_type
    if title and not entry.get("title"):
        entry["title"] = title
    if auth_seen:
        entry["auth_seen"] = True
    return entry


def add_tech(surface: Dict, headers: Dict[str, str]) -> None:
    tech = surface.setdefault("tech", {})
    for name in _TECH_HEADERS:
        value = headers.get(name)
        if value and name not in tech:
            tech[name] = value


def finalize(surface: Dict) -> Dict:
    endpoints = surface.get("endpoints", {})
    surface["counts"] = {
        "endpoints": len(endpoints),
        "with_status": sum(1 for e in endpoints.values() if e.get("status")),
        "with_params": sum(1 for e in endpoints.values() if e.get("params")),
        "methods": sum(len(e.get("methods") or []) for e in endpoints.values()),
        "api_ops": len(surface.get("api_ops") or []),
    }
    return surface


def endpoint_urls(surface: Dict) -> List[str]:
    return sorted(surface.get("endpoints", {}))


def api_coverage(surface: Dict) -> Dict[str, object]:
    """Spec-declared API operations vs methods verified on the surface."""
    ops = surface.get("api_ops") or []
    origins = surface.get("origins") or []
    base = str(origins[0]).rstrip("/") if origins else ""
    endpoints = surface.get("endpoints") or {}
    unverified: List[Dict[str, str]] = []
    for op in ops:
        method = str(op.get("method") or "")
        path = str(op.get("path") or "")
        if not method or not path or not base:
            continue
        entry = endpoints.get(endpoint_key(base + path))
        if entry is None or method not in (entry.get("methods") or []):
            unverified.append({"method": method, "path": path})
    return {"api_ops": len(ops), "api_ops_unverified": unverified}


def query_endpoints(surface: Dict, limit: int = 8) -> List[Tuple[str, List[str]]]:
    """(url, query-param-names) pairs whose query params can be probed."""
    out: List[Tuple[str, List[str]]] = []
    for key in endpoint_urls(surface):
        entry = surface["endpoints"][key]
        query_params = sorted(
            name for name, where in entry.get("params", {}).items()
            if where == "query"
        )
        if not query_params:
            continue
        methods = [m.upper() for m in (entry.get("methods") or [])]
        if methods and "GET" not in methods and "HEAD" not in methods:
            continue
        out.append((key, query_params))
        if len(out) >= limit:
            break
    return out


def html_endpoints(surface: Dict, limit: int = 8) -> List[str]:
    out: List[str] = []
    for key in endpoint_urls(surface):
        entry = surface["endpoints"][key]
        if entry.get("status") and not (200 <= entry["status"] < 300):
            continue
        ctype = entry.get("content_type") or ""
        if ctype.startswith("text/html") or (not ctype and entry.get("title")):
            out.append(key)
        if len(out) >= limit:
            break
    return out


# ---------------------------------------------------------------------------
# Recon → asset graph (ASSET DISCOVERY)
# ---------------------------------------------------------------------------

def recon_to_graph(recon, origins: Iterable[str]):
    """Fold recon results into an AssetGraph (§7.2 nodes/edges).

    `recon` may be a ReconResult (same run) or the dict committed as
    recon.json (resume).
    """
    from types import SimpleNamespace

    from velora.assets.graph import AssetGraph

    if isinstance(recon, dict):
        recon = SimpleNamespace(**recon)
    graph = AssetGraph()
    origins = list(dict.fromkeys(origins))
    scheme_by_origin = {o: urllib.parse.urlparse(o).scheme for o in origins}
    for origin in origins:
        parts = urllib.parse.urlparse(origin)
        host = (parts.hostname or "").lower()
        if not host:
            continue
        scheme = parts.scheme or "http"
        port = parts.port or (443 if scheme == "https" else 80)
        domain = graph.add_node("domain", host, host=host)
        for ip in _resolve_ips(host):
            node = graph.add_node("host", ip, ip=ip)
            graph.add_edge(domain.id, node.id, "resolves_to")
        port_node = graph.add_node("port", f"{host}:{port}",
                                   host=host, port=port, scheme=scheme)
        graph.add_edge(domain.id, port_node.id, "hosts")
        service = graph.add_node("service", scheme, scheme=scheme)
        graph.add_edge(port_node.id, service.id, "exposes")
    seen_urls = 0
    for url in _all_urls(recon, origins):
        if seen_urls >= _MAX_GRAPH_URLS:
            break
        seen_urls += 1
        host = (urllib.parse.urlparse(url).hostname or "").lower()
        domain = graph.get(f"domain:{host}")
        url_node = graph.add_node("url", url, url=url)
        if domain is not None:
            graph.add_edge(domain.id, url_node.id, "hosts")
        endpoint = _endpoint_of(recon, url)
        if endpoint:
            label = f"{endpoint['method']} {urllib.parse.urlparse(url).path or '/'}"
            ep_node = graph.add_node(
                "endpoint", label,
                method=endpoint["method"],
                route=urllib.parse.urlparse(url).path or "/",
            )
            graph.add_edge(url_node.id, ep_node.id, "exposes")
    return graph


def _resolve_ips(host: str) -> List[str]:
    try:
        infos = socket.getaddrinfo(host, None)
    except OSError:
        return []
    ips = []
    for info in infos:
        addr = info[4][0]
        if addr not in ips:
            ips.append(addr)
    return ips


def _all_urls(recon, origins: Iterable[str]) -> List[str]:
    urls: List[str] = []
    origin_set = set(origins)
    for url in list(getattr(recon, "discovered", [])) + list(
        getattr(recon, "endpoints", {})
    ):
        origin = urllib.parse.urlunparse(
            urllib.parse.urlparse(url)._replace(path="", params="", query="", fragment="")
        )
        if origin in origin_set or urllib.parse.urlparse(url).netloc in {
            urllib.parse.urlparse(o).netloc for o in origin_set
        }:
            urls.append(url)
    return list(dict.fromkeys(urls))


def _endpoint_of(recon, url: str) -> Optional[Dict]:
    endpoints = getattr(recon, "endpoints", {}) or {}
    data = endpoints.get(url)
    if not data:
        return None
    methods = [m.upper() for m in (data.get("methods") or ["GET"])]
    return {"method": methods[0] if methods else "GET"}


def split_origin_params(url: str) -> Tuple[str, Dict[str, str]]:
    """URL → (endpoint key, {query param: 'query'})."""
    parts = urllib.parse.urlparse(url)
    query = urllib.parse.parse_qs(parts.query)
    return endpoint_key(url), {name: "query" for name in query}
