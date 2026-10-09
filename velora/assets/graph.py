"""Universal asset graph (finalplan §7.2): nodes, edges, kind-keyed slices.

Nodes carry a kind (file, code_symbol, endpoint, url, host, …) plus
properties; edges typed (resolves_to, hosts, exposes, routes_to, calls).
Workers receive *slices* keyed by asset kind — the dispatch rule that
makes the mode graphs asset-agnostic. Serialized as `assets.json` in the
session dir.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, Iterable, Iterator, List, Optional, Sequence, Set

EDGE_KINDS = ("resolves_to", "hosts", "exposes", "routes_to", "calls",
              "depends_on")
NODE_KINDS = (
    "file",
    "code_symbol",
    "endpoint",
    "domain",
    "host",
    "port",
    "service",
    "url",
    "api_operation",
    "workload",
    "bucket",
    "identity",
    "dependency",
    "config",
)


@dataclass
class Node:
    id: str
    kind: str
    label: str
    props: Dict = field(default_factory=dict)

    def to_dict(self) -> Dict:
        return {"id": self.id, "kind": self.kind, "label": self.label, "props": dict(self.props)}

    @classmethod
    def from_dict(cls, data: Dict) -> "Node":
        return cls(
            id=data["id"],
            kind=data["kind"],
            label=data.get("label", data["id"]),
            props=dict(data.get("props", {})),
        )


@dataclass
class Edge:
    src: str
    dst: str
    kind: str
    props: Dict = field(default_factory=dict)

    def to_dict(self) -> Dict:
        return {"src": self.src, "dst": self.dst, "kind": self.kind, "props": dict(self.props)}

    @classmethod
    def from_dict(cls, data: Dict) -> "Edge":
        return cls(
            src=data["src"],
            dst=data["dst"],
            kind=data["kind"],
            props=dict(data.get("props", {})),
        )


def node_id(kind: str, name: str) -> str:
    return f"{kind}:{name}"


class AssetGraph:
    def __init__(self, nodes: Optional[Iterable[Node]] = None,
                 edges: Optional[Iterable[Edge]] = None):
        self._nodes: Dict[str, Node] = {}
        self._edges: Dict[tuple, Edge] = {}
        for node in nodes or ():
            self._nodes[node.id] = node
        for edge in edges or ():
            self._edges[(edge.src, edge.dst, edge.kind)] = edge

    # -- construction ----------------------------------------------------

    def add_node(self, kind: str, label: str, **props) -> Node:
        nid = node_id(kind, label)
        existing = self._nodes.get(nid)
        if existing is not None:
            existing.props.update({k: v for k, v in props.items() if v is not None})
            return existing
        node = Node(id=nid, kind=kind, label=str(label), props=dict(props))
        self._nodes[nid] = node
        return node

    def add_edge(self, src: str, dst: str, kind: str, **props) -> Edge:
        key = (src, dst, kind)
        existing = self._edges.get(key)
        if existing is not None:
            existing.props.update({k: v for k, v in props.items() if v is not None})
            return existing
        edge = Edge(src=src, dst=dst, kind=kind, props=dict(props))
        self._edges[key] = edge
        return edge

    # -- access ----------------------------------------------------------

    def get(self, nid: str) -> Optional[Node]:
        return self._nodes.get(nid)

    def __contains__(self, nid: str) -> bool:
        return nid in self._nodes

    def __len__(self) -> int:
        return len(self._nodes)

    def __iter__(self) -> Iterator[Node]:
        return iter(self._nodes.values())

    @property
    def edges(self) -> List[Edge]:
        return list(self._edges.values())

    def by_kind(self, kind: str) -> List[Node]:
        return [n for n in self._nodes.values() if n.kind == kind]

    def kinds(self) -> List[str]:
        seen: Set[str] = set()
        for node in self._nodes.values():
            seen.add(node.kind)
        return sorted(seen)

    def edges_of_kind(self, kind: str) -> List[Edge]:
        return [e for e in self._edges.values() if e.kind == kind]

    # -- slices ----------------------------------------------------------

    def slice(self, kinds: Sequence[str]) -> "AssetGraph":
        """Induced subgraph over nodes of the given kinds (both endpoints)."""
        wanted = set(kinds)
        keep = {n.id for n in self._nodes.values() if n.kind in wanted}
        nodes = [self._nodes[nid] for nid in sorted(keep)]
        edges = [
            e for e in self._edges.values() if e.src in keep and e.dst in keep
        ]
        return AssetGraph(nodes=nodes, edges=edges)

    def kinds_present(self, kinds: Sequence[str]) -> List[str]:
        wanted = set(kinds)
        return sorted({n.kind for n in self._nodes.values() if n.kind in wanted})

    # -- serialization ---------------------------------------------------

    def to_dict(self) -> Dict:
        return {
            "nodes": [n.to_dict() for n in self._nodes.values()],
            "edges": [e.to_dict() for e in self._edges.values()],
        }

    @classmethod
    def from_dict(cls, data: Dict) -> "AssetGraph":
        if not isinstance(data, dict):
            return cls()
        raw_nodes = data.get("nodes", [])
        raw_edges = data.get("edges", [])
        if not isinstance(raw_nodes, list) or not isinstance(raw_edges, list):
            return cls()
        nodes = [
            Node.from_dict(n) for n in raw_nodes
            if isinstance(n, dict) and "id" in n and "kind" in n
        ]
        edges = [
            Edge.from_dict(e) for e in raw_edges
            if isinstance(e, dict)
            and all(k in e for k in ("src", "dst", "kind"))
        ]
        return cls(nodes=nodes, edges=edges)

    def summary(self) -> Dict[str, int]:
        counts: Dict[str, int] = {}
        for node in self._nodes.values():
            counts[node.kind] = counts.get(node.kind, 0) + 1
        return counts


_ROUTE_DECORATOR_NAMES = {
    "route": None,
    "get": "GET", "post": "POST", "put": "PUT", "delete": "DELETE",
    "patch": "PATCH", "head": "HEAD", "options": "OPTIONS",
}


def discover_code_assets(
    root: Path,
    pattern: str = "**/*.py",
    files: Optional[List[Path]] = None,
) -> AssetGraph:
    """Code-derived assets: file nodes, symbols, and detected endpoints.

    `files` overrides globbing when the caller already enumerated the tree
    (the INGEST stage applies scan exclusions before ASSET MODEL runs)."""
    graph = AssetGraph()
    root = Path(root)
    if files is not None:
        enumerated = [Path(p) for p in files]
        base = root.parent if root.is_file() else root
    elif root.is_file():
        enumerated = [root]
        base = root.parent
    else:
        enumerated = sorted(p for p in root.glob(pattern) if p.is_file())
        base = root
    for path in enumerated:
        rel = str(path.relative_to(base)) if path.is_relative_to(base) else str(path)
        file_node = graph.add_node("file", rel, path=str(path))
        try:
            tree = ast.parse(path.read_text(encoding="utf-8", errors="replace"))
        except (OSError, SyntaxError, ValueError):
            continue
        _walk_module(graph, tree, file_node, rel)
    return graph


def _walk_module(graph: AssetGraph, tree: ast.AST, file_node: Node, rel: str) -> None:
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            symbol = graph.add_node(
                "code_symbol",
                f"{rel}::{node.name}",
                name=node.name,
                line=getattr(node, "lineno", None),
                file=rel,
            )
            graph.add_edge(file_node.id, symbol.id, "exposes")
            _maybe_endpoint(graph, node, symbol, rel)
        elif isinstance(node, ast.Call):
            _maybe_call_endpoint(graph, node, file_node, rel)


def _call_name(call: ast.Call) -> str:
    func = call.func
    parts: List[str] = []
    while isinstance(func, ast.Attribute):
        parts.append(func.attr)
        func = func.value
    if isinstance(func, ast.Name):
        parts.append(func.id)
    return ".".join(reversed(parts))


def _first_arg_string(call: ast.Call) -> Optional[str]:
    if call.args:
        arg = call.args[0]
        if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
            return arg.value
    return None


def _decorator_methods(call: ast.Call, default: str) -> List[str]:
    for keyword in call.keywords:
        if keyword.arg == "methods":
            value = keyword.value
            if isinstance(value, (ast.List, ast.Tuple)):
                methods = [
                    elt.value for elt in value.elts
                    if isinstance(elt, ast.Constant) and isinstance(elt.value, str)
                ]
                if methods:
                    return [m.upper() for m in methods]
            if isinstance(value, ast.Constant) and isinstance(value.value, str):
                return [value.value.upper()]
    return [default]


def _maybe_endpoint(graph: AssetGraph, node, symbol: Node, rel: str) -> None:
    for decorator in getattr(node, "decorator_list", []):
        if not isinstance(decorator, ast.Call):
            continue
        name = _call_name(decorator)
        leaf = name.rsplit(".", 1)[-1]
        if leaf not in _ROUTE_DECORATOR_NAMES:
            continue
        route = _first_arg_string(decorator)
        if route is None:
            continue
        methods = _decorator_methods(decorator, _ROUTE_DECORATOR_NAMES[leaf] or "GET")
        for method in methods:
            endpoint = graph.add_node(
                "endpoint",
                f"{method} {route}",
                method=method,
                route=route,
                handler=getattr(node, "name", None),
                file=rel,
            )
            graph.add_edge(symbol.id, endpoint.id, "routes_to")


def _maybe_call_endpoint(graph: AssetGraph, call: ast.Call, file_node: Node, rel: str) -> None:
    name = _call_name(call)
    if name.endswith(("path", "re_path", "url")) and "urls" in rel.replace("\\", "/"):
        route = _first_arg_string(call)
        if route:
            endpoint = graph.add_node(
                "endpoint",
                f"ANY {route}",
                method="ANY",
                route=route,
                file=rel,
            )
            graph.add_edge(file_node.id, endpoint.id, "routes_to")
