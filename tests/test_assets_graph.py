"""Tests for the universal asset graph and its kind-keyed slices (§7.2)."""

from pathlib import Path

from velora.assets.graph import AssetGraph, discover_code_assets, node_id


class TestGraphCore:
    def test_add_and_get_node(self):
        g = AssetGraph()
        node = g.add_node("host", "api.example.com", port=443)
        assert g.get(node.id) is node
        assert node.id == "host:api.example.com"
        assert g.get("host:nope") is None

    def test_add_is_idempotent_and_merges_props(self):
        g = AssetGraph()
        g.add_node("endpoint", "GET /x", method="GET")
        g.add_node("endpoint", "GET /x", handler="view")
        node = g.get(node_id("endpoint", "GET /x"))
        assert node.props["method"] == "GET"
        assert node.props["handler"] == "view"
        assert len(g) == 1

    def test_edges_deduped_and_kinded(self):
        g = AssetGraph()
        a = g.add_node("file", "a.py")
        b = g.add_node("code_symbol", "a.py::f")
        g.add_edge(a.id, b.id, "exposes")
        g.add_edge(a.id, b.id, "exposes", line=1)
        assert len(g.edges) == 1
        assert g.edges_of_kind("exposes")
        assert not g.edges_of_kind("hosts")

    def test_slice_is_induced_by_kind(self):
        g = AssetGraph()
        f = g.add_node("file", "app.py")
        s = g.add_node("code_symbol", "app.py::home")
        e = g.add_node("endpoint", "GET /")
        h = g.add_node("host", "example.com")
        g.add_edge(f.id, s.id, "exposes")
        g.add_edge(s.id, e.id, "routes_to")
        g.add_edge(h.id, e.id, "hosts")

        code_slice = g.slice(["file", "code_symbol", "endpoint"])
        assert {n.kind for n in code_slice} == {"file", "code_symbol", "endpoint"}
        assert len(code_slice.edges) == 2
        assert not any(e.kind == "hosts" for e in code_slice.edges)

        host_slice = g.slice(["host"])
        assert len(host_slice) == 1
        assert host_slice.edges == []

    def test_roundtrip(self):
        g = AssetGraph()
        g.add_node("url", "https://x/a", status=200)
        g.add_node("domain", "x")
        g.add_edge("domain:x", "url:https://x/a", "resolves_to")
        restored = AssetGraph.from_dict(g.to_dict())
        assert len(restored) == 2
        assert len(restored.edges) == 1
        assert restored.get("url:https://x/a").props["status"] == 200

    def test_from_dict_tolerates_garbage(self):
        assert len(AssetGraph.from_dict(None)) == 0
        assert len(AssetGraph.from_dict({})) == 0
        assert len(AssetGraph.from_dict({"nodes": "x"})) == 0

    def test_summary_counts_kinds(self):
        g = AssetGraph()
        g.add_node("file", "a")
        g.add_node("file", "b")
        g.add_node("endpoint", "GET /")
        assert g.summary() == {"file": 2, "endpoint": 1}


class TestCodeDiscovery:
    FLASK = """
from flask import Flask
app = Flask(__name__)

@app.route("/login", methods=["POST"])
def login():
    return "ok"
"""

    FASTAPI = """
from fastapi import FastAPI
api = FastAPI()

@api.get("/items")
def items():
    return []
"""

    DJANGO_URLS = """
from django.urls import path
urlpatterns = [path("admin/", lambda r: None)]
"""

    def _write(self, tmp_path: Path, name: str, body: str) -> Path:
        path = tmp_path / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(body, encoding="utf-8")
        return path

    def test_files_and_symbols(self, tmp_path):
        self._write(tmp_path, "app.py", "def view():\n    pass\n")
        g = discover_code_assets(tmp_path)
        assert g.get("file:app.py") is not None
        assert g.get("code_symbol:app.py::view") is not None
        edge_ids = {(e.src, e.dst) for e in g.edges}
        assert ("file:app.py", "code_symbol:app.py::view") in edge_ids

    def test_flask_and_fastapi_endpoints(self, tmp_path):
        self._write(tmp_path, "web.py", self.FLASK)
        self._write(tmp_path, "api.py", self.FASTAPI)
        g = discover_code_assets(tmp_path)
        assert g.get(node_id("endpoint", "POST /login")) is not None
        assert g.get(node_id("endpoint", "GET /items")) is not None
        routes = {e.dst for e in g.edges_of_kind("routes_to")}
        assert "endpoint:POST /login" in routes
        assert "endpoint:GET /items" in routes

    def test_django_urls(self, tmp_path):
        self._write(tmp_path, "urls.py", self.DJANGO_URLS)
        g = discover_code_assets(tmp_path)
        assert g.get(node_id("endpoint", "ANY admin/")) is not None

    def test_single_file_input(self, tmp_path):
        path = self._write(tmp_path, "one.py", "class C:\n    pass\n")
        g = discover_code_assets(path)
        assert g.get("code_symbol:one.py::C") is not None

    def test_unparsable_file_still_yields_node(self, tmp_path):
        self._write(tmp_path, "broken.py", "def (((")
        g = discover_code_assets(tmp_path)
        assert g.get("file:broken.py") is not None

    def test_slice_of_discovered(self, tmp_path):
        self._write(tmp_path, "web.py", self.FLASK)
        g = discover_code_assets(tmp_path)
        endpoints = g.slice(["endpoint"])
        assert len(endpoints) == 1
        assert endpoints.kinds_present(["endpoint"]) == ["endpoint"]
