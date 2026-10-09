"""INGEST extension tests: dependency manifests + IaC adapters (§10)."""

from pathlib import Path

from velora.assets.graph import EDGE_KINDS, NODE_KINDS, AssetGraph
from velora.assets.ingest import absorb, discover_manifest_assets


def _discover(tmp_path) -> dict:
    return discover_manifest_assets(tmp_path)


def _nodes(result, kind):
    return result["graph"].by_kind(kind)


def test_requirements_txt(tmp_path):
    (tmp_path / "requirements.txt").write_text(
        "flask==2.0.1\n"
        "requests>=2.28,<3  # pinned range\n"
        "# full comment\n"
        "-r other.txt\n"
        "-e .\n"
        "git+https://example.com/x.git\n"
        "Django\n"
    )
    result = _discover(tmp_path)
    deps = _nodes(result, "dependency")
    names = {n.props["name"]: n for n in deps}
    assert set(names) == {"flask", "requests", "Django"}
    assert names["flask"].props["version"] == "==2.0.1"
    assert names["requests"].props["version"] == ">=2.28,<3"
    assert names["Django"].props["version"] == ""
    assert all(n.props["manager"] == "pip" for n in deps)
    assert result["stats"]["dependencies"] == 3
    assert result["stats"]["dependencies"] == 3


def test_package_json_dependencies(tmp_path):
    (tmp_path / "package.json").write_text(
        '{"dependencies": {"lodash": "^4.17.21"},'
        ' "devDependencies": {"jest": "29.x"}}'
    )
    result = _discover(tmp_path)
    names = {n.props["name"]: n.props for n in _nodes(result, "dependency")}
    assert names["lodash"] == {
        "name": "lodash", "version": "^4.17.21", "manager": "npm",
        "source_file": "package.json",
    }
    assert names["jest"]["version"] == "29.x"
    assert result["stats"]["dependencies"] == 2


def test_pyproject_and_markers(tmp_path):
    (tmp_path / "pyproject.toml").write_text(
        '[project]\n'
        'name = "demo"\n'
        'dependencies = ["requests>=2.0", "uvicorn[standard]==0.23.0",\n'
        '                \'pywin32; sys_platform == "win32"\']\n'
        '[project.optional-dependencies]\n'
        'dev = ["pytest>=7"]\n'
    )
    result = _discover(tmp_path)
    names = {n.props["name"]: n for n in _nodes(result, "dependency")}
    assert names["requests"].props["version"] == ">=2.0"
    assert names["uvicorn"].props["version"] == "==0.23.0"
    assert names["pywin32"].props["version"] == ""
    assert names["pytest"].props["version"] == ">=7"
    assert result["stats"]["dependencies"] == 4


def test_go_mod_single_and_block(tmp_path):
    (tmp_path / "go.mod").write_text(
        "module example.com/app\n"
        "go 1.22\n"
        "require github.com/gin-gonic/gin v1.9.1\n"
        "require (\n"
        "\tgithub.com/stretchr/testify v1.8.4\n"
        "\tgolang.org/x/text v0.14.0 // indirect\n"
        ")\n"
    )
    result = _discover(tmp_path)
    names = {n.props["name"]: n for n in _nodes(result, "dependency")}
    assert names["github.com/gin-gonic/gin"].props["version"] == "v1.9.1"
    assert names["github.com/stretchr/testify"].props["version"] == "v1.8.4"
    assert names["golang.org/x/text"].props["version"] == "v0.14.0"
    assert all(n.props["manager"] == "go" for n in _nodes(result, "dependency"))


def test_gemfile_and_cargo_and_pom(tmp_path):
    (tmp_path / "Gemfile").write_text(
        "source 'https://rubygems.org'\n"
        "gem 'rails', '~> 7.1'\n"
        "gem 'puma'\n"
    )
    (tmp_path / "Cargo.toml").write_text(
        "[package]\nname = \"demo\"\n"
        '[dependencies]\nserde = "1.0"\n'
        '[dependencies.rand]\nversion = "0.8"\n'
        '[dev-dependencies]\npretty_assertions = "*"\n'
    )
    (tmp_path / "pom.xml").write_text(
        "<project><dependencies>"
        "<dependency><groupId>org.apache.commons</groupId>"
        "<artifactId>commons-lang3</artifactId>"
        "<version>3.14.0</version></dependency>"
        "<dependency><groupId>junit</groupId>"
        "<artifactId>junit</artifactId></dependency>"
        "</dependencies></project>"
    )
    result = _discover(tmp_path)
    by_manager = {}
    for node in _nodes(result, "dependency"):
        by_manager.setdefault(node.props["manager"], {})[
            node.props["name"]] = node.props["version"]
    assert by_manager["gem"] == {"rails": "~> 7.1", "puma": ""}
    assert by_manager["cargo"] == {"serde": "1.0", "rand": "0.8",
                                   "pretty_assertions": "*"}
    assert by_manager["maven"] == {
        "org.apache.commons:commons-lang3": "3.14.0",
        "junit:junit": "",
    }


def test_dockerfile_images(tmp_path):
    (tmp_path / "Dockerfile").write_text(
        "# syntax=docker/dockerfile:1\n"
        "FROM --platform=linux/amd64 python:3.12-slim AS builder\n"
        "FROM scratch\n"
        "FROM ${BASE_IMAGE}\n"
        "FROM registry.example:5000/nginx:1.25\n"
        "COPY --from=builder /app /app\n"
    )
    result = _discover(tmp_path)
    workloads = _nodes(result, "workload")
    labels = {n.label for n in workloads}
    assert labels == {"python:3.12-slim", "registry.example:5000/nginx:1.25"}
    by_label = {n.label: n for n in workloads}
    assert by_label["python:3.12-slim"].props["image"] == "python"
    assert by_label["python:3.12-slim"].props["tag"] == "3.12-slim"
    assert by_label["python:3.12-slim"].props["stage"] == "builder"
    reg = by_label["registry.example:5000/nginx:1.25"]
    assert reg.props["image"] == "registry.example:5000/nginx"
    assert reg.props["tag"] == "1.25"
    assert result["stats"]["containers"] == 2


def test_compose_services(tmp_path):
    (tmp_path / "docker-compose.yml").write_text(
        "services:\n"
        "  web:\n"
        "    image: nginx:1.25\n"
        "  worker:\n"
        "    build: ./worker\n"
        "  db:\n"
        "    image: postgres:16\n"
    )
    result = _discover(tmp_path)
    props = {n.props["service"]: n.props for n in _nodes(result, "workload")}
    assert props["web"]["image"] == "nginx"
    assert props["web"]["tag"] == "1.25"
    assert props["worker"]["image"] == "worker"  # build-only → service name
    assert props["db"]["image"] == "postgres"
    assert result["stats"]["containers"] == 3


def test_compose_skipped_without_yaml(monkeypatch, tmp_path):
    import velora.assets.ingest as ingest
    (tmp_path / "docker-compose.yml").write_text(
        "services:\n  web:\n    image: nginx:1.25\n"
    )
    monkeypatch.setattr(ingest, "yaml", None)
    result = _discover(tmp_path)
    assert _nodes(result, "workload") == []
    assert "containers" not in result["stats"]


def test_k8s_manifests(tmp_path):
    (tmp_path / "deploy.yml").write_text(
        "apiVersion: apps/v1\n"
        "kind: Deployment\n"
        "metadata:\n  name: api\n"
        "spec:\n  template:\n    spec:\n      containers:\n"
        "      - name: api\n        image: ghcr.io/acme/api:1.4\n"
        "---\n"
        "apiVersion: v1\n"
        "kind: Service\n"
        "metadata:\n  name: api\n"
        "spec:\n  ports:\n  - port: 8080\n"
        "---\n"
        "apiVersion: v1\n"
        "kind: Secret\n"
        "metadata:\n  name: db\n"
        "type: Opaque\n"
        "stringData:\n  password: hunter2\n"
        "---\n"
        "apiVersion: v1\n"
        "kind: ServiceAccount\n"
        "metadata:\n  name: runner\n"
    )
    result = _discover(tmp_path)
    workload = _nodes(result, "workload")[0]
    assert workload.label == "Deployment/api"
    assert workload.props["images"] == ["ghcr.io/acme/api:1.4"]
    service = _nodes(result, "service")[0]
    assert service.label == "Service/api"
    assert service.props["ports"] == [8080]
    secret = _nodes(result, "config")[0]
    assert secret.label == "Secret/db"
    assert secret.props["secret_type"] == "Opaque"
    assert "hunter2" not in str(secret.props)  # payload never recorded
    identity = _nodes(result, "identity")[0]
    assert identity.label == "ServiceAccount/runner"
    assert result["stats"]["kubernetes"] == 4


def test_non_k8s_yaml_excluded(tmp_path):
    (tmp_path / "ci.yml").write_text("stages:\n  - build\n  - test\n")
    result = _discover(tmp_path)
    assert all(n.kind != "file" for n in result["graph"])
    assert result["stats"] == {}


def test_terraform_resources(tmp_path):
    (tmp_path / "infra.tf").write_text(
        'resource "aws_s3_bucket" "data" {\n  bucket = "x"\n}\n'
        'resource "aws_instance" "web" {\n  ami = "ami-1"\n}\n'
        'resource "aws_iam_role" "runner" {\n  name = "r"\n}\n'
    )
    result = _discover(tmp_path)
    assert {n.label for n in _nodes(result, "bucket")} == {
        "aws_s3_bucket.data"}
    assert {n.label for n in _nodes(result, "workload")} == {
        "aws_instance.web"}
    assert {n.label for n in _nodes(result, "identity")} == {
        "aws_iam_role.runner"}
    assert result["stats"]["terraform"] == 3


def test_vendor_dirs_skipped(tmp_path):
    vendor = tmp_path / "node_modules" / "pkg"
    vendor.mkdir(parents=True)
    (vendor / "package.json").write_text('{"dependencies": {"x": "1.0"}}')
    (tmp_path / "requirements.txt").write_text("flask==1.0\n")
    result = _discover(tmp_path)
    deps = _nodes(result, "dependency")
    assert [n.props["name"] for n in deps] == ["flask"]


def test_edges_and_kinds_registry(tmp_path):
    (tmp_path / "requirements.txt").write_text("flask==2.0.1\n")
    (tmp_path / "Dockerfile").write_text("FROM alpine:3.19\n")
    result = _discover(tmp_path)
    graph = result["graph"]
    edge_kinds = {e.kind for e in graph.edges}
    assert "depends_on" in edge_kinds
    assert "exposes" in edge_kinds
    assert "dependency" in NODE_KINDS
    assert "config" in NODE_KINDS
    assert "depends_on" in EDGE_KINDS
    file_node = graph.get("file:requirements.txt")
    dep = graph.get("dependency:flask@==2.0.1")
    assert file_node is not None and dep is not None
    assert any(e.src == file_node.id and e.dst == dep.id
               for e in graph.edges_of_kind("depends_on"))


def test_absorb_merges_graphs(tmp_path):
    (tmp_path / "requirements.txt").write_text("flask==2.0.1\n")
    result = _discover(tmp_path)
    target = AssetGraph()
    target.add_node("file", "requirements.txt", extra="kept")
    absorb(target, result["graph"])
    assert target.get("dependency:flask@==2.0.1") is not None
    assert target.get("file:requirements.txt").props["extra"] == "kept"
    assert target.summary()["dependency"] == 1


def test_missing_root_is_empty():
    result = discover_manifest_assets(Path("/nonexistent/velora-path"))
    assert len(result["graph"]) == 0
    assert result["stats"] == {}
