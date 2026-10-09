"""INGEST extensions: dependency manifests + IaC/config assets (§10).

Pure local parsing — no network, no vendor-tree walks (node_modules,
.venv, target, … are skipped). Produces graph nodes:

  dependency   pip/npm/go/gem/cargo/maven manifests (name + version spec)
  workload     container images (Dockerfile FROM, compose services) and
               terraform resources that are not buckets/identities
  bucket       storage-bucket resources (terraform)
  identity     IAM-style resources (terraform) / RBAC objects (k8s)
  service      k8s Service objects
  config       ConfigMap / Secret (name+type only) / Ingress / other yamls

Edges: manifest file --depends_on--> dependency; IaC file --exposes-->
declared object. YAML parsing is optional (PyYAML): without it, yaml
files are skipped rather than failed.
"""
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Dict, Iterator, List, Optional, Tuple

try:  # PyYAML is a dev/optional dependency — never required at runtime.
    import yaml  # type: ignore
except Exception:  # pragma: no cover - environment without PyYAML
    yaml = None  # type: ignore

try:
    import tomllib
except ModuleNotFoundError:  # pragma: no cover - pre-3.11
    tomllib = None  # type: ignore

MAX_MANIFESTS = 400
MAX_YAML_FILES = 100
MAX_TF_FILES = 100

_SKIP_DIRS = frozenset({
    "node_modules", ".git", ".venv", "venv", "env", "dist", "build",
    "target", "vendor", "__pycache__", ".tox", ".mypy_cache",
    ".pytest_cache", "site-packages", ".eggs",
})

_MANIFEST_NAMES = frozenset({
    "package.json", "pyproject.toml", "go.mod", "Gemfile", "Cargo.toml",
    "pom.xml",
})

_REQ_LINE = re.compile(
    r"^([A-Za-z0-9][A-Za-z0-9._-]*)\s*((?:[=<>!~]=|[<>=!~]).*)?$"
)
_PEP508 = re.compile(
    r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)\s*(?:\[[^\]]*\])?\s*(.*)$"
)
_GO_REQUIRE = re.compile(r"^require\s+(\S+)\s+(\S+)\s*(?://.*)?$")
_GO_BLOCK = re.compile(r"^(\S+)\s+(v\S+)\s*(?://.*)?$")
_GEM = re.compile(r"""^\s*gem\s+['"]([^'"]+)['"]\s*(?:,\s*['"]([^'"]+)['"])?""")
_POM_DEP = re.compile(r"<dependency>(.*?)</dependency>", re.S)
_POM_GROUP = re.compile(r"<groupId>\s*([^<]+?)\s*</groupId>")
_POM_ARTIFACT = re.compile(r"<artifactId>\s*([^<]+?)\s*</artifactId>")
_POM_VERSION = re.compile(r"<version>\s*([^<]+?)\s*</version>")
_FROM = re.compile(
    r"^\s*FROM\s+(?:--platform=\S+\s+)?(\S+)(?:\s+AS\s+(\S+))?\s*$", re.I
)
_TF_RESOURCE = re.compile(r'resource\s+"([^"]+)"\s+"([^"]+)"')


def _rel(path: Path, base: Path) -> str:
    try:
        return str(path.resolve().relative_to(base.resolve()))
    except ValueError:
        return str(path)


def _skipped(path: Path) -> bool:
    return any(part in _SKIP_DIRS for part in path.parts)


def _add_file(graph, path: Path, base: Path):
    rel = _rel(path, base)
    return graph.add_node("file", rel, path=str(path)), rel


def _add_dependency(graph, file_node, name: str, version: str,
                    manager: str, rel: str) -> None:
    name = str(name).strip()
    if not name or len(name) > 200:
        return
    version = str(version or "").strip()
    label = f"{name}@{version}" if version else name
    dep = graph.add_node(
        "dependency", label,
        name=name, version=version, manager=manager, source_file=rel,
    )
    graph.add_edge(file_node.id, dep.id, "depends_on")


# -- dependency manifests ---------------------------------------------------

def _parse_requirements(path: Path, graph, file_node, rel: str) -> int:
    count = 0
    for raw in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = raw.split(" #", 1)[0].strip()
        if not line or line.startswith(("#", "-", "http:", "https:", ".")):
            continue
        match = _REQ_LINE.match(line)
        if match is None:
            continue
        _add_dependency(graph, file_node, match.group(1),
                        match.group(2) or "", "pip", rel)
        count += 1
    return count


def _parse_package_json(path: Path, graph, file_node, rel: str) -> int:
    try:
        data = json.loads(path.read_text(encoding="utf-8", errors="replace"))
    except (ValueError, TypeError):
        return 0
    if not isinstance(data, dict):
        return 0
    count = 0
    for section, manager in (("dependencies", "npm"),
                             ("devDependencies", "npm")):
        block = data.get(section)
        if not isinstance(block, dict):
            continue
        for name, version in block.items():
            _add_dependency(graph, file_node, str(name),
                            str(version) if version is not None else "",
                            manager, rel)
            count += 1
    return count


def _parse_pyproject(path: Path, graph, file_node, rel: str) -> int:
    if tomllib is None:
        return 0
    try:
        data = tomllib.loads(path.read_text(encoding="utf-8", errors="replace"))
    except Exception:
        return 0
    project = data.get("project") if isinstance(data, dict) else None
    if not isinstance(project, dict):
        return 0
    specs: List[str] = []
    deps = project.get("dependencies")
    if isinstance(deps, list):
        specs.extend(str(d) for d in deps if isinstance(d, str))
    optional = project.get("optional-dependencies")
    if isinstance(optional, dict):
        for group in optional.values():
            if isinstance(group, list):
                specs.extend(str(d) for d in group if isinstance(d, str))
    count = 0
    for spec in specs:
        match = _PEP508.match(spec)
        if match is None:
            continue
        version = match.group(2).split(";", 1)[0].strip()
        _add_dependency(graph, file_node, match.group(1), version, "pip", rel)
        count += 1
    return count


def _parse_go_mod(path: Path, graph, file_node, rel: str) -> int:
    count = 0
    in_block = False
    for raw in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = raw.strip()
        if in_block:
            if line == ")":
                in_block = False
                continue
            match = _GO_BLOCK.match(line)
            if match:
                _add_dependency(graph, file_node, match.group(1),
                                match.group(2), "go", rel)
                count += 1
            continue
        if line.startswith("require ("):
            in_block = True
            continue
        match = _GO_REQUIRE.match(line)
        if match:
            _add_dependency(graph, file_node, match.group(1),
                            match.group(2), "go", rel)
            count += 1
    return count


def _parse_gemfile(path: Path, graph, file_node, rel: str) -> int:
    count = 0
    for raw in path.read_text(encoding="utf-8", errors="replace").splitlines():
        match = _GEM.match(raw)
        if match:
            _add_dependency(graph, file_node, match.group(1),
                            match.group(2) or "", "gem", rel)
            count += 1
    return count


def _parse_cargo_toml(path: Path, graph, file_node, rel: str) -> int:
    if tomllib is None:
        return 0
    try:
        data = tomllib.loads(path.read_text(encoding="utf-8", errors="replace"))
    except Exception:
        return 0
    if not isinstance(data, dict):
        return 0
    count = 0
    for section in ("dependencies", "dev-dependencies", "build-dependencies"):
        block = data.get(section)
        if not isinstance(block, dict):
            continue
        for name, value in block.items():
            if isinstance(value, str):
                version = value
            elif isinstance(value, dict):
                version = str(value.get("version") or "")
            else:
                version = ""
            _add_dependency(graph, file_node, str(name), version, "cargo", rel)
            count += 1
    return count


def _parse_pom(path: Path, graph, file_node, rel: str) -> int:
    text = path.read_text(encoding="utf-8", errors="replace")
    count = 0
    for block in _POM_DEP.findall(text):
        group_m = _POM_GROUP.search(block)
        art_m = _POM_ARTIFACT.search(block)
        ver_m = _POM_VERSION.search(block)
        if group_m is None or art_m is None:
            continue
        name = f"{group_m.group(1)}:{art_m.group(1)}"
        _add_dependency(graph, file_node, name,
                        ver_m.group(1) if ver_m else "", "maven", rel)
        count += 1
    return count


_DEPENDENCY_PARSERS = {
    "package.json": _parse_package_json,
    "pyproject.toml": _parse_pyproject,
    "go.mod": _parse_go_mod,
    "Gemfile": _parse_gemfile,
    "Cargo.toml": _parse_cargo_toml,
    "pom.xml": _parse_pom,
}


# -- container / IaC --------------------------------------------------------

def _image_ref(ref: str) -> Tuple[str, Optional[str]]:
    ref = ref.split("@", 1)[0]
    last_slash = ref.rfind("/")
    last_colon = ref.rfind(":")
    if last_colon > last_slash:
        return ref[:last_colon], ref[last_colon + 1:]
    return ref, None


def _add_workload(graph, file_node, label: str, props: Dict[str, object],
                  rel: str) -> None:
    node = graph.add_node("workload", label, source_file=rel, **props)
    graph.add_edge(file_node.id, node.id, "exposes")


def _parse_dockerfile(path: Path, graph, file_node, rel: str) -> int:
    count = 0
    for raw in path.read_text(encoding="utf-8", errors="replace").splitlines():
        match = _FROM.match(raw)
        if match is None:
            continue
        image = match.group(1)
        if image.lower() == "scratch" or "$" in image:
            continue
        name, tag = _image_ref(image)
        props: Dict[str, object] = {
            "image": name, "tag": tag, "iac": "dockerfile",
        }
        if match.group(2):
            props["stage"] = match.group(2).lower()
        _add_workload(graph, file_node, image, props, rel)
        count += 1
    return count


def _parse_compose(path: Path, graph, file_node, rel: str) -> int:
    if yaml is None:
        return 0
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8", errors="replace"))
    except Exception:
        return 0
    services = data.get("services") if isinstance(data, dict) else None
    if not isinstance(services, dict):
        return 0
    count = 0
    for name, svc in services.items():
        image = svc.get("image") if isinstance(svc, dict) else None
        if not isinstance(image, str) or not image:
            if isinstance(svc, dict) and svc.get("build"):
                image = str(name)
            else:
                continue
        tag_split = _image_ref(image)
        _add_workload(graph, file_node, f"compose:{name}", {
            "image": tag_split[0], "tag": tag_split[1],
            "service": str(name), "iac": "compose",
        }, rel)
        count += 1
    return count

_K8S_SECRET_KINDS = {"Secret"}
_K8S_IDENTITY_KINDS = {
    "ServiceAccount", "Role", "ClusterRole", "RoleBinding",
    "ClusterRoleBinding",
}
_K8S_CONFIG_KINDS = {"ConfigMap", "Ingress", "NetworkPolicy"}


def _k8s_images(doc: Dict) -> List[str]:
    images: List[str] = []

    def walk(value: object, depth: int = 0) -> None:
        if depth > 12 or len(images) > 20:
            return
        if isinstance(value, dict):
            for key, sub in value.items():
                if key == "image" and isinstance(sub, str):
                    images.append(sub)
                else:
                    walk(sub, depth + 1)
        elif isinstance(value, list):
            for item in value:
                walk(item, depth + 1)

    walk(doc)
    return images


def _parse_k8s_doc(doc: Dict, path: Path, graph, file_node, rel: str) -> int:
    kind = doc.get("kind")
    metadata = doc.get("metadata")
    name = metadata.get("name") if isinstance(metadata, dict) else None
    if not isinstance(kind, str) or not isinstance(name, str):
        return 0
    label = f"{kind}/{name}"
    common: Dict[str, object] = {"k8s_kind": kind, "iac": "kubernetes"}
    if kind == "Secret":
        # Name + type only — never record secret payloads.
        node = graph.add_node(
            "config", label,
            secret_type=str(doc.get("type") or ""), **common,
        )
        graph.add_edge(file_node.id, node.id, "exposes")
        return 1
    if kind == "Service":
        spec = doc.get("spec")
        ports = []
        if isinstance(spec, dict) and isinstance(spec.get("ports"), list):
            ports = [p.get("port") for p in spec["ports"]
                     if isinstance(p, dict) and p.get("port") is not None]
        node = graph.add_node("service", label, ports=ports, **common)
        graph.add_edge(file_node.id, node.id, "exposes")
        return 1
    if kind in _K8S_IDENTITY_KINDS or kind in _K8S_CONFIG_KINDS:
        node_kind = "identity" if kind in _K8S_IDENTITY_KINDS else "config"
        node = graph.add_node(node_kind, label, **common)
        graph.add_edge(file_node.id, node.id, "exposes")
        return 1
    images = _k8s_images(doc)
    _add_workload(graph, file_node, label, {
        "image": images[0] if images else None,
        "images": images, "k8s_name": name, **common,
    }, rel)
    return 1


def _parse_k8s_yaml(path: Path, graph, file_node, rel: str) -> int:
    if yaml is None:
        return 0
    text = path.read_text(encoding="utf-8", errors="replace")
    if "kind:" not in text or "apiVersion:" not in text:
        return 0
    try:
        docs = list(yaml.safe_load_all(text))
    except Exception:
        return 0
    count = 0
    for doc in docs:
        if isinstance(doc, dict):
            count += _parse_k8s_doc(doc, path, graph, file_node, rel)
    return count


_TF_BUCKET = ("aws_s3_bucket", "google_storage_bucket", "azurerm_storage")
_TF_IDENTITY = ("aws_iam", "google_service_account", "google_project_iam",
                "azuread_", "aws_organizations", "google_service_identity")


def _parse_terraform(path: Path, graph, file_node, rel: str) -> int:
    text = path.read_text(encoding="utf-8", errors="replace")
    count = 0
    for resource_type, name in _TF_RESOURCE.findall(text):
        label = f"{resource_type}.{name}"
        if resource_type.startswith(_TF_BUCKET):
            node = graph.add_node(
                "bucket", label,
                resource_type=resource_type, iac="terraform", source_file=rel,
            )
            graph.add_edge(file_node.id, node.id, "exposes")
        elif resource_type.startswith(_TF_IDENTITY):
            node = graph.add_node(
                "identity", label,
                resource_type=resource_type, iac="terraform", source_file=rel,
            )
            graph.add_edge(file_node.id, node.id, "exposes")
        else:
            _add_workload(graph, file_node, label, {
                "resource_type": resource_type, "iac": "terraform",
            }, rel)
        count += 1
    return count


# -- discovery --------------------------------------------------------------

def _candidates(root: Path) -> Iterator[Path]:
    seen: set = set()

    def note(path: Path) -> Optional[Path]:
        key = str(path)
        if key in seen or _skipped(path) or not path.is_file():
            return None
        seen.add(key)
        return path

    for pattern in ("requirements*.txt", "package.json", "pyproject.toml",
                    "go.mod", "Gemfile", "Cargo.toml", "pom.xml",
                    "Dockerfile", "Dockerfile.*", "*.dockerfile",
                    "docker-compose.yml", "docker-compose.yaml",
                    "compose.yml", "compose.yaml"):
        for path in sorted(root.glob(f"**/{pattern}")):
            hit = note(path)
            if hit is not None:
                yield hit
    tf_count = 0
    for path in sorted(root.glob("**/*.tf")):
        if tf_count >= MAX_TF_FILES:
            break
        hit = note(path)
        if hit is not None:
            tf_count += 1
            yield hit
    yaml_count = 0
    for path in sorted(list(root.glob("**/*.yaml")) + list(root.glob("**/*.yml"))):
        if yaml_count >= MAX_YAML_FILES:
            break
        hit = note(path)
        if hit is not None:
            yaml_count += 1
            yield hit


def discover_manifest_assets(root: Path) -> Dict[str, object]:
    """Parse manifests/IaC under `root` → graph + per-category counts."""
    from velora.assets.graph import AssetGraph

    graph = AssetGraph()
    root = Path(root)
    stats: Dict[str, int] = {}
    manifests = 0
    if not root.is_dir():
        return {"graph": graph, "stats": stats}
    for path in _candidates(root):
        if manifests >= MAX_MANIFESTS:
            break
        name = path.name
        rel = _rel(path, root)
        if name.startswith("requirements") and name.endswith(".txt"):
            parser = _parse_requirements
            category = "dependencies"
        elif name in _DEPENDENCY_PARSERS:
            parser = _DEPENDENCY_PARSERS[name]
            category = "dependencies"
        elif name.startswith("Dockerfile") or name.endswith(".dockerfile"):
            parser = _parse_dockerfile
            category = "containers"
        elif name in ("docker-compose.yml", "docker-compose.yaml",
                      "compose.yml", "compose.yaml"):
            parser = _parse_compose
            category = "containers"
        elif path.suffix == ".tf":
            parser = _parse_terraform
            category = "terraform"
        elif path.suffix in (".yaml", ".yml"):
            try:
                head = path.read_text(encoding="utf-8",
                                      errors="replace")[:8192]
            except OSError:
                continue
            if "kind:" not in head or "apiVersion:" not in head:
                continue  # not a k8s manifest — leave it out of the graph
            parser = _parse_k8s_yaml
            category = "kubernetes"
        else:
            continue
        try:
            file_node, rel = _add_file(graph, path, root)
            produced = parser(path, graph, file_node, rel)
        except OSError:
            continue
        if produced:
            manifests += 1
            stats[category] = stats.get(category, 0) + int(produced)
    return {"graph": graph, "stats": stats}


def absorb(graph, other) -> None:
    """Merge another AssetGraph's nodes/edges into `graph` (props merge)."""
    for node in other:
        graph.add_node(node.kind, node.label, **node.props)
    for edge in other.edges:
        graph.add_edge(edge.src, edge.dst, edge.kind, **edge.props)
