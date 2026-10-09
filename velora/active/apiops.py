"""API-operations adapter: rich OpenAPI/Swagger operation records (§10).

Pure parse of a spec *text* already fetched by recon — one record per
(method, path): operationId, summary, parameters with in/required/type,
requestBody content types, security requirements, tags. Feeds ENUMERATE
coverage (declared vs verified methods) and HYPOTHESIZE candidates.
Never raises: malformed input yields an empty list.
"""
from __future__ import annotations

import json
from typing import Dict, List, Optional

METHODS = frozenset({
    "get", "post", "put", "delete", "patch", "head", "options", "trace",
})
MAX_OPERATIONS = 500


def _param(param: object) -> Optional[Dict[str, object]]:
    if not isinstance(param, dict) or not param.get("name"):
        return None
    where = str(param.get("in") or "query")
    record: Dict[str, object] = {
        "name": str(param["name"]),
        "in": where,
        "required": bool(param.get("required", where == "path")),
    }
    schema = param.get("schema")
    if isinstance(schema, dict) and schema.get("type"):
        record["type"] = str(schema["type"])
    elif param.get("type"):
        # Swagger 2.0 keeps the type on the parameter itself.
        record["type"] = str(param["type"])
    if isinstance(schema, dict) and isinstance(schema.get("enum"), list):
        record["enum"] = [str(v) for v in schema["enum"]][:20]
    elif isinstance(param.get("enum"), list):
        record["enum"] = [str(v) for v in param["enum"]][:20]
    return record


def _params(items: object) -> List[Dict[str, object]]:
    out: List[Dict[str, object]] = []
    seen = set()
    for raw in items if isinstance(items, list) else []:
        record = _param(raw)
        if record is None:
            continue
        key = (str(record["name"]), str(record["in"]))
        if key in seen:
            continue
        seen.add(key)
        out.append(record)
    return out


def _operation(path: str, method: str, op: Dict[str, object],
               path_level: List[object],
               global_security: object) -> Dict[str, object]:
    request = op.get("requestBody")
    request = request if isinstance(request, dict) else {}
    content = request.get("content")
    content = content if isinstance(content, dict) else {}
    security = op.get("security")
    if not isinstance(security, list):
        security = global_security if isinstance(global_security, list) else None
    tags = [str(t) for t in op.get("tags") or [] if isinstance(t, str)]
    return {
        "method": method.upper(),
        "path": path,
        "operation_id": str(op["operationId"]) if op.get("operationId") else None,
        "summary": str(op["summary"]) if op.get("summary") else None,
        "params": _params(list(op.get("parameters") or []) + path_level),
        "request_content_types": sorted(str(c) for c in content),
        "request_body_required": bool(request.get("required")),
        "security": security,
        "tags": tags,
        "deprecated": bool(op.get("deprecated")),
    }


def parse_api_operations(text: str) -> List[Dict[str, object]]:
    """Spec text → sorted operation records; [] for anything malformed."""
    try:
        spec = json.loads(text)
    except (ValueError, TypeError):
        return []
    if not isinstance(spec, dict) or not isinstance(spec.get("paths"), dict):
        return []
    global_security = spec.get("security")
    operations: List[Dict[str, object]] = []
    for path, item in spec["paths"].items():
        if not isinstance(path, str) or not path.startswith("/"):
            continue
        if not isinstance(item, dict):
            continue
        path_level = _params(item.get("parameters"))
        for key, op in item.items():
            if str(key).lower() not in METHODS or not isinstance(op, dict):
                continue
            operations.append(
                _operation(path, str(key), op, path_level, global_security)
            )
            if len(operations) >= MAX_OPERATIONS:
                operations.sort(key=lambda o: (str(o["path"]),
                                               str(o["method"])))
                return operations
    operations.sort(key=lambda o: (str(o["path"]), str(o["method"])))
    return operations
