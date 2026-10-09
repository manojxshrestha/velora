"""API-operations adapter parse tests (finalplan §10 Phase 4)."""

from velora.active.apiops import MAX_OPERATIONS, parse_api_operations


def _one(method="get", op=None, extra=None):
    spec = {
        "openapi": "3.0.0",
        "paths": {"/api/data": {method: op or {"summary": "data"},
                                **(extra or {})}},
    }
    import json
    return json.dumps(spec)


def test_minimal_spec_single_operation():
    (op,) = parse_api_operations(_one())
    assert op["method"] == "GET"
    assert op["path"] == "/api/data"
    assert op["summary"] == "data"
    assert op["operation_id"] is None
    assert op["params"] == []
    assert op["request_content_types"] == []
    assert op["request_body_required"] is False
    assert op["security"] is None
    assert op["tags"] == []
    assert op["deprecated"] is False


def test_parameters_required_type_and_enum():
    spec = {
        "openapi": "3.0.0",
        "paths": {
            "/items/{id}": {
                "get": {
                    "parameters": [
                        {"name": "id", "in": "path", "schema": {"type": "string"}},
                        {"name": "q", "in": "query", "required": True,
                         "schema": {"type": "integer", "enum": [1, 2]}},
                        {"name": "junk"},            # no `in` → query default
                        {"in": "query", "required": True},  # no name → dropped
                    ],
                },
            },
        },
    }
    import json
    (op,) = parse_api_operations(json.dumps(spec))
    by_name = {p["name"]: p for p in op["params"]}
    assert by_name["id"] == {"name": "id", "in": "path", "required": True,
                             "type": "string"}
    assert by_name["q"]["required"] is True
    assert by_name["q"]["type"] == "integer"
    assert by_name["q"]["enum"] == ["1", "2"]
    assert by_name["junk"]["in"] == "query"
    assert len(op["params"]) == 3


def test_path_level_parameters_merge_with_override():
    spec = {
        "openapi": "3.0.0",
        "paths": {
            "/things": {
                "parameters": [
                    {"name": "tenant", "in": "header", "required": True},
                ],
                "get": {"summary": "list"},
                "post": {"parameters": [{"name": "tenant", "in": "header"}],
                         "summary": "create"},
            },
        },
    }
    import json
    ops = parse_api_operations(json.dumps(spec))
    assert [o["method"] for o in ops] == ["GET", "POST"]
    get_op = next(o for o in ops if o["method"] == "GET")
    assert get_op["params"][0] == {"name": "tenant", "in": "header",
                                   "required": True}
    post_op = next(o for o in ops if o["method"] == "POST")
    # op-level record wins (required False), no duplicate
    assert post_op["params"] == [{"name": "tenant", "in": "header",
                                  "required": False}]


def test_request_body_openapi3():
    spec = {
        "openapi": "3.0.0",
        "paths": {
            "/login": {
                "post": {
                    "requestBody": {
                        "required": True,
                        "content": {
                            "application/json": {},
                            "application/x-www-form-urlencoded": {},
                        },
                    },
                },
            },
        },
    }
    import json
    (op,) = parse_api_operations(json.dumps(spec))
    assert op["request_body_required"] is True
    assert op["request_content_types"] == [
        "application/json", "application/x-www-form-urlencoded",
    ]


def test_swagger2_body_param_and_top_level_type():
    spec = {
        "swagger": "2.0",
        "paths": {
            "/pets": {
                "post": {
                    "parameters": [
                        {"name": "body", "in": "body",
                         "schema": {"type": "object"}},
                        {"name": "limit", "in": "query", "type": "integer"},
                    ],
                },
            },
        },
    }
    import json
    (op,) = parse_api_operations(json.dumps(spec))
    by_name = {p["name"]: p for p in op["params"]}
    assert by_name["body"]["in"] == "body"
    assert by_name["body"]["type"] == "object"
    assert by_name["limit"]["type"] == "integer"


def test_security_op_overrides_global():
    import json
    spec = {
        "openapi": "3.0.0",
        "security": [{"apiKey": []}],
        "paths": {
            "/a": {"get": {}, "post": {"security": [{"oauth2": ["read"]}]}},
        },
    }
    ops = parse_api_operations(json.dumps(spec))
    by_method = {o["method"]: o for o in ops}
    assert by_method["GET"]["security"] == [{"apiKey": []}]
    assert by_method["POST"]["security"] == [{"oauth2": ["read"]}]


def test_metadata_fields():
    spec = {
        "openapi": "3.0.0",
        "paths": {
            "/legacy": {"delete": {"operationId": "purgeThing",
                                   "summary": "purge",
                                   "tags": ["admin", 5],
                                   "deprecated": True}},
        },
    }
    import json
    (op,) = parse_api_operations(json.dumps(spec))
    assert op["operation_id"] == "purgeThing"
    assert op["summary"] == "purge"
    assert op["tags"] == ["admin"]  # non-string tag dropped, not coerced
    assert op["deprecated"] is True


def test_malformed_inputs_return_empty():
    assert parse_api_operations("") == []
    assert parse_api_operations("not json {") == []
    assert parse_api_operations('["list"]') == []
    assert parse_api_operations('{"paths": []}') == []
    assert parse_api_operations('{"paths": {"nope": {}}}') == []
    assert parse_api_operations(
        '{"paths": {"/x": {"parameters": [], "summary": "not an op"}}}'
    ) == []
    assert parse_api_operations(
        '{"paths": {"/x": {"get": "not-a-dict"}}}'
    ) == []


def test_operations_sorted_and_capped():
    import json
    paths = {f"/p{i:04d}": {"get": {}, "post": {}} for i in range(400)}
    ops = parse_api_operations(json.dumps({"paths": paths}))
    assert len(ops) == MAX_OPERATIONS
    keys = [(o["path"], o["method"]) for o in ops]
    assert keys == sorted(keys)
