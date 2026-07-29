"""Discover an app's API surface from a served OpenAPI/Swagger spec.

A JSON API serves no HTML to crawl, so the HTML crawler sees only '/'. But most REST frameworks
(FastAPI, connexion, Spring, NestJS, Express+swagger, ...) publish a machine-readable spec at a
well-known path. Parsing it yields the exact endpoint list — paths, methods, query params, and JSON
body fields — which feeds both the declarative fan-out (headers/crash/exposure across the real
endpoints, not just '/') and the injection probes (concrete params/body fields to inject into).

Handles both OpenAPI 3 (`servers`, `requestBody`) and Swagger 2 (`basePath`, `in: body/formData`).
JSON only — the well-known endpoints below serve JSON even when the human-facing spec is YAML.
"""
from __future__ import annotations

from urllib.parse import urlparse

import httpx

from .schema import Endpoint

# Well-known spec locations across frameworks. Ordered most-specific first.
SPEC_PATHS = (
    "/openapi.json", "/swagger.json", "/v3/api-docs", "/api-docs/swagger.json",
    "/api/openapi.json", "/api/swagger.json", "/v2/api-docs", "/swagger/v1/swagger.json",
    "/api-docs", "/openapi",
)

_METHODS = ("get", "post", "put", "patch", "delete")
_PATH_PARAM_FILL = "1"  # concretize {id}/{username} for fan-out fetches; injection uses raw_path


def fetch_spec(base_url: str, client: httpx.Client) -> dict | None:
    """Return the first served OpenAPI/Swagger doc (a dict with a `paths` object), else None."""
    for path in SPEC_PATHS:
        try:
            resp = client.get(path)
        except (httpx.HTTPError, httpx.InvalidURL):
            continue
        if resp.status_code != 200:
            continue
        ctype = resp.headers.get("content-type", "").lower()
        if "json" not in ctype and not resp.text.lstrip().startswith("{"):
            continue  # an HTML swagger-UI page, not the raw spec
        try:
            spec = resp.json()
        except (ValueError, httpx.HTTPError):
            continue
        if isinstance(spec, dict) and isinstance(spec.get("paths"), dict):
            return spec
    return None


def _base_path(spec: dict) -> str:
    """The path prefix all operations sit under: Swagger 2 `basePath`, or the path component of an
    OpenAPI 3 `servers[0].url`. '' when the spec's paths are already absolute (e.g. VAmPI)."""
    bp = spec.get("basePath")
    if isinstance(bp, str) and bp.startswith("/"):
        return bp.rstrip("/")
    servers = spec.get("servers")
    if isinstance(servers, list) and servers and isinstance(servers[0], dict):
        url = servers[0].get("url", "")
        if isinstance(url, str) and url:
            p = urlparse(url).path if "://" in url else url
            if p.startswith("/") and p != "/":
                return p.rstrip("/")
    return ""


def _deref(spec: dict, schema, depth: int = 0):
    """Follow a `$ref` (#/components/schemas/X or Swagger 2 #/definitions/X) to the schema it names.
    Modern specs (FastAPI, Spring, NestJS) reference body schemas by $ref, not inline properties."""
    if not isinstance(schema, dict) or depth > 6:
        return schema if isinstance(schema, dict) else {}
    ref = schema.get("$ref")
    if isinstance(ref, str) and ref.startswith("#/"):
        node = spec
        for part in ref[2:].split("/"):
            node = node.get(part) if isinstance(node, dict) else None
            if node is None:
                return {}
        return _deref(spec, node, depth + 1)
    return schema


def _schema_props(spec: dict, schema, depth: int = 0) -> list[str]:
    """Property names of a (possibly $ref'd, allOf-composed) object schema."""
    schema = _deref(spec, schema, depth)
    if not isinstance(schema, dict) or depth > 6:
        return []
    props: list[str] = []
    p = schema.get("properties")
    if isinstance(p, dict):
        props.extend(p.keys())
    for sub in schema.get("allOf") or []:  # composed schema: merge each part's properties
        props.extend(_schema_props(spec, sub, depth + 1))
    return list(dict.fromkeys(props))


def _body_fields(spec: dict, op: dict, params: list) -> list[str]:
    """Request-body property names: OpenAPI 3 `requestBody.content[json].schema` (resolving $ref),
    plus Swagger 2 `in: body` schema and `in: formData` param names."""
    fields: list[str] = []
    rb = op.get("requestBody")
    if isinstance(rb, dict):
        content = rb.get("content")
        if isinstance(content, dict):
            for ctype in ("application/json", "application/x-www-form-urlencoded"):
                media = content.get(ctype)
                if isinstance(media, dict):
                    fields.extend(_schema_props(spec, media.get("schema")))
    for p in params:
        if not isinstance(p, dict):
            continue
        if p.get("in") == "formData" and p.get("name"):
            fields.append(p["name"])
        elif p.get("in") == "body":
            fields.extend(_schema_props(spec, p.get("schema")))
    return list(dict.fromkeys(fields))  # dedup, order-preserving


def _params_in(params: list, where: str) -> list[str]:
    return list(dict.fromkeys(
        p["name"] for p in params
        if isinstance(p, dict) and p.get("in") == where and p.get("name")
    ))


def parse_endpoints(spec: dict) -> list[Endpoint]:
    """Flatten an OpenAPI/Swagger spec into one Endpoint per (path x method)."""
    paths = spec.get("paths")
    if not isinstance(paths, dict):
        return []
    base = _base_path(spec)
    endpoints: list[Endpoint] = []
    for raw_path, item in paths.items():
        if not isinstance(raw_path, str) or not isinstance(item, dict):
            continue
        shared = item.get("parameters")
        shared = shared if isinstance(shared, list) else []
        for method in _METHODS:
            op = item.get(method)
            if not isinstance(op, dict):
                continue
            op_params = op.get("parameters")
            params = shared + (op_params if isinstance(op_params, list) else [])
            path_params = _params_in(params, "path")
            templated = base + raw_path
            concrete = templated
            for pp in path_params:
                concrete = concrete.replace("{" + pp + "}", _PATH_PARAM_FILL)
            endpoints.append(Endpoint(
                path=concrete,
                method=method,
                query_params=_params_in(params, "query"),
                body_fields=_body_fields(spec, op, params),
                path_params=path_params,
                raw_path=templated,
            ))
    return endpoints


def ingest(base_url: str, client: httpx.Client) -> list[Endpoint]:
    """Full pass: fetch a served spec (if any) and return its endpoints ([] when none is served)."""
    spec = fetch_spec(base_url, client)
    return parse_endpoints(spec) if spec is not None else []
