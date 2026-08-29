"""API-spec detection and expansion.

strix's ``api_spec.py`` only *detects* a spec and extracts base URLs; it leaves
path/operation/parameter iteration to an agent. This module does both: it
classifies OpenAPI 3.x / Swagger 2.0 / Postman and then walks the document into
concrete endpoints and parameters (the deterministic path's biggest yield).

Pure logic: callers fetch the spec text (via the proxy) and pass it here.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from enum import StrEnum
from typing import Any

import yaml

from reconnaissance.models import DiscoveredEndpoint, DiscoveredParam, EndpointSource, HttpMethod, ParamLocation

logger = logging.getLogger(__name__)

_OPERATION_KEYS = frozenset({"get", "put", "post", "delete", "patch", "options", "head", "trace"})
_LOCATION_MAP = {"query": ParamLocation.QUERY, "path": ParamLocation.PATH, "header": ParamLocation.HEADER, "body": ParamLocation.BODY, "formData": ParamLocation.BODY}


class SpecKind(StrEnum):
    """Recognised API-spec formats."""

    OPENAPI3 = "openapi3"
    SWAGGER2 = "swagger2"
    POSTMAN = "postman"


@dataclass(frozen=True, slots=True)
class SpecEndpoint:
    """One endpoint expanded from a spec, with its declared parameters."""

    endpoint: DiscoveredEndpoint
    params: tuple[DiscoveredParam, ...] = ()


@dataclass(frozen=True, slots=True)
class SpecResult:
    """Everything expanded from one spec document."""

    kind: SpecKind
    base_urls: tuple[str, ...]
    endpoints: tuple[SpecEndpoint, ...]
    operation_count: int

    @classmethod
    def empty(cls) -> SpecResult:
        """A result carrying nothing (unrecognised or unparseable input)."""
        return cls(kind=SpecKind.OPENAPI3, base_urls=(), endpoints=(), operation_count=0)


def _load(text: str) -> dict[str, Any] | None:
    stripped = text.strip()
    if not stripped:
        return None
    try:
        parsed: object = json.loads(stripped)
    except json.JSONDecodeError:
        try:
            parsed = yaml.safe_load(stripped)
        except yaml.YAMLError:
            return None
    return parsed if isinstance(parsed, dict) else None


def detect_spec(text: str) -> SpecKind | None:
    """Classify ``text`` as a known API spec, or return None."""
    doc = _load(text)
    if doc is None:
        return None
    return _classify(doc)


def _classify(doc: dict[str, Any]) -> SpecKind | None:
    if isinstance(doc.get("openapi"), str) and doc["openapi"].startswith("3."):
        return SpecKind.OPENAPI3
    if doc.get("swagger") == "2.0":
        return SpecKind.SWAGGER2
    info = doc.get("info")
    if isinstance(doc.get("item"), list) and isinstance(info, dict):
        return SpecKind.POSTMAN
    return None


def _resolve_ref(doc: dict[str, Any], node: dict[str, Any]) -> dict[str, Any]:
    ref = node.get("$ref")
    if not isinstance(ref, str) or not ref.startswith("#/"):
        return node
    target: Any = doc
    for part in ref[2:].split("/"):
        if not isinstance(target, dict) or part not in target:
            return node
        target = target[part]
    return target if isinstance(target, dict) else node


def _openapi3_base_urls(doc: dict[str, Any]) -> tuple[str, ...]:
    servers = doc.get("servers")
    if not isinstance(servers, list):
        return ()
    urls = [s["url"] for s in servers if isinstance(s, dict) and isinstance(s.get("url"), str)]
    return tuple(urls)


def _swagger2_base_urls(doc: dict[str, Any]) -> tuple[str, ...]:
    host = doc.get("host")
    if not isinstance(host, str):
        return ()
    raw_base = doc.get("basePath")
    base_path = raw_base if isinstance(raw_base, str) else ""
    raw_schemes = doc.get("schemes")
    schemes: list[Any] = raw_schemes if isinstance(raw_schemes, list) else ["https"]
    return tuple(f"{scheme}://{host}{base_path}" for scheme in schemes if isinstance(scheme, str))


def _join(base: str, path: str) -> str:
    if not base:
        return path
    return f"{base.rstrip('/')}/{path.lstrip('/')}"


def _params_from_operation(doc: dict[str, Any], operation: dict[str, Any]) -> tuple[DiscoveredParam, ...]:
    params: list[DiscoveredParam] = []
    seen: set[tuple[str, ParamLocation]] = set()
    raw_params = operation.get("parameters")
    for raw in raw_params if isinstance(raw_params, list) else []:
        if not isinstance(raw, dict):
            continue
        node = _resolve_ref(doc, raw)
        name = node.get("name")
        location = _LOCATION_MAP.get(str(node.get("in", "")))
        if not isinstance(name, str) or location is None:
            continue
        key = (name, location)
        if key in seen:
            continue
        seen.add(key)
        params.append(DiscoveredParam(name=name, location=location, source=EndpointSource.SPEC))
    params.extend(_body_params(doc, operation, seen))
    return tuple(params)


def _body_params(doc: dict[str, Any], operation: dict[str, Any], seen: set[tuple[str, ParamLocation]]) -> list[DiscoveredParam]:
    request_body = operation.get("requestBody")
    if not isinstance(request_body, dict):
        return []
    node = _resolve_ref(doc, request_body)
    content = node.get("content")
    out: list[DiscoveredParam] = []
    if not isinstance(content, dict):
        return out
    for media in content.values():
        if not isinstance(media, dict):
            continue
        schema = _resolve_ref(doc, media.get("schema", {})) if isinstance(media.get("schema"), dict) else {}
        properties = schema.get("properties")
        if not isinstance(properties, dict):
            continue
        for prop_name in properties:
            key = (prop_name, ParamLocation.BODY)
            if isinstance(prop_name, str) and key not in seen:
                seen.add(key)
                out.append(DiscoveredParam(name=prop_name, location=ParamLocation.BODY, source=EndpointSource.SPEC))
    return out


def _walk_paths(doc: dict[str, Any], base_urls: tuple[str, ...]) -> tuple[tuple[SpecEndpoint, ...], int]:
    paths = doc.get("paths")
    if not isinstance(paths, dict):
        return (), 0
    base = base_urls[0] if base_urls else ""
    endpoints: list[SpecEndpoint] = []
    operations = 0
    for path, item in paths.items():
        if not isinstance(path, str) or not isinstance(item, dict):
            continue
        params: list[DiscoveredParam] = []
        for method_key, operation in item.items():
            if method_key.lower() not in _OPERATION_KEYS or not isinstance(operation, dict):
                continue
            operations += 1
            params.extend(_params_from_operation(doc, operation))
        url = _join(base, path)
        endpoint = DiscoveredEndpoint(url=url, method=HttpMethod.GET, source=EndpointSource.SPEC)
        endpoints.append(SpecEndpoint(endpoint=endpoint, params=tuple(_dedup_params(params))))
    return tuple(endpoints), operations


def _dedup_params(params: list[DiscoveredParam]) -> list[DiscoveredParam]:
    seen: set[tuple[str, ParamLocation]] = set()
    out: list[DiscoveredParam] = []
    for p in params:
        key = (p.name, p.location)
        if key not in seen:
            seen.add(key)
            out.append(p)
    return out


def walk_spec(text: str) -> SpecResult:
    """Expand a spec document into endpoints and parameters.

    Returns:
        A :class:`SpecResult`. For Postman or unrecognised/unparseable input the
        endpoint list is empty (base URLs may still be present).
    """
    doc = _load(text)
    if doc is None:
        return SpecResult.empty()
    kind = _classify(doc)
    if kind is None:
        return SpecResult.empty()
    if kind is SpecKind.OPENAPI3:
        base_urls = _openapi3_base_urls(doc)
    elif kind is SpecKind.SWAGGER2:
        base_urls = _swagger2_base_urls(doc)
    else:
        return SpecResult(kind=kind, base_urls=(), endpoints=(), operation_count=0)
    endpoints, operations = _walk_paths(doc, base_urls)
    return SpecResult(kind=kind, base_urls=base_urls, endpoints=endpoints, operation_count=operations)
