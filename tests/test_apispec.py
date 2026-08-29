"""Tests for API-spec detection and expansion."""

from __future__ import annotations

from pathlib import Path

from reconnaissance.adapters.tools import apispec
from reconnaissance.adapters.tools.apispec import SpecKind
from reconnaissance.models import ParamLocation

FIXTURE = (Path(__file__).parent / "fixtures" / "openapi.json").read_text()


def test_detect_spec_identifies_openapi3() -> None:
    assert apispec.detect_spec(FIXTURE) is SpecKind.OPENAPI3


def test_detect_spec_returns_none_for_garbage() -> None:
    assert apispec.detect_spec("not a spec at all") is None


def test_walk_spec_expands_paths_with_base_url() -> None:
    # Given an OpenAPI 3 document with two paths
    result = apispec.walk_spec(FIXTURE)
    # Then endpoints are absolute (server base joined) and both paths present
    urls = {se.endpoint.url for se in result.endpoints}
    assert "https://app.example.com/api/v1/users" in urls
    assert "https://app.example.com/api/v1/users/{id}" in urls
    assert result.operation_count == 3


def test_walk_spec_extracts_query_path_and_body_params() -> None:
    # Given the same document
    result = apispec.walk_spec(FIXTURE)
    by_url = {se.endpoint.url: se for se in result.endpoints}
    users = by_url["https://app.example.com/api/v1/users"]
    user_by_id = by_url["https://app.example.com/api/v1/users/{id}"]
    # Then query params, a path param, and requestBody props are all captured
    users_params = {(p.name, p.location) for p in users.params}
    assert ("page", ParamLocation.QUERY) in users_params
    assert ("name", ParamLocation.BODY) in users_params
    assert ("email", ParamLocation.BODY) in users_params
    id_params = {(p.name, p.location) for p in user_by_id.params}
    assert ("id", ParamLocation.PATH) in id_params
    assert ("expand", ParamLocation.QUERY) in id_params


def test_walk_spec_returns_empty_for_unrecognised_input() -> None:
    result = apispec.walk_spec("{}")
    assert result.endpoints == ()
