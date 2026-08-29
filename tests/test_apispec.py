"""Tests for API-spec detection and expansion."""

from __future__ import annotations

from pathlib import Path

from reconnaissance.adapters.tools import apispec
from reconnaissance.adapters.tools.apispec import SpecKind
from reconnaissance.models import HttpMethod, ParamLocation

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


def test_walk_spec_preserves_method_and_attributes_params_per_operation() -> None:
    # Given the same document (GET+POST on /users, GET on /users/{id})
    result = apispec.walk_spec(FIXTURE)
    by_key = {(se.endpoint.method, se.endpoint.url): se for se in result.endpoints}
    users_get = by_key[(HttpMethod.GET, "https://app.example.com/api/v1/users")]
    users_post = by_key[(HttpMethod.POST, "https://app.example.com/api/v1/users")]
    user_by_id = by_key[(HttpMethod.GET, "https://app.example.com/api/v1/users/{id}")]
    # Then each verb keeps its own params: query on GET, requestBody props on POST
    assert ("page", ParamLocation.QUERY) in {(p.name, p.location) for p in users_get.params}
    post_params = {(p.name, p.location) for p in users_post.params}
    assert ("name", ParamLocation.BODY) in post_params
    assert ("email", ParamLocation.BODY) in post_params
    id_params = {(p.name, p.location) for p in user_by_id.params}
    assert ("id", ParamLocation.PATH) in id_params
    assert ("expand", ParamLocation.QUERY) in id_params


def test_walk_spec_returns_empty_for_unrecognised_input() -> None:
    result = apispec.walk_spec("{}")
    assert result.endpoints == ()
