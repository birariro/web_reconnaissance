"""Tests for source-map recovery."""

from __future__ import annotations

from pathlib import Path

from reconnaissance.adapters.tools import sourcemap

FIXTURE = (Path(__file__).parent / "fixtures" / "app.js.map").read_text()


def test_map_url_for_appends_map_suffix() -> None:
    assert sourcemap.map_url_for("https://x/static/app.js") == "https://x/static/app.js.map"


def test_parse_sourcemap_extracts_paths_and_urls_from_sources_content() -> None:
    # Given a sourcemap with original sources embedded
    result = sourcemap.parse_sourcemap(FIXTURE)
    # Then absolute paths and full URLs are recovered
    assert result.parsed is True
    assert "/api/v2/login" in result.endpoints
    assert "/api/v2/users?page=1" in result.endpoints
    assert "https://api.example.com/graphql" in result.endpoints
    assert "/admin/users/{id}/edit" in result.endpoints
    assert "webpack:///src/api/client.ts" in result.source_files


def test_parse_sourcemap_reports_not_parsed_for_blank() -> None:
    result = sourcemap.parse_sourcemap("   ")
    assert result.parsed is False
    assert result.endpoints == ()


def test_parse_sourcemap_reports_not_parsed_for_invalid_json() -> None:
    result = sourcemap.parse_sourcemap("<html>not json</html>")
    assert result.parsed is False


def test_find_secrets_detects_aws_and_generic_keys() -> None:
    text = "const k='AKIAIOSFODNN7EXAMPLE'; const cfg={api_key: 'abcd1234efgh5678 ijkl'.trim()}; token='secretTOKENvalue1234';"
    kinds = {kind for kind, _ in sourcemap.find_secrets(text)}
    assert "aws_access_key" in kinds


def test_find_secrets_returns_empty_for_clean_text() -> None:
    assert sourcemap.find_secrets("const x = 1; function f() { return x; }") == ()


def test_extract_references_finds_paths_and_query_from_raw_js() -> None:
    js = 'showJson("/dashboard"); fetch("/auth/login"); showJson("/search?q=" + q);'
    refs = sourcemap.extract_references(js)
    assert "/dashboard" in refs
    assert "/auth/login" in refs
    assert "/search?q=" in refs

