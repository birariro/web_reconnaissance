"""Tests for the katana wrapper (parser + graceful degradation)."""

from __future__ import annotations

from pathlib import Path

from reconnaissance.adapters.tools import katana
from reconnaissance.models import EndpointSource, HttpMethod

FIXTURE = Path(__file__).parent / "fixtures" / "katana.jsonl"


def test_parse_crawl_maps_endpoint_fields_when_given_katana_jsonl() -> None:
    # Given katana JSONL with nested request/response objects
    text = FIXTURE.read_text()
    # When parsed
    outcome = katana.parse_crawl(text)
    # Then each endpoint maps request.endpoint and response fields, tagged CRAWL/GET
    first = outcome.endpoints[0]
    assert first.url == "https://app.example.com/"
    assert first.method is HttpMethod.GET
    assert first.source is EndpointSource.CRAWL
    assert first.status == 200
    assert first.content_type == "text/html"
    assert first.title == "Home"
    assert outcome.missing_binary is False


def test_parse_crawl_collects_js_urls_when_path_or_content_type_is_javascript() -> None:
    # Given crawl output containing a .js asset and an off-host .js asset
    text = FIXTURE.read_text()
    # When parsed
    outcome = katana.parse_crawl(text)
    # Then the .js URLs are captured (scoping happens later, so off-host is kept)
    assert "https://app.example.com/static/app.js" in outcome.js_urls
    assert "https://cdn.other.com/lib.js" in outcome.js_urls
    # And a non-JS endpoint is not treated as JS
    assert "https://app.example.com/login" not in outcome.js_urls


def test_parse_crawl_preserves_post_method() -> None:
    # Given a POST request line (recorded for inventory; only sent under --destructive)
    line = '{"request":{"method":"POST","endpoint":"https://app.example.com/submit"},"response":{"status_code":200}}'
    # When parsed
    outcome = katana.parse_crawl(line)
    # Then the endpoint keeps its POST method
    assert outcome.endpoints[0].url == "https://app.example.com/submit"
    assert outcome.endpoints[0].method is HttpMethod.POST


def test_parse_crawl_skips_invalid_lines_when_json_is_malformed() -> None:
    # Given a valid line and a garbage line
    text = '{"request":{"method":"GET","endpoint":"https://app.example.com/a"},"response":{}}\nnot json\n'
    # When parsed
    outcome = katana.parse_crawl(text)
    # Then only the valid line yields an endpoint (missing status -> None)
    assert len(outcome.endpoints) == 1
    assert outcome.endpoints[0].status is None


def test_crawl_reports_missing_binary_when_katana_absent() -> None:
    # Given katana is not installed here and non-empty seeds
    # When crawl runs
    outcome = katana.crawl(["https://app.example.com/"])
    # Then it degrades gracefully rather than raising
    assert outcome.missing_binary is True
    assert outcome.endpoints == ()
    assert outcome.js_urls == ()


def test_crawl_returns_empty_when_seeds_empty() -> None:
    # Given no seeds
    # When crawl runs
    outcome = katana.crawl([])
    # Then nothing runs and the outcome is empty (binary not consulted)
    assert outcome.missing_binary is False
    assert outcome.endpoints == ()
