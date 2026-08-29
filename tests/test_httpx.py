"""Tests for the httpx wrapper (parser + graceful degradation)."""

from __future__ import annotations

from collections.abc import Sequence
from pathlib import Path

import pytest

from reconnaissance.adapters.execution import CommandResult
from reconnaissance.adapters.tools import httpx
from reconnaissance.models import EndpointSource, HttpMethod

FIXTURE = Path(__file__).parent / "fixtures" / "httpx.jsonl"


def test_parse_probe_maps_fields_and_forbidden_status_when_given_jsonl() -> None:
    # Given ProjectDiscovery httpx JSONL including a 403 row
    text = FIXTURE.read_text()
    # When parsed
    outcome = httpx.parse_probe(text, source=EndpointSource.CRAWL)
    # Then each line becomes a GET endpoint with its fields mapped through
    first = outcome.endpoints[0]
    assert first.url == "https://app.example.com/"
    assert first.status == 200
    assert first.title == "Home"
    assert first.content_type == "text/html"
    assert first.content_length == 5123
    assert first.method is HttpMethod.GET
    assert first.source is EndpointSource.CRAWL
    # And the 403 row maps its status straight through
    forbidden = outcome.endpoints[2]
    assert forbidden.url == "https://app.example.com/admin"
    assert forbidden.status == 403
    assert forbidden.title == "Forbidden"


def test_parse_probe_captures_response_headers() -> None:
    # Given a row carrying a response-header map
    outcome = httpx.parse_probe(FIXTURE.read_text(), source=EndpointSource.CRAWL)
    # Then the headers are captured as sorted (name, value) pairs on the endpoint
    home = outcome.endpoints[0]
    headers = dict(home.headers)
    assert headers["server"] == "nginx"
    assert headers["x_powered_by"] == "Express"
    # And a row without a header map has empty headers
    assert outcome.endpoints[1].headers == ()


def test_parse_probe_captures_tls_certificate() -> None:
    # Given a row carrying a TLS cert (httpx -tls-grab)
    outcome = httpx.parse_probe(FIXTURE.read_text(), source=EndpointSource.CRAWL)
    cert = outcome.endpoints[0].cert
    # Then cert identification fields are captured (SANs recorded, never seeded)
    assert cert is not None
    assert cert.subject_cn == "app.example.com"
    assert "*.example.com" in cert.sans
    assert cert.issuer == "Lets Encrypt"
    assert cert.not_after == "2027-01-01T00:00:00Z"
    assert cert.sha256 == "abc123def456"
    # And an HTTP-only row (no tls) has no cert
    assert outcome.endpoints[1].cert is None


def test_parse_probe_dedups_tech_across_rows_when_shared() -> None:
    # Given two rows that both list Nginx and React
    text = FIXTURE.read_text()
    # When parsed
    outcome = httpx.parse_probe(text, source=EndpointSource.CRAWL)
    # Then technologies are deduplicated in first-seen order
    assert [t.name for t in outcome.technologies] == ["Nginx", "React"]


def test_parse_probe_skips_bad_lines_when_json_invalid() -> None:
    # Given output with a blank line and a malformed JSON line
    text = '{"url":"https://a.example.com/","status_code":200}\n\nnot json\n'
    # When parsed
    outcome = httpx.parse_probe(text, source=EndpointSource.CRAWL)
    # Then only the valid row survives
    assert len(outcome.endpoints) == 1
    assert outcome.endpoints[0].url == "https://a.example.com/"


def test_probe_reports_missing_binary_when_httpx_absent(monkeypatch: pytest.MonkeyPatch) -> None:
    # Given the httpx binary is not on PATH (the real one here is the unrelated
    # pip HTTP client, so force the missing-binary result instead of relying on absence)
    def fake_run_command(argv: Sequence[str], **kwargs: object) -> CommandResult:
        return CommandResult(argv=tuple(argv), exit_code=None, stdout="", stderr="", timed_out=False, missing_binary=True)

    monkeypatch.setattr(httpx, "run_command", fake_run_command)
    # When probe runs with a non-empty URL list
    outcome = httpx.probe(["https://app.example.com/"], source=EndpointSource.CRAWL)
    # Then it degrades gracefully rather than raising
    assert outcome.missing_binary is True
    assert outcome.endpoints == ()
    assert outcome.technologies == ()


def test_probe_skips_binary_when_urls_empty() -> None:
    # Given no URLs to probe
    # When probe runs
    outcome = httpx.probe([], source=EndpointSource.CRAWL)
    # Then it returns an empty outcome without invoking the binary
    assert outcome.missing_binary is False
    assert outcome.endpoints == ()
    assert outcome.technologies == ()
