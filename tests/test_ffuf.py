"""Tests for the ffuf wrapper (parser + graceful degradation)."""

from __future__ import annotations

from pathlib import Path

from reconnaissance.adapters.tools import ffuf
from reconnaissance.models import EndpointSource, HttpMethod

FIXTURE = Path(__file__).parent / "fixtures" / "ffuf.json"


def test_parse_fuzz_maps_each_result_when_given_ffuf_json() -> None:
    # Given ffuf JSON output with several hits
    text = FIXTURE.read_text()
    # When parsed
    outcome = ffuf.parse_fuzz(text)
    # Then every result row becomes a BRUTE-sourced GET endpoint with status mapped
    assert outcome.missing_binary is False
    assert len(outcome.endpoints) == 3
    assert {e.source for e in outcome.endpoints} == {EndpointSource.BRUTE}
    assert {e.method for e in outcome.endpoints} == {HttpMethod.GET}
    admin = outcome.endpoints[0]
    assert admin.url == "https://app.example.com/admin"
    assert admin.status == 403
    assert admin.content_type == "text/html"
    assert admin.content_length == 146


def test_parse_fuzz_keeps_exposed_git_config_when_present() -> None:
    # Given a fixture containing a .git/config exposed-file hit
    text = FIXTURE.read_text()
    # When parsed
    urls = {e.url: e for e in ffuf.parse_fuzz(text).endpoints}
    # Then the exposed file is included as a 200
    git_config = urls["https://app.example.com/.git/config"]
    assert git_config.status == 200


def test_parse_fuzz_keeps_soft_404_row_when_present() -> None:
    # Given a fixture with a soft-404-looking row (large length, status 200)
    text = FIXTURE.read_text()
    # When parsed (this wrapper does NOT filter soft-404s)
    urls = {e.url: e for e in ffuf.parse_fuzz(text).endpoints}
    # Then the soft-404 row is still present for the pipeline to filter later
    soft = urls["https://app.example.com/random404xyz"]
    assert soft.status == 200
    assert soft.content_length == 5123


def test_parse_fuzz_returns_empty_when_blank() -> None:
    # Given blank output (ffuf wrote nothing usable)
    # When parsed
    outcome = ffuf.parse_fuzz("   ")
    # Then an empty outcome is returned rather than raising
    assert outcome.endpoints == ()
    assert outcome.missing_binary is False


def test_fuzz_reports_missing_binary_when_ffuf_absent() -> None:
    # Given a binary name that does not exist (ffuf is not installed here)
    # When fuzz runs
    outcome = ffuf.fuzz("https://app.example.com", "wordlist.txt")
    # Then it degrades gracefully rather than raising
    assert outcome.missing_binary is True
    assert outcome.endpoints == ()
