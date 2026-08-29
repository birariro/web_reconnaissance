"""Tests for the gau wrapper (parser + graceful degradation)."""

from __future__ import annotations

from pathlib import Path

from reconnaissance.adapters.tools import gau
from reconnaissance.models import EndpointSource, HttpMethod

FIXTURE = Path(__file__).parent / "fixtures" / "gau.txt"


def test_parse_urls_returns_each_nonblank_line_when_given_gau_output() -> None:
    # Given gau stdout with blank lines
    text = FIXTURE.read_text()
    # When parsed
    urls = gau.parse_urls(text)
    # Then every non-blank line is returned in order
    assert urls[0] == "https://app.example.com/"
    assert "https://evil.other.com/phishing" in urls
    assert all(u.strip() for u in urls)


def test_collect_reports_missing_binary_when_gau_absent() -> None:
    # Given a binary name that does not exist (gau is not installed here)
    # When collect runs
    outcome = gau.collect("app.example.com")
    # Then it degrades gracefully rather than raising
    assert outcome.missing_binary is True
    assert outcome.urls == ()
    assert outcome.endpoints == ()


def test_collect_stamps_gau_source_when_parsing_urls() -> None:
    # Given raw archive URLs
    urls = gau.parse_urls("https://app.example.com/a\nhttps://app.example.com/b\n")
    # When turned into endpoints (mirrors collect's mapping)
    from reconnaissance.models import DiscoveredEndpoint

    endpoints = tuple(DiscoveredEndpoint(url=u, method=HttpMethod.GET, source=EndpointSource.GAU) for u in urls)
    # Then each is a GET endpoint tagged as gau-sourced
    assert {e.source for e in endpoints} == {EndpointSource.GAU}
    assert {e.method for e in endpoints} == {HttpMethod.GET}
