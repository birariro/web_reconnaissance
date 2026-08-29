"""Tests for the arjun wrapper (parser + graceful degradation)."""

from __future__ import annotations

from pathlib import Path

import pytest

from reconnaissance.adapters.tools import arjun
from reconnaissance.models import EndpointSource, ParamLocation

FIXTURE = Path(__file__).parent / "fixtures" / "arjun.json"


def test_parse_params_maps_query_and_brute_when_given_arjun_json() -> None:
    # Given arjun -oJ JSON with four params under one URL
    text = FIXTURE.read_text()
    # When parsed
    outcome = arjun.parse_params(text)
    # Then every param is a QUERY param sourced from BRUTE, in order
    assert [p.name for p in outcome.params] == ["q", "lang", "debug", "redirect"]
    assert {p.location for p in outcome.params} == {ParamLocation.QUERY}
    assert {p.source for p in outcome.params} == {EndpointSource.BRUTE}
    assert all(p.sample_value is None for p in outcome.params)
    assert outcome.missing_binary is False


def test_parse_params_dedupes_by_name_when_repeated() -> None:
    # Given two URLs sharing a param name
    text = '{"https://a/x": {"method": "GET", "params": ["q", "lang"]}, "https://a/y": {"method": "GET", "params": ["q", "id"]}}'
    # When parsed
    outcome = arjun.parse_params(text)
    # Then the repeated name appears once, first-seen order preserved
    assert [p.name for p in outcome.params] == ["q", "lang", "id"]


def test_parse_params_returns_empty_when_text_blank() -> None:
    # Given blank output (arjun found nothing / wrote nothing)
    # When parsed
    outcome = arjun.parse_params("   ")
    # Then the outcome is empty rather than raising
    assert outcome.params == ()
    assert outcome.missing_binary is False


def test_find_params_reports_missing_binary_when_arjun_absent(monkeypatch: pytest.MonkeyPatch) -> None:
    # Given the arjun binary is not on PATH (forced, so the test is independent
    # of whether arjun happens to be installed in this environment)
    from reconnaissance.adapters.execution import CommandResult

    def _missing(argv: object, **_kwargs: object) -> CommandResult:
        return CommandResult(argv=tuple(argv), exit_code=None, stdout="", stderr="", timed_out=False, missing_binary=True)  # type: ignore[arg-type]

    monkeypatch.setattr(arjun, "run_command", _missing)
    # When find_params runs
    outcome = arjun.find_params("https://app.example.com/search")
    # Then it degrades gracefully rather than raising
    assert outcome.missing_binary is True
    assert outcome.params == ()
