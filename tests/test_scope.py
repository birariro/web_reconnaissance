"""Tests for URL validation, scope enforcement, and path patterns."""

from __future__ import annotations

import pytest

from reconnaissance.models import Scope
from reconnaissance.scope import InvalidUrlError, OutOfScopeError, assert_in_scope, is_in_scope, is_internal_host, normalize_url, path_pattern, validate_target

SCOPE = Scope(target_host="app.example.com", passive_sources=frozenset({"web.archive.org"}))


def test_normalize_url_lowercases_host_and_drops_default_port_and_fragment() -> None:
    assert normalize_url("HTTPS://App.Example.com:443/Path?a=1#frag") == "https://app.example.com/Path?a=1"


def test_validate_target_returns_host_when_valid() -> None:
    normalized, host = validate_target("https://app.example.com/")
    assert host == "app.example.com"
    assert normalized == "https://app.example.com/"


@pytest.mark.parametrize("bad", ["ftp://app.example.com/", "javascript:alert(1)", "https://user:pass@app.example.com/", "https:///nohost"])
def test_validate_target_rejects_forbidden_url_when_scheme_or_userinfo_bad(bad: str) -> None:
    with pytest.raises(InvalidUrlError):
        validate_target(bad)


def test_assert_in_scope_allows_target_host_when_active() -> None:
    assert assert_in_scope("https://app.example.com/x", SCOPE, active=True) == "https://app.example.com/x"


def test_assert_in_scope_blocks_offscope_host_when_active() -> None:
    with pytest.raises(OutOfScopeError, match="out of scope"):
        assert_in_scope("https://evil.com/", SCOPE, active=True)


def test_assert_in_scope_blocks_userinfo_confusion_host() -> None:
    # Host is evil.com; app.example.com is only userinfo — must be rejected.
    with pytest.raises(InvalidUrlError):
        assert_in_scope("https://app.example.com@evil.com/", SCOPE, active=True)


def test_assert_in_scope_allows_passive_source_only_when_not_active() -> None:
    assert assert_in_scope("https://web.archive.org/x", SCOPE, active=False).startswith("https://web.archive.org")
    with pytest.raises(OutOfScopeError):
        assert_in_scope("https://web.archive.org/x", SCOPE, active=True)


@pytest.mark.parametrize(
    ("url", "expected"),
    [
        ("https://app.example.com/user/12345/posts/6789", "/user/{id}/posts/{id}"),
        ("https://app.example.com/u/550e8400-e29b-41d4-a716-446655440000", "/u/{id}"),
        ("https://app.example.com/static/app.js", "/static/app.js"),
    ],
)
def test_path_pattern_collapses_variable_segments(url: str, expected: str) -> None:
    assert path_pattern(url) == expected


@pytest.mark.parametrize(("host", "internal"), [("localhost", True), ("127.0.0.1", True), ("10.0.0.5", True), ("169.254.169.254", True), ("app.example.com", False), ("93.184.216.34", False)])
def test_is_internal_host_flags_private_and_loopback(host: str, internal: bool) -> None:
    assert is_internal_host(host) is internal


def test_normalize_url_raises_on_out_of_range_port() -> None:
    # A malformed port must be a clean domain error, not a bare ValueError that aborts the scan.
    with pytest.raises(InvalidUrlError, match="invalid port"):
        normalize_url("https://app.example.com:99999/x")


def test_is_in_scope_rejects_bad_port_url_without_crashing() -> None:
    assert is_internal_host("x") is False  # sanity
    assert not is_in_scope("https://app.example.com:99999/x", SCOPE, active=True)


@pytest.mark.parametrize(("raw", "expected"), [("http://[::1]/a", "http://[::1]/a"), ("http://[::1]:8080/a", "http://[::1]:8080/a")])
def test_normalize_url_preserves_ipv6_brackets(raw: str, expected: str) -> None:
    assert normalize_url(raw) == expected


def test_validate_target_rejects_internal_host_by_default() -> None:
    with pytest.raises(InvalidUrlError, match="internal"):
        validate_target("http://127.0.0.1:8080/")


def test_validate_target_allows_internal_when_opted_in() -> None:
    normalized, host = validate_target("http://127.0.0.1:8080/", allow_internal=True)
    assert host == "127.0.0.1"
    assert normalized == "http://127.0.0.1:8080/"


def test_assert_in_scope_enforces_path_prefix() -> None:
    scope = Scope(target_host="app.example.com", path_prefix="/app")
    assert assert_in_scope("https://app.example.com/app/x", scope, active=True).endswith("/app/x")
    with pytest.raises(OutOfScopeError, match="path outside prefix"):
        assert_in_scope("https://app.example.com/other", scope, active=True)
