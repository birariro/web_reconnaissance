"""Tests for the egress proxy policy (pure) and the running proxy (integration)."""

from __future__ import annotations

import urllib.error
import urllib.request

import pytest

from reconnaissance.adapters.egress import EgressProxy, ProxyPolicy, RateLimiter
from reconnaissance.models import Scope

SCOPE = Scope(target_host="app.example.com", passive_sources=frozenset({"web.archive.org"}))


class _FakeClock:
    def __init__(self) -> None:
        self.t = 0.0

    def __call__(self) -> float:
        return self.t


def test_rate_limiter_blocks_when_bucket_empty_and_refills_over_time() -> None:
    clock = _FakeClock()
    limiter = RateLimiter(2.0, clock=clock)
    # Given a 2/sec bucket, two immediate tokens succeed, the third fails
    assert limiter.try_acquire() is True
    assert limiter.try_acquire() is True
    assert limiter.try_acquire() is False
    # When time advances one second, a token refills
    clock.t = 1.0
    assert limiter.try_acquire() is True


def test_proxy_policy_denies_out_of_scope_host() -> None:
    policy = ProxyPolicy(SCOPE, rate_per_second=100.0, max_requests=100)
    assert policy.check("app.example.com").allowed is True
    decision = policy.check("evil.com")
    assert decision.allowed is False
    assert "out of scope" in decision.reason


def test_proxy_policy_allows_passive_source_host() -> None:
    policy = ProxyPolicy(SCOPE, rate_per_second=100.0, max_requests=100)
    assert policy.check("web.archive.org").allowed is True


def test_proxy_policy_trips_killswitch_at_max_requests() -> None:
    policy = ProxyPolicy(SCOPE, rate_per_second=100.0, max_requests=2)
    assert policy.check("app.example.com").allowed is True
    assert policy.check("app.example.com").allowed is True
    tripped = policy.check("app.example.com")
    assert tripped.allowed is False
    assert "kill-switch" in tripped.reason


@pytest.mark.integration
def test_proxy_refuses_connect_to_out_of_scope_host() -> None:
    # Given a running proxy scoped to app.example.com
    policy = ProxyPolicy(SCOPE, rate_per_second=100.0, max_requests=100)
    with EgressProxy(policy) as proxy:
        handler = urllib.request.ProxyHandler({"https": proxy.proxy_url})
        opener = urllib.request.build_opener(handler)
        # When a CONNECT to an out-of-scope host is attempted, the tunnel is refused (403)
        with pytest.raises(urllib.error.URLError, match="403") as exc:
            opener.open("https://evil.com/", timeout=5.0)
        assert "403" in str(exc.value)
