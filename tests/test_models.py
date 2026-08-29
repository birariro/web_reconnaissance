"""Tests for domain-model validation and secret masking."""

from __future__ import annotations

import pytest

from reconnaissance.models import Budget, DiscoveredEndpoint, EndpointSource, HttpMethod, Secret, fingerprint


def test_discovered_endpoint_rejects_blank_url() -> None:
    with pytest.raises(ValueError, match="non-empty"):
        DiscoveredEndpoint(url="  ", method=HttpMethod.GET, source=EndpointSource.CRAWL)


def test_discovered_endpoint_rejects_out_of_range_status() -> None:
    with pytest.raises(ValueError, match="status out of range"):
        DiscoveredEndpoint(url="https://x/", method=HttpMethod.GET, source=EndpointSource.CRAWL, status=999)


def test_secret_from_raw_masks_value_by_default() -> None:
    secret = Secret.from_raw("aws", "AKIA1234567890ABCD", "https://x/js")
    assert secret.preview == "AKIA…××××"
    assert "1234567890" not in secret.preview
    assert secret.digest == fingerprint("AKIA1234567890ABCD")


def test_secret_from_raw_reveals_value_when_requested() -> None:
    secret = Secret.from_raw("aws", "AKIA1234567890ABCD", "https://x/js", reveal=True)
    assert secret.preview == "AKIA1234567890ABCD"


def test_secret_from_raw_rejects_empty_raw() -> None:
    with pytest.raises(ValueError, match="non-empty"):
        Secret.from_raw("aws", "", "https://x/js")


def test_budget_rejects_zero_passes() -> None:
    with pytest.raises(ValueError, match="max_passes"):
        Budget(max_passes=0)
