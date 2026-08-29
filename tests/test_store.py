"""Integration tests for the SQLite store (real DB, injected clock/id)."""

from __future__ import annotations

import itertools
import json
from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path

import pytest

from reconnaissance.adapters.store import EndpointInsert, ScanStore
from reconnaissance.models import Classification, DiscoveredEndpoint, DiscoveredParam, EndpointSource, HttpMethod, ParamLocation, ScanConfig, Scope, TerminationReason

FIXED_NOW = datetime(2026, 8, 29, 12, 0, 0, tzinfo=UTC)


def _ids() -> Iterator[str]:
    for n in itertools.count():
        yield f"id-{n}"


def _store(tmp_path: Path) -> ScanStore:
    ids = _ids()
    store = ScanStore(str(tmp_path / "scan.sqlite"), now=lambda: FIXED_NOW, new_id=lambda: next(ids))
    store.initialize()
    return store


def _config() -> ScanConfig:
    return ScanConfig(base_url="https://app.example.com/", scope=Scope(target_host="app.example.com"))


def _endpoint(url: str, *, source: EndpointSource = EndpointSource.CRAWL, status: int | None = None, title: str | None = None) -> EndpointInsert:
    ep = DiscoveredEndpoint(url=url, method=HttpMethod.GET, source=source, status=status, title=title)
    return EndpointInsert(endpoint=ep, path="/x", path_pattern="/x", classification=Classification.DYNAMIC, in_scope=True)


@pytest.mark.integration
def test_add_endpoint_inserts_new_then_merges_on_repeat(tmp_path: Path) -> None:
    # Given a scan
    store = _store(tmp_path)
    scan_id = store.create_scan(_config())
    # When the same URL is added twice from different sources
    first_id, first_new = store.add_endpoint(scan_id, _endpoint("https://app.example.com/a", source=EndpointSource.CRAWL))
    second_id, second_new = store.add_endpoint(scan_id, _endpoint("https://app.example.com/a", source=EndpointSource.GAU, status=200, title="A"))
    # Then it is one row, sources merged, probe fields filled
    assert first_new is True
    assert second_new is False
    assert first_id == second_id
    rows = store.list_endpoints(scan_id)
    assert len(rows) == 1
    assert set(json.loads(str(rows[0]["sources_json"]))) == {"crawl", "gau"}
    assert rows[0]["status"] == 200
    assert rows[0]["title"] == "A"


@pytest.mark.integration
def test_add_parameter_dedups_on_same_endpoint(tmp_path: Path) -> None:
    store = _store(tmp_path)
    scan_id = store.create_scan(_config())
    endpoint_id, _ = store.add_endpoint(scan_id, _endpoint("https://app.example.com/s"))
    param = DiscoveredParam(name="q", location=ParamLocation.QUERY, source=EndpointSource.BRUTE)
    store.add_parameter(endpoint_id, param)
    store.add_parameter(endpoint_id, param)
    assert len(store.list_parameters(scan_id)) == 1


@pytest.mark.integration
def test_finish_scan_records_termination_reason(tmp_path: Path) -> None:
    store = _store(tmp_path)
    scan_id = store.create_scan(_config())
    store.finish_scan(scan_id, reason=TerminationReason.BUDGET_EXHAUSTED, technologies=[{"name": "nginx"}], api_surfaces=[])
    scan = store.get_scan(scan_id)
    assert scan["termination_reason"] == "budget_exhausted"
    assert scan["finished_at"] is not None


@pytest.mark.integration
def test_get_scan_raises_for_unknown_id(tmp_path: Path) -> None:
    store = _store(tmp_path)
    with pytest.raises(KeyError, match="scan not found"):
        store.get_scan("nope")
