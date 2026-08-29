"""End-to-end pipeline tests using an injected fake Toolset (no binaries/network)."""

from __future__ import annotations

import dataclasses
from collections.abc import Sequence
from pathlib import Path

import pytest

from reconnaissance.adapters.store import ScanStore
from reconnaissance.adapters.tools import arjun, ffuf, gau, httpx, katana
from reconnaissance.models import Budget, DiscoveredEndpoint, EndpointSource, HttpMethod, ScanConfig, Scope, Technology, TerminationReason
from reconnaissance.pipeline import ResponseSignature as Sig
from reconnaissance.pipeline import Toolset, harvest_query_params, is_soft_404, run_scan

FIXTURES = Path(__file__).parent / "fixtures"
HOST = "app.example.com"
BASE = "https://app.example.com/"


def _probe(urls: Sequence[str], source: EndpointSource, proxy: str | None) -> httpx.ProbeOutcome:
    # The soft-404 baseline probe hits the random path -> return a 200/5123 signature.
    endpoints = tuple(DiscoveredEndpoint(url=u, method=HttpMethod.GET, source=source, status=200, content_length=5123) for u in urls)
    return httpx.ProbeOutcome(endpoints=endpoints, technologies=(), missing_binary=False)


def _crawl(seeds: Sequence[str], proxy: str | None, headless: bool) -> katana.CrawlOutcome:
    if any("login" in s for s in seeds) or seeds == ():
        return katana.CrawlOutcome(endpoints=(), js_urls=(), missing_binary=False)
    endpoints = (
        DiscoveredEndpoint(url="https://app.example.com/login", method=HttpMethod.GET, source=EndpointSource.CRAWL, status=200),
        DiscoveredEndpoint(url="https://evil.other.com/x", method=HttpMethod.GET, source=EndpointSource.CRAWL, status=200),
    )
    return katana.CrawlOutcome(endpoints=endpoints, js_urls=("https://app.example.com/static/app.js",), missing_binary=False)


def _fuzz_with_soft404(base: str, wordlist: str, proxy: str | None) -> ffuf.FuzzOutcome:
    endpoints = (
        DiscoveredEndpoint(url="https://app.example.com/admin", method=HttpMethod.GET, source=EndpointSource.BRUTE, status=403, content_length=146),
        DiscoveredEndpoint(url="https://app.example.com/random404", method=HttpMethod.GET, source=EndpointSource.BRUTE, status=200, content_length=5123),
    )
    return ffuf.FuzzOutcome(endpoints=endpoints, missing_binary=False)


def _no_params(url: str, proxy: str | None) -> arjun.ParamOutcome:
    return arjun.ParamOutcome(params=(), missing_binary=False)


def _no_gau(host: str, proxy: str | None) -> gau.GauOutcome:
    return gau.GauOutcome(urls=(), endpoints=(), missing_binary=False)


def _sourcemap_body(url: str, proxy: str | None) -> str | None:
    if url.endswith("app.js.map"):
        return (FIXTURES / "app.js.map").read_text()
    return None


def _config() -> ScanConfig:
    return ScanConfig(base_url=BASE, scope=Scope(target_host=HOST))


def _fake_toolset() -> Toolset:
    return Toolset(probe=_probe, crawl=_crawl, fuzz=_fuzz_with_soft404, find_params=_no_params, collect_historical=_no_gau, http_get=_sourcemap_body)


@pytest.mark.integration
def test_run_scan_end_to_end_builds_inventory_and_converges(tmp_path: Path) -> None:
    # Given a fully faked toolset (crawl + soft-404 fuzz + sourcemap)
    db = str(tmp_path / "s.sqlite")
    # When a scan runs with a wordlist (enables brute stage)
    result = run_scan(_config(), db_path=db, wordlist=str(tmp_path / "wl.txt"), toolset=_fake_toolset())
    # Then it converges and the inventory holds the expected in-scope endpoints
    assert result.termination_reason is TerminationReason.CONVERGED
    store = ScanStore(db)
    urls = {str(r["url"]) for r in store.list_endpoints(result.scan_id)}
    assert BASE in urls
    assert "https://app.example.com/login" in urls
    # sourcemap-recovered endpoint present
    assert "https://app.example.com/api/v2/login" in urls
    # off-host crawl result excluded by scope
    assert not any("evil.other.com" in u for u in urls)
    # soft-404 (200/5123 == baseline) dropped, real 403 admin kept
    assert "https://app.example.com/admin" in urls
    assert not any("random404" in u for u in urls)


@pytest.mark.integration
def test_run_scan_graceful_when_all_binaries_missing(tmp_path: Path) -> None:
    # Given the real Toolset (no recon binaries installed) but http_get faked off
    db = str(tmp_path / "s.sqlite")
    toolset = Toolset(
        probe=lambda urls, source, proxy: httpx.ProbeOutcome(endpoints=(), technologies=(), missing_binary=True),
        crawl=lambda seeds, proxy, headless: katana.CrawlOutcome(endpoints=(), js_urls=(), missing_binary=True),
        fuzz=lambda base, wl, proxy: ffuf.FuzzOutcome(endpoints=(), missing_binary=True),
        find_params=lambda url, proxy: arjun.ParamOutcome(params=(), missing_binary=True),
        collect_historical=lambda host, proxy: gau.GauOutcome(urls=(), endpoints=(), missing_binary=True),
        http_get=lambda url, proxy: None,
    )
    # When a scan runs with everything missing
    result = run_scan(_config(), db_path=db, toolset=toolset)
    # Then it still completes: the seed endpoint is recorded and it converges
    assert result.termination_reason is TerminationReason.CONVERGED
    assert result.endpoint_count >= 1


@pytest.mark.integration
def test_run_scan_sends_discovered_state_changing_requests_only_when_destructive(tmp_path: Path) -> None:
    # Given a crawl that surfaces a DELETE endpoint
    def crawl_delete(seeds: Sequence[str], proxy: str | None, headless: bool) -> katana.CrawlOutcome:
        endpoint = DiscoveredEndpoint(url="https://app.example.com/items/1", method=HttpMethod.DELETE, source=EndpointSource.CRAWL)
        return katana.CrawlOutcome(endpoints=(endpoint,), js_urls=(), missing_binary=False)

    sent: list[tuple[str, str]] = []

    def http_request(url: str, method: str, proxy: str | None) -> int | None:
        sent.append((method, url))
        return 204

    base = dataclasses.replace(_fake_toolset(), probe=_empty_probe, crawl=crawl_delete, http_get=lambda url, proxy: None, http_request=http_request)

    # When destructive is OFF (default), the DELETE is inventoried but never sent
    run_scan(ScanConfig(base_url=BASE, scope=Scope(target_host=HOST)), db_path=str(tmp_path / "off.sqlite"), toolset=base)
    assert sent == []

    # When destructive is ON, the DELETE is actually sent and its status recorded
    result = run_scan(ScanConfig(base_url=BASE, scope=Scope(target_host=HOST), send_destructive=True), db_path=str(tmp_path / "on.sqlite"), toolset=base)
    assert ("DELETE", "https://app.example.com/items/1") in sent
    store = ScanStore(str(tmp_path / "on.sqlite"))
    rows = {(str(r["method"]), str(r["url"])): r["status"] for r in store.list_endpoints(result.scan_id)}
    assert rows[("DELETE", "https://app.example.com/items/1")] == 204


def test_harvest_query_params_extracts_named_query_keys() -> None:
    params = harvest_query_params("https://app.example.com/s?q=x&lang=en&q=dup", EndpointSource.GAU)
    names = {p.name for p in params}
    assert names == {"q", "lang"}


def test_is_soft_404_matches_baseline_signature() -> None:
    baseline = Sig(status=200, length_bucket=5123 // 256)
    hit = DiscoveredEndpoint(url="https://x/y", method=HttpMethod.GET, source=EndpointSource.BRUTE, status=200, content_length=5123)
    miss = DiscoveredEndpoint(url="https://x/z", method=HttpMethod.GET, source=EndpointSource.BRUTE, status=403, content_length=146)
    assert is_soft_404(Sig.of(hit), baseline) is True
    assert is_soft_404(Sig.of(miss), baseline) is False


def _empty_probe(urls: Sequence[str], source: EndpointSource, proxy: str | None) -> httpx.ProbeOutcome:
    return httpx.ProbeOutcome(endpoints=(), technologies=(), missing_binary=False)


@pytest.mark.integration
def test_run_scan_reports_budget_exhausted_when_passes_run_out(tmp_path: Path) -> None:
    # Given a crawl that invents a brand-new path pattern on every call (never converges)
    counter = [0]

    def crawl_expanding(seeds: Sequence[str], proxy: str | None, headless: bool) -> katana.CrawlOutcome:
        counter[0] += 1
        url = f"https://app.example.com/section{counter[0]}"
        return katana.CrawlOutcome(endpoints=(DiscoveredEndpoint(url=url, method=HttpMethod.GET, source=EndpointSource.CRAWL, status=200),), js_urls=(), missing_binary=False)

    toolset = dataclasses.replace(_fake_toolset(), probe=_empty_probe, crawl=crawl_expanding, http_get=lambda url, proxy: None)
    config = ScanConfig(base_url=BASE, scope=Scope(target_host=HOST), budget=Budget(max_passes=2))
    # When the pass budget runs out while still expanding
    result = run_scan(config, db_path=str(tmp_path / "s.sqlite"), toolset=toolset)
    # Then it is reported as partial, not converged
    assert result.termination_reason is TerminationReason.BUDGET_EXHAUSTED


@pytest.mark.integration
def test_run_scan_reports_budget_exhausted_when_endpoint_cap_hit(tmp_path: Path) -> None:
    # Given an endpoint budget of 1 (the seed alone hits it)
    config = ScanConfig(base_url=BASE, scope=Scope(target_host=HOST), budget=Budget(max_endpoints=1))
    toolset = dataclasses.replace(_fake_toolset(), probe=_empty_probe, http_get=lambda url, proxy: None)
    # When a scan runs
    result = run_scan(config, db_path=str(tmp_path / "s.sqlite"), toolset=toolset)
    # Then the endpoint budget (counting real endpoints, not patterns) stops it
    assert result.termination_reason is TerminationReason.BUDGET_EXHAUSTED


@pytest.mark.integration
def test_run_scan_captures_technologies_from_probe(tmp_path: Path) -> None:
    # Given a probe that fingerprints a technology
    def probe_with_tech(urls: Sequence[str], source: EndpointSource, proxy: str | None) -> httpx.ProbeOutcome:
        return httpx.ProbeOutcome(endpoints=(), technologies=(Technology(name="nginx"),), missing_binary=False)

    toolset = dataclasses.replace(_fake_toolset(), probe=probe_with_tech, crawl=lambda s, p, h: katana.CrawlOutcome(endpoints=(), js_urls=(), missing_binary=False), http_get=lambda url, proxy: None)
    db = str(tmp_path / "s.sqlite")
    result = run_scan(ScanConfig(base_url=BASE, scope=Scope(target_host=HOST)), db_path=db, toolset=toolset)
    # Then the technology is persisted on the scan
    import json

    scan = ScanStore(db).get_scan(result.scan_id)
    assert any(t["name"] == "nginx" for t in json.loads(str(scan["tech_json"])))


@pytest.mark.integration
def test_run_scan_extracts_and_masks_secret_from_sourcemap(tmp_path: Path) -> None:
    # Given a crawl that yields a JS asset whose sourcemap leaks an AWS key
    leaky_map = '{"version":3,"sources":["a.ts"],"sourcesContent":["const k=\'AKIAIOSFODNN7EXAMPLE\';"]}'

    def crawl_js(seeds: Sequence[str], proxy: str | None, headless: bool) -> katana.CrawlOutcome:
        if any("app.js" in s for s in seeds):
            return katana.CrawlOutcome(endpoints=(), js_urls=(), missing_binary=False)
        return katana.CrawlOutcome(endpoints=(), js_urls=("https://app.example.com/app.js",), missing_binary=False)

    def http_get(url: str, proxy: str | None) -> str | None:
        return leaky_map if url.endswith(".map") else None

    toolset = dataclasses.replace(_fake_toolset(), probe=_empty_probe, crawl=crawl_js, http_get=http_get)
    db = str(tmp_path / "s.sqlite")
    result = run_scan(ScanConfig(base_url=BASE, scope=Scope(target_host=HOST)), db_path=db, toolset=toolset)
    # Then the JS endpoint carries a masked (non-raw) secret
    import json

    rows = ScanStore(db).list_endpoints(result.scan_id)
    secrets = [s for r in rows for s in json.loads(str(r["secrets_json"]))]
    assert any(s["kind"] == "aws_access_key" for s in secrets)
    assert all(s["preview"] != "AKIAIOSFODNN7EXAMPLE" for s in secrets)
