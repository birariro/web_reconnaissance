"""Deterministic recon pipeline with a bounded convergence loop.

Stages run in order; endpoints discovered by one stage are fed back as seeds
until the set of path-patterns stops growing, a budget is hit, or the egress
kill-switch trips. Everything active goes through the egress proxy, and every
target — including URLs discovered mid-crawl — is scope-checked before use.

The network boundary is injected as a :class:`Toolset` (O8) so the orchestrator
is testable without binaries or real traffic.
"""

from __future__ import annotations

import contextlib
import logging
import time
import urllib.error
import urllib.request
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from urllib.parse import parse_qsl, urlsplit

from reconnaissance import scope as scope_mod
from reconnaissance.adapters.egress import EgressProxy, ProxyPolicy
from reconnaissance.adapters.execution import DockerToolEnvironment
from reconnaissance.adapters.store import EndpointInsert, ScanStore
from reconnaissance.adapters.tools import apispec, arjun, ffuf, gau, httpx, katana, sourcemap
from reconnaissance.models import (
    Classification,
    DiscoveredEndpoint,
    DiscoveredParam,
    EndpointSource,
    HttpMethod,
    ParamLocation,
    ScanConfig,
    Secret,
    TerminationReason,
)

logger = logging.getLogger(__name__)

WELL_KNOWN_PATHS = ("/robots.txt", "/sitemap.xml", "/security.txt", "/.well-known/security.txt")
SPEC_CANDIDATE_PATHS = ("/openapi.json", "/swagger.json", "/api-docs", "/v2/api-docs")
_HTTP_GET_TIMEOUT = 15.0
_MAX_BODY_BYTES = 5 * 1024 * 1024
_SOFT_404_PROBE_PATH = "/reconnaissance-nonexistent-a9f3c1e7"


@dataclass(frozen=True, slots=True)
class ResponseSignature:
    """A coarse response fingerprint used to detect soft-404 catch-alls."""

    status: int | None
    length_bucket: int | None

    @classmethod
    def of(cls, endpoint: DiscoveredEndpoint) -> ResponseSignature:
        length = endpoint.content_length
        bucket = None if length is None else length // 256
        return cls(status=endpoint.status, length_bucket=bucket)


@dataclass(frozen=True, slots=True)
class ScanResult:
    """Summary of a completed scan."""

    scan_id: str
    endpoint_count: int
    parameter_count: int
    termination_reason: TerminationReason


def _safe_url(url: str) -> str:
    parts = urlsplit(url)
    return f"{parts.scheme}://{parts.netloc}{parts.path}"


def _real_http_get(url: str, proxy: str | None) -> str | None:
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({"http": proxy, "https": proxy})) if proxy else urllib.request.build_opener()
    try:
        with opener.open(url, timeout=_HTTP_GET_TIMEOUT) as response:
            raw: bytes = response.read(_MAX_BODY_BYTES)
    except (urllib.error.URLError, OSError, ValueError) as e:
        logger.warning("http get failed: url=%s err=%s", _safe_url(url), type(e).__name__)
        return None
    return raw.decode("utf-8", errors="replace")


@dataclass(frozen=True, slots=True)
class Toolset:
    """Injected network boundary over the recon tools (see :func:`default_toolset`)."""

    probe: Callable[[Sequence[str], EndpointSource, str | None], httpx.ProbeOutcome]
    crawl: Callable[[Sequence[str], str | None, bool], katana.CrawlOutcome]
    fuzz: Callable[[str, str, str | None], ffuf.FuzzOutcome]
    find_params: Callable[[str, str | None], arjun.ParamOutcome]
    collect_historical: Callable[[str, str | None], gau.GauOutcome]
    http_get: Callable[[str, str | None], str | None]


def default_toolset(rate: int) -> Toolset:
    """Build the real toolset, threading the per-request ``rate`` into every tool
    so each self-limits (the proxy only bounds per-connection over TLS)."""
    return Toolset(
        probe=lambda urls, source, proxy: httpx.probe(urls, source=source, proxy=proxy, rate=rate),
        crawl=lambda seeds, proxy, headless: katana.crawl(seeds, proxy=proxy, headless=headless, rate=rate),
        fuzz=lambda base, wordlist, proxy: ffuf.fuzz(base, wordlist, proxy=proxy, rate=rate),
        find_params=lambda url, proxy: arjun.find_params(url, proxy=proxy, rate=rate),
        collect_historical=lambda host, proxy: gau.collect(host, proxy=proxy),
        http_get=_real_http_get,
    )


class _PatternLedger:
    """Tracks path-patterns seen and enforces the per-pattern visit cap."""

    def __init__(self, per_pattern_cap: int) -> None:
        self._cap = per_pattern_cap
        self._counts: dict[str, int] = {}

    def admit(self, url: str) -> bool:
        """Return True if ``url`` is a novel pattern instance within the cap."""
        pattern = scope_mod.path_pattern(url)
        count = self._counts.get(pattern, 0)
        if count >= self._cap:
            return False
        self._counts[pattern] = count + 1
        return True

    @property
    def pattern_count(self) -> int:
        return len(self._counts)


def harvest_query_params(url: str, source: EndpointSource) -> tuple[DiscoveredParam, ...]:
    """Extract query-string parameters from a URL (e.g. a historical gau URL)."""
    query = urlsplit(url).query
    if not query:
        return ()
    seen: set[str] = set()
    params: list[DiscoveredParam] = []
    for name, value in parse_qsl(query, keep_blank_values=True):
        if name and name not in seen:
            seen.add(name)
            params.append(DiscoveredParam(name=name, location=ParamLocation.QUERY, source=source, sample_value=value or None))
    return tuple(params)


def classify_endpoint(url: str, content_type: str | None) -> Classification:
    """Coarsely classify an endpoint from its path and content type."""
    path = urlsplit(url).path.lower()
    if "/admin" in path:
        return Classification.ADMIN
    if any(marker in path for marker in ("/login", "/logout", "/auth", "/oauth", "/session")):
        return Classification.AUTH
    if "/api" in path or "/graphql" in path or (content_type is not None and "json" in content_type):
        return Classification.API
    if urlsplit(url).query or "{id}" in scope_mod.path_pattern(url):
        return Classification.DYNAMIC
    if content_type is not None and any(marker in content_type for marker in ("javascript", "css", "image", "font")):
        return Classification.STATIC
    return Classification.UNKNOWN


def is_soft_404(sig: ResponseSignature, baseline: ResponseSignature | None) -> bool:
    """True if a response matches the catch-all baseline (a soft 404)."""
    if baseline is None or sig.status is None:
        return False
    return sig.status == baseline.status and sig.length_bucket == baseline.length_bucket


@dataclass(slots=True)
class _ScanContext:
    config: ScanConfig
    store: ScanStore
    scan_id: str
    proxy_url: str
    policy: ProxyPolicy
    toolset: Toolset
    wordlist: str | None
    ledger: _PatternLedger
    tool_proxy_url: str = ""
    headless: bool = False
    baseline: ResponseSignature | None = None
    technologies: list[dict[str, str | None]] = field(default_factory=list)
    api_surfaces: list[dict[str, object]] = field(default_factory=list)
    start_time: float = 0.0
    endpoint_count: int = 0


def run_scan(
    config: ScanConfig,
    *,
    db_path: str,
    wordlist: str | None = None,
    toolset: Toolset | None = None,
    proxy_rate: float = 50.0,
    max_concurrency: int = 8,
    headless: bool = False,
    clock: Callable[[], float] = time.monotonic,
) -> ScanResult:
    """Run the full deterministic pipeline for one authorized target.

    Args:
        config: Validated scan configuration (must be ``authorized``).
        db_path: SQLite path for the inventory.
        wordlist: Optional wordlist for directory brute force (skipped if None).
        toolset: Injected tool boundary. When None the real tools run inside the
            Docker image (mandatory); tests inject a fake and skip Docker.
        proxy_rate: Global requests-per-second ceiling enforced by the proxy.
        clock: Monotonic clock (injected for testing).

    Returns:
        A :class:`ScanResult` with counts and the termination reason.

    Raises:
        RuntimeError: If real tools are needed but Docker is unavailable.
    """
    use_real_tools = toolset is None
    tools = toolset if toolset is not None else default_toolset(int(proxy_rate))
    store = ScanStore(db_path)
    store.initialize()
    scan_id = store.create_scan(config)
    policy = ProxyPolicy(config.scope, rate_per_second=proxy_rate, max_requests=config.budget.max_requests, max_concurrency=max_concurrency)

    with contextlib.ExitStack() as stack:
        if use_real_tools:
            # Recon tools run only inside the pinned Docker image — no host binaries.
            if not DockerToolEnvironment.available():
                raise RuntimeError("Docker is required to run recon tools; start the Docker daemon and retry.")
            stack.enter_context(DockerToolEnvironment())
            bind_host, tool_proxy_host = "0.0.0.0", "host.docker.internal"  # noqa: S104 - reachable from the tools container; scope-guarded
        else:
            bind_host, tool_proxy_host = "127.0.0.1", "127.0.0.1"
        proxy = stack.enter_context(EgressProxy(policy, host=bind_host))
        ctx = _ScanContext(
            config=config,
            store=store,
            scan_id=scan_id,
            proxy_url=proxy.url_for("127.0.0.1"),
            tool_proxy_url=proxy.url_for(tool_proxy_host),
            policy=policy,
            toolset=tools,
            wordlist=wordlist,
            ledger=_PatternLedger(config.budget.per_pattern_cap),
            headless=headless,
            start_time=clock(),
        )
        reason = _run_stages(ctx, clock=clock)

    endpoints = store.list_endpoints(scan_id)
    parameters = store.list_parameters(scan_id)
    store.finish_scan(scan_id, reason=reason, technologies=ctx.technologies, api_surfaces=ctx.api_surfaces)
    logger.info("scan finished: scan_id=%s endpoints=%d params=%d reason=%s", scan_id, len(endpoints), len(parameters), reason)
    return ScanResult(scan_id=scan_id, endpoint_count=len(endpoints), parameter_count=len(parameters), termination_reason=reason)


def _run_stages(ctx: _ScanContext, *, clock: Callable[[], float]) -> TerminationReason:
    base_url = scope_mod.normalize_url(ctx.config.base_url)
    _establish_soft_404_baseline(ctx, base_url)
    _record_endpoint(ctx, DiscoveredEndpoint(url=base_url, method=HttpMethod.GET, source=EndpointSource.SEED))
    _stage_probe(ctx, [base_url], EndpointSource.SEED)

    seeds = {base_url}
    seeds |= _stage_well_known(ctx, base_url)
    seeds |= _stage_historical(ctx)
    seeds |= _stage_api_specs(ctx, base_url)

    for pass_index in range(ctx.config.budget.max_passes):
        if _killswitch_tripped(ctx):
            return TerminationReason.KILLSWITCH
        if _budget_exhausted(ctx, clock=clock):
            return TerminationReason.BUDGET_EXHAUSTED
        before = ctx.ledger.pattern_count
        new_seeds = _run_discovery_pass(ctx, sorted(seeds), first_pass=pass_index == 0)
        _stage_probe(ctx, sorted(new_seeds), EndpointSource.CRAWL)
        seeds = new_seeds
        logger.info("pass complete: pass=%d patterns=%d new_seeds=%d", pass_index, ctx.ledger.pattern_count, len(new_seeds))
        if ctx.ledger.pattern_count == before or not new_seeds:
            return TerminationReason.CONVERGED
    # Ran out of passes while still finding new patterns → coverage is partial.
    return TerminationReason.BUDGET_EXHAUSTED


def _stage_probe(ctx: _ScanContext, urls: Sequence[str], source: EndpointSource) -> None:
    scoped = [u for u in urls if scope_mod.is_in_scope(u, ctx.config.scope, active=True)]
    if not scoped:
        return
    outcome = ctx.toolset.probe(scoped, source, ctx.tool_proxy_url)
    if outcome.missing_binary:
        ctx.store.log_error(ctx.scan_id, "probe", "httpx binary missing")
        return
    for tech in outcome.technologies:
        entry: dict[str, str | None] = {"name": tech.name, "version": tech.version, "category": tech.category}
        if entry not in ctx.technologies:
            ctx.technologies.append(entry)
    for endpoint in outcome.endpoints:
        if not scope_mod.is_in_scope(endpoint.url, ctx.config.scope, active=True):
            continue
        if is_soft_404(ResponseSignature.of(endpoint), ctx.baseline):
            continue
        _record_endpoint(ctx, endpoint)


def _run_discovery_pass(ctx: _ScanContext, seeds: Sequence[str], *, first_pass: bool) -> set[str]:
    discovered: set[str] = set()
    discovered |= _stage_crawl(ctx, seeds)
    if first_pass and ctx.wordlist is not None:
        discovered |= _stage_bruteforce(ctx)
    _stage_parameters(ctx, seeds)
    # Only in-scope, novel-pattern URLs become the next frontier.
    return {url for url in discovered if scope_mod.is_in_scope(url, ctx.config.scope, active=True) and ctx.ledger.admit(url)}


def _establish_soft_404_baseline(ctx: _ScanContext, base_url: str) -> None:
    probe_url = scope_mod.normalize_url(base_url.rstrip("/") + _SOFT_404_PROBE_PATH)
    outcome = ctx.toolset.probe([probe_url], EndpointSource.SEED, ctx.tool_proxy_url)
    if outcome.endpoints:
        ctx.baseline = ResponseSignature.of(outcome.endpoints[0])
        logger.debug("soft-404 baseline: %s", ctx.baseline)


def _stage_well_known(ctx: _ScanContext, base_url: str) -> set[str]:
    found: set[str] = set()
    for path in WELL_KNOWN_PATHS:
        url = scope_mod.normalize_url(base_url.rstrip("/") + path)
        body = ctx.toolset.http_get(url, ctx.proxy_url)
        if body is None:
            continue
        _record_endpoint(ctx, DiscoveredEndpoint(url=url, method=HttpMethod.GET, source=EndpointSource.ROBOTS))
        found |= _extract_paths_from_text(ctx, base_url, body)
    return found


def _extract_paths_from_text(ctx: _ScanContext, base_url: str, body: str) -> set[str]:
    found: set[str] = set()
    for line in body.splitlines():
        token = line.split(":", 1)[-1].strip() if ":" in line else line.strip()
        if token.startswith("/"):
            candidate = scope_mod.normalize_url(base_url.rstrip("/") + token.split()[0])
            if scope_mod.is_in_scope(candidate, ctx.config.scope, active=True):
                found.add(candidate)
    return found


def _stage_historical(ctx: _ScanContext) -> set[str]:
    outcome = ctx.toolset.collect_historical(ctx.config.scope.target_host, ctx.tool_proxy_url)
    if outcome.missing_binary:
        ctx.store.log_error(ctx.scan_id, "historical", "gau binary missing")
        return set()
    found: set[str] = set()
    for url in outcome.urls:
        if not scope_mod.is_in_scope(url, ctx.config.scope, active=True):
            continue
        normalized = scope_mod.normalize_url(url)
        endpoint_id = _record_endpoint(ctx, DiscoveredEndpoint(url=normalized, method=HttpMethod.GET, source=EndpointSource.GAU))
        for param in harvest_query_params(url, EndpointSource.GAU):
            ctx.store.add_parameter(endpoint_id, param)
        found.add(normalized)
    return found


def _stage_api_specs(ctx: _ScanContext, base_url: str) -> set[str]:
    found: set[str] = set()
    for path in SPEC_CANDIDATE_PATHS:
        url = scope_mod.normalize_url(base_url.rstrip("/") + path)
        body = ctx.toolset.http_get(url, ctx.proxy_url)
        if body is None:
            continue
        result = apispec.walk_spec(body)
        if not result.endpoints:
            continue
        ctx.api_surfaces.append({"kind": str(result.kind), "location": url, "base_urls": list(result.base_urls), "endpoint_count": len(result.endpoints), "operations": result.operation_count})
        for spec_endpoint in result.endpoints:
            if not scope_mod.is_in_scope(spec_endpoint.endpoint.url, ctx.config.scope, active=True):
                continue
            endpoint_id = _record_endpoint(ctx, spec_endpoint.endpoint)
            for param in spec_endpoint.params:
                ctx.store.add_parameter(endpoint_id, param)
            found.add(spec_endpoint.endpoint.url)
    return found


def _stage_crawl(ctx: _ScanContext, seeds: Sequence[str]) -> set[str]:
    outcome = ctx.toolset.crawl(seeds, ctx.tool_proxy_url, False)
    if outcome.missing_binary:
        ctx.store.log_error(ctx.scan_id, "crawl", "katana binary missing")
        return set()
    found: set[str] = set()
    for endpoint in outcome.endpoints:
        if not scope_mod.is_in_scope(endpoint.url, ctx.config.scope, active=True):
            continue
        _record_endpoint(ctx, endpoint)
        found.add(scope_mod.normalize_url(endpoint.url))
    found |= _stage_js(ctx, outcome.js_urls)
    return found


def _stage_js(ctx: _ScanContext, js_urls: Sequence[str]) -> set[str]:
    """Analyze each discovered JS asset: its raw body and its sourcemap.

    From both we extract referenced endpoints (and their query parameters) and
    scan for exposed secrets. The raw-body scan is what recovers endpoints/params
    that live only in client JS (e.g. a ``"/search?q="`` fetch) when no sourcemap
    is published.
    """
    found: set[str] = set()
    for js_url in js_urls:
        if not scope_mod.is_in_scope(js_url, ctx.config.scope, active=True):
            continue
        js_id = _record_endpoint(ctx, DiscoveredEndpoint(url=scope_mod.normalize_url(js_url), method=HttpMethod.GET, source=EndpointSource.JS))
        body = ctx.toolset.http_get(js_url, ctx.proxy_url)
        if body is not None:
            _record_secrets(ctx, js_id, js_url, body)
            found |= _record_refs(ctx, js_url, sourcemap.extract_references(body))
        map_url = sourcemap.map_url_for(js_url)
        map_body = ctx.toolset.http_get(map_url, ctx.proxy_url)
        if map_body is not None:
            _record_secrets(ctx, js_id, map_url, map_body)
            found |= _record_refs(ctx, js_url, sourcemap.parse_sourcemap(map_body).endpoints)
    return found


def _record_refs(ctx: _ScanContext, base_url: str, refs: Sequence[str]) -> set[str]:
    found: set[str] = set()
    for ref in refs:
        candidate = scope_mod.absolutize(base_url, ref)
        if candidate is None or not scope_mod.is_in_scope(candidate, ctx.config.scope, active=True):
            continue
        endpoint_id = _record_endpoint(ctx, DiscoveredEndpoint(url=candidate, method=HttpMethod.GET, source=EndpointSource.JS))
        for param in harvest_query_params(candidate, EndpointSource.JS):
            ctx.store.add_parameter(endpoint_id, param)
        found.add(candidate)
    return found


def _record_secrets(ctx: _ScanContext, endpoint_id: str, source_url: str, body: str) -> None:
    for kind, raw in sourcemap.find_secrets(body):
        secret = Secret.from_raw(kind, raw, source_url, reveal=ctx.config.reveal_secrets)
        ctx.store.add_secret(endpoint_id, {"kind": secret.kind, "preview": secret.preview, "digest": secret.digest, "source_url": secret.source_url})


def _stage_bruteforce(ctx: _ScanContext) -> set[str]:
    if ctx.wordlist is None:
        return set()
    base_url = scope_mod.normalize_url(ctx.config.base_url)
    outcome = ctx.toolset.fuzz(base_url, ctx.wordlist, ctx.tool_proxy_url)
    if outcome.missing_binary:
        ctx.store.log_error(ctx.scan_id, "bruteforce", "ffuf binary missing")
        return set()
    found: set[str] = set()
    for endpoint in outcome.endpoints:
        if not scope_mod.is_in_scope(endpoint.url, ctx.config.scope, active=True):
            continue
        if is_soft_404(ResponseSignature.of(endpoint), ctx.baseline):
            logger.debug("soft-404 dropped: url=%s", endpoint.url)
            continue
        _record_endpoint(ctx, endpoint)
        found.add(scope_mod.normalize_url(endpoint.url))
    return found


def _stage_parameters(ctx: _ScanContext, seeds: Sequence[str]) -> None:
    for url in seeds:
        if not _is_dynamic(url):
            continue
        outcome = ctx.toolset.find_params(url, ctx.tool_proxy_url)
        if outcome.missing_binary:
            ctx.store.log_error(ctx.scan_id, "parameters", "arjun binary missing")
            return
        endpoint_id = _record_endpoint(ctx, DiscoveredEndpoint(url=scope_mod.normalize_url(url), method=HttpMethod.GET, source=EndpointSource.CRAWL))
        for param in outcome.params:
            ctx.store.add_parameter(endpoint_id, param)


def _is_dynamic(url: str) -> bool:
    return bool(urlsplit(url).query) or "{id}" in scope_mod.path_pattern(url)


def _record_endpoint(ctx: _ScanContext, endpoint: DiscoveredEndpoint) -> str:
    normalized = scope_mod.normalize_url(endpoint.url)
    parts = urlsplit(normalized)
    row = EndpointInsert(
        endpoint=endpoint,
        path=parts.path or "/",
        path_pattern=scope_mod.path_pattern(normalized),
        classification=classify_endpoint(normalized, endpoint.content_type),
        in_scope=scope_mod.is_in_scope(normalized, ctx.config.scope, active=True),
        response_sig=str(ResponseSignature.of(endpoint)) if endpoint.status is not None else None,
    )
    endpoint_id, is_new = ctx.store.add_endpoint(ctx.scan_id, row)
    if is_new:
        ctx.endpoint_count += 1
    return endpoint_id


def _budget_exhausted(ctx: _ScanContext, *, clock: Callable[[], float]) -> bool:
    if ctx.endpoint_count >= ctx.config.budget.max_endpoints:
        return True
    return (clock() - ctx.start_time) >= ctx.config.budget.max_seconds


def _killswitch_tripped(ctx: _ScanContext) -> bool:
    return ctx.policy.request_count >= ctx.config.budget.max_requests
