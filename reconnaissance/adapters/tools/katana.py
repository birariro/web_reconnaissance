"""katana wrapper: active in-scope crawling.

katana (ProjectDiscovery) actively crawls the target from a set of seed URLs,
emitting one JSONL object per discovered request. It runs in a non-destructive
GET profile only: JS-parsing crawl (``-jc``), known-files (``-kf all``), and XHR
extraction are enabled, but no form-fill/auto-submit flag is ever passed, so
katana records request surfaces without replaying state-changing requests.
"""

from __future__ import annotations

import json
import logging
from collections.abc import Sequence
from dataclasses import dataclass
from urllib.parse import urlsplit

from reconnaissance.adapters.execution import DEFAULT_TIMEOUT_SECONDS, run_command
from reconnaissance.models import DiscoveredEndpoint, EndpointSource, HttpMethod

logger = logging.getLogger(__name__)

BINARY = "katana"

# GET/HEAD/OPTIONS map straight through; anything else is recorded as GET only.
_RECORDABLE_METHODS = {m.value: m for m in HttpMethod}


@dataclass(frozen=True, slots=True)
class CrawlOutcome:
    """Result of a katana crawl.

    Attributes:
        endpoints: Discovered request surfaces tagged ``EndpointSource.CRAWL``.
        js_urls: URLs that look like JavaScript (``.js`` path or javascript
            content-type), for downstream JS analysis.
        missing_binary: True if the katana binary was not found.
    """

    endpoints: tuple[DiscoveredEndpoint, ...]
    js_urls: tuple[str, ...]
    missing_binary: bool


def crawl(
    seeds: Sequence[str],
    *,
    depth: int = 3,
    rate: int = 50,
    proxy: str | None = None,
    headless: bool = False,
    timeout: float = DEFAULT_TIMEOUT_SECONDS,
) -> CrawlOutcome:
    """Crawl ``seeds`` in-scope and record discovered request surfaces.

    Args:
        seeds: Seed URLs to crawl from; fed to katana via stdin. Empty means no run.
        depth: Maximum crawl depth (``-d``).
        rate: Requests per second (``-rl``).
        proxy: Egress proxy URL; all traffic is forced through it when set.
        headless: Drive a headless browser (``-hl -sc``) for JS-heavy targets.
        timeout: Per-run timeout in seconds.

    Returns:
        A :class:`CrawlOutcome`. On a missing binary or non-zero exit, all
        result tuples are empty and the pipeline records the gap.
    """
    if not seeds:
        return CrawlOutcome(endpoints=(), js_urls=(), missing_binary=False)

    argv = [
        BINARY,
        "-jc",
        "-kf",
        "all",
        "-xhr",
        "-d",
        str(depth),
        "-rl",
        str(rate),
        "-silent",
        "-j",
        "-ef",
        "png,jpg,jpeg,gif,svg,woff,woff2,ttf,eot,ico",
    ]
    if headless:
        argv += ["-hl", "-sc"]
    if proxy is not None:
        argv += ["-proxy", proxy]

    result = run_command(argv, timeout=timeout, input_text="\n".join(seeds))
    if result.missing_binary:
        return CrawlOutcome(endpoints=(), js_urls=(), missing_binary=True)
    if not result.ok:
        logger.warning("katana failed: seeds=%s exit=%s timed_out=%s", len(seeds), result.exit_code, result.timed_out)
        return CrawlOutcome(endpoints=(), js_urls=(), missing_binary=False)

    return parse_crawl(result.stdout)


def parse_crawl(text: str) -> CrawlOutcome:
    """Parse katana JSONL into a :class:`CrawlOutcome`. Exposed for testing.

    Each non-blank line is a JSON object shaped
    ``{"request":{"method","endpoint"},"response":{"status_code","content_type","title"}}``.
    Non-GET/HEAD/OPTIONS methods are still recorded but forced to GET — the
    pipeline only records surfaces, it never replays a state-changing request.
    Blank or malformed lines are skipped with a warning.
    """
    endpoints: list[DiscoveredEndpoint] = []
    js_urls: list[str] = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            record = json.loads(line)
        except json.JSONDecodeError:
            logger.warning("katana: skipping non-JSON line")
            continue

        if not isinstance(record, dict):
            continue
        request = record.get("request")
        response = record.get("response")
        request = request if isinstance(request, dict) else {}
        response = response if isinstance(response, dict) else {}
        url = request.get("endpoint")
        if not isinstance(url, str) or not url:
            continue

        raw_method = str(request.get("method", "GET")).upper()
        method = _RECORDABLE_METHODS.get(raw_method)
        if method is None:
            logger.debug("katana: recording non-GET method as GET: method=%s url=%s", raw_method, url)
            method = HttpMethod.GET

        content_type = response.get("content_type")
        status = response.get("status_code")
        endpoints.append(
            DiscoveredEndpoint(
                url=url,
                method=method,
                source=EndpointSource.CRAWL,
                status=status if isinstance(status, int) and 100 <= status <= 599 else None,
                content_type=content_type if isinstance(content_type, str) else None,
                title=response.get("title") if isinstance(response.get("title"), str) else None,
            )
        )

        if urlsplit(url).path.endswith(".js") or (content_type is not None and "javascript" in content_type):
            js_urls.append(url)

    return CrawlOutcome(endpoints=tuple(endpoints), js_urls=tuple(js_urls), missing_binary=False)
