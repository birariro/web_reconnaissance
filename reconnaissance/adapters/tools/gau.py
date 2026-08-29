"""gau wrapper: passive historical-URL collection.

gau queries third-party archives (Wayback, Common Crawl, OTX, URLScan) — it does
NOT touch the target directly, so it runs against the passive-source allowlist,
never the target host. Output is one URL per line.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass

from reconnaissance.adapters.execution import DEFAULT_TIMEOUT_SECONDS, run_command
from reconnaissance.models import DiscoveredEndpoint, EndpointSource, HttpMethod

logger = logging.getLogger(__name__)

BINARY = "gau"


@dataclass(frozen=True, slots=True)
class GauOutcome:
    """Result of a gau run.

    Attributes:
        urls: Raw in-order URLs gau emitted (unfiltered; the pipeline scopes and
            revalidates them).
        endpoints: The same URLs as GET endpoints tagged ``EndpointSource.GAU``.
        missing_binary: True if the gau binary was not found.
    """

    urls: tuple[str, ...]
    endpoints: tuple[DiscoveredEndpoint, ...]
    missing_binary: bool


def collect(host: str, *, proxy: str | None = None, timeout: float = DEFAULT_TIMEOUT_SECONDS) -> GauOutcome:
    """Collect historical URLs for ``host`` from public archives.

    Args:
        host: Apex/host to query archives for (e.g. ``app.example.com``).
        proxy: Egress proxy URL; all traffic is forced through it when set.
        timeout: Per-run timeout in seconds.

    Returns:
        A :class:`GauOutcome`. On a missing binary or non-zero exit, the URL
        lists are empty and the pipeline records the gap.
    """
    argv = [BINARY, "--subs", host]
    if proxy is not None:
        argv += ["--proxy", proxy]
    result = run_command(argv, timeout=timeout)
    if result.missing_binary:
        return GauOutcome(urls=(), endpoints=(), missing_binary=True)
    if not result.ok:
        logger.warning("gau failed: host=%s exit=%s timed_out=%s", host, result.exit_code, result.timed_out)
        return GauOutcome(urls=(), endpoints=(), missing_binary=False)

    urls = parse_urls(result.stdout)
    endpoints = tuple(DiscoveredEndpoint(url=url, method=HttpMethod.GET, source=EndpointSource.GAU) for url in urls)
    return GauOutcome(urls=urls, endpoints=endpoints, missing_binary=False)


def parse_urls(text: str) -> tuple[str, ...]:
    """Parse gau stdout (one URL per line) into a tuple. Exposed for testing."""
    return tuple(line.strip() for line in text.splitlines() if line.strip())
