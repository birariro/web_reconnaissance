"""ffuf wrapper: content/endpoint brute-forcing.

ffuf fuzzes a wordlist against a ``FUZZ`` placeholder in the URL and writes its
findings as JSON to a file (``-of json -o <path>``), not stdout. This wrapper
runs GET-only (ffuf's default method) and returns every hit; soft-404 filtering
by response length happens later in the pipeline, not here.
"""

from __future__ import annotations

import contextlib
import json
import logging
import os
import tempfile
from dataclasses import dataclass

from reconnaissance.adapters.execution import DEFAULT_TIMEOUT_SECONDS, run_command
from reconnaissance.models import DiscoveredEndpoint, EndpointSource, HttpMethod

logger = logging.getLogger(__name__)

BINARY = "ffuf"


@dataclass(frozen=True, slots=True)
class FuzzOutcome:
    """Result of an ffuf run.

    Attributes:
        endpoints: Discovered endpoints (one per ffuf result row), tagged
            ``EndpointSource.BRUTE``. Unfiltered: soft-404-looking rows are kept
            for the pipeline to filter by response length.
        missing_binary: True if the ffuf binary was not found.
    """

    endpoints: tuple[DiscoveredEndpoint, ...]
    missing_binary: bool


def fuzz(
    base_url: str,
    wordlist: str,
    *,
    rate: int = 50,
    proxy: str | None = None,
    match_codes: str = "200,204,301,302,307,401,403,405",
    timeout: float = DEFAULT_TIMEOUT_SECONDS,
) -> FuzzOutcome:
    """Brute-force endpoints under ``base_url`` using ``wordlist``.

    Args:
        base_url: Target base URL; ``/FUZZ`` is appended as the fuzz point.
        wordlist: Path to the wordlist file.
        rate: Requests-per-second cap.
        proxy: Egress proxy URL; all traffic is forced through it when set.
        match_codes: Comma-separated HTTP status codes to treat as hits.
        timeout: Per-run timeout in seconds.

    Returns:
        A :class:`FuzzOutcome`. On a missing binary or non-zero exit, the
        endpoint tuple is empty and the pipeline records the gap.
    """
    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tmp:
        tmp_path = tmp.name
    try:
        argv = [
            BINARY,
            "-w", wordlist,
            "-u", base_url.rstrip("/") + "/FUZZ",
            "-mc", match_codes,
            "-ac",
            "-t", "20",
            "-rate", str(rate),
            "-noninteractive",
            "-of", "json",
            "-o", tmp_path,
        ]
        if proxy is not None:
            argv += ["-x", proxy]
        result = run_command(argv, timeout=timeout)
        if result.missing_binary:
            return FuzzOutcome(endpoints=(), missing_binary=True)
        if not result.ok:
            logger.warning("ffuf failed: base_url=%s exit=%s timed_out=%s", base_url, result.exit_code, result.timed_out)
            return FuzzOutcome(endpoints=(), missing_binary=False)

        with open(tmp_path, encoding="utf-8") as handle:
            return parse_fuzz(handle.read())
    finally:
        with contextlib.suppress(FileNotFoundError):
            os.unlink(tmp_path)


def parse_fuzz(text: str) -> FuzzOutcome:
    """Parse ffuf ``-of json`` output into a :class:`FuzzOutcome`. Exposed for testing."""
    if not text.strip():
        return FuzzOutcome(endpoints=(), missing_binary=False)
    try:
        document = json.loads(text)
    except json.JSONDecodeError:
        logger.warning("ffuf output was not valid JSON")
        return FuzzOutcome(endpoints=(), missing_binary=False)

    results = document.get("results") if isinstance(document, dict) else None
    endpoints: list[DiscoveredEndpoint] = []
    for item in results if isinstance(results, list) else []:
        if not isinstance(item, dict):
            continue
        url = item.get("url")
        status = item.get("status")
        if not isinstance(url, str) or not url:
            continue
        endpoints.append(
            DiscoveredEndpoint(
                url=url,
                method=HttpMethod.GET,
                source=EndpointSource.BRUTE,
                status=status if isinstance(status, int) and 100 <= status <= 599 else None,
                content_type=item.get("content-type") if isinstance(item.get("content-type"), str) else None,
                content_length=item.get("length") if isinstance(item.get("length"), int) else None,
            )
        )
    return FuzzOutcome(endpoints=tuple(endpoints), missing_binary=False)
