"""arjun wrapper: HTTP parameter discovery (GET-only, non-destructive).

arjun brute-forces hidden query parameters against a live URL. Parameter
discovery is only non-destructive in GET mode, so this wrapper hard-codes
``-m GET`` and never sends POST/PUT/DELETE. Output is a JSON object keyed by
URL (arjun ``-oJ``); each value carries a ``method`` and a ``params`` list.
"""

from __future__ import annotations

import contextlib
import json
import logging
import os
import tempfile
from dataclasses import dataclass

from reconnaissance.adapters.execution import DEFAULT_TIMEOUT_SECONDS, run_command
from reconnaissance.models import DiscoveredParam, EndpointSource, ParamLocation

logger = logging.getLogger(__name__)

BINARY = "arjun"


@dataclass(frozen=True, slots=True)
class ParamOutcome:
    """Result of an arjun parameter-discovery run.

    Attributes:
        params: Discovered query parameters, deduplicated by name in
            first-seen order.
        missing_binary: True if the arjun binary was not found.
    """

    params: tuple[DiscoveredParam, ...]
    missing_binary: bool


def find_params(url: str, *, proxy: str | None = None, rate: int = 0, timeout: float = DEFAULT_TIMEOUT_SECONDS) -> ParamOutcome:
    """Discover hidden GET parameters on ``url``.

    Runs arjun in GET mode only (parameter discovery is non-destructive only
    for GET). arjun writes JSON via ``-oJ`` to a temp file, which is read back
    and parsed.

    Args:
        url: Absolute URL to probe (e.g. ``https://app.example.com/search``).
        proxy: Egress proxy URL; forced through ``HTTP_PROXY``/``HTTPS_PROXY``
            when set (arjun has no stable proxy flag).
        rate: Requests-per-second cap; passed as ``--rate-limit`` only when > 0.
        timeout: Per-run timeout in seconds.

    Returns:
        A :class:`ParamOutcome`. On a missing binary or non-zero exit, the
        params tuple is empty and the pipeline records the gap.
    """
    fd, tmp_path = tempfile.mkstemp(suffix=".json")
    os.close(fd)
    try:
        argv = [BINARY, "-u", url, "-m", "GET", "-oJ", tmp_path]
        if rate > 0:
            argv += ["--rate-limit", str(rate)]
        env = {"HTTP_PROXY": proxy, "HTTPS_PROXY": proxy} if proxy is not None else None
        result = run_command(argv, timeout=timeout, env=env)
        if result.missing_binary:
            return ParamOutcome(params=(), missing_binary=True)
        if not result.ok:
            logger.warning("arjun failed: url=%s exit=%s timed_out=%s", url, result.exit_code, result.timed_out)
            return ParamOutcome(params=(), missing_binary=False)

        with open(tmp_path, encoding="utf-8") as fh:
            return parse_params(fh.read())
    finally:
        with contextlib.suppress(FileNotFoundError):
            os.unlink(tmp_path)


def parse_params(text: str) -> ParamOutcome:
    """Parse arjun ``-oJ`` JSON into a :class:`ParamOutcome`. Exposed for testing.

    Args:
        text: Contents of arjun's JSON output file (object keyed by URL, each
            value carrying a ``params`` list). Blank/invalid text yields an
            empty outcome.

    Returns:
        A :class:`ParamOutcome` with query params deduplicated by name in
        first-seen order.
    """
    if not text.strip():
        return ParamOutcome(params=(), missing_binary=False)
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        logger.warning("arjun output was not valid JSON")
        return ParamOutcome(params=(), missing_binary=False)

    if not isinstance(data, dict):
        return ParamOutcome(params=(), missing_binary=False)
    seen: set[str] = set()
    params: list[DiscoveredParam] = []
    for entry in data.values():
        if not isinstance(entry, dict):
            continue
        names = entry.get("params")
        for name in names if isinstance(names, list) else []:
            if not isinstance(name, str) or name in seen:
                continue
            seen.add(name)
            params.append(DiscoveredParam(name=name, location=ParamLocation.QUERY, source=EndpointSource.BRUTE, sample_value=None))
    return ParamOutcome(params=tuple(params), missing_binary=False)
