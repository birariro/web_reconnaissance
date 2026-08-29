"""httpx wrapper: active HTTP probing of a known URL list.

ProjectDiscovery httpx reads a URL list from stdin and emits one JSON object per
line describing each live endpoint (status, title, server, technologies, body
size). This wrapper runs it non-destructively (GET-only) and folds the JSONL
into endpoints plus a deduplicated technology list.

NOTE: this module is named ``httpx`` to match the tool; it must NOT ``import
httpx`` (the unrelated pip HTTP client).
"""

from __future__ import annotations

import json
import logging
from collections.abc import Sequence
from dataclasses import dataclass

from reconnaissance.adapters.execution import DEFAULT_TIMEOUT_SECONDS, run_command
from reconnaissance.models import CertInfo, DiscoveredEndpoint, EndpointSource, HttpMethod, Technology

logger = logging.getLogger(__name__)

BINARY = "httpx"


@dataclass(frozen=True, slots=True)
class ProbeOutcome:
    """Result of an httpx probe run.

    Attributes:
        endpoints: One probed endpoint per JSONL line, tagged with the caller's
            source and carrying status/title/content metadata.
        technologies: Technologies fingerprinted across all lines, deduplicated
            in first-seen order.
        missing_binary: True if the httpx binary was not found.
    """

    endpoints: tuple[DiscoveredEndpoint, ...]
    technologies: tuple[Technology, ...]
    missing_binary: bool


def probe(urls: Sequence[str], *, source: EndpointSource, proxy: str | None = None, rate: int = 50, timeout: float = DEFAULT_TIMEOUT_SECONDS) -> ProbeOutcome:
    """Probe ``urls`` with httpx and parse its JSONL output.

    Args:
        urls: URLs to probe; fed to the child via stdin (httpx reads targets
            from stdin). If empty, the binary is not run.
        source: Discovery origin stamped on every resulting endpoint.
        proxy: Egress proxy URL; all traffic is forced through it when set.
        rate: Requests-per-second cap passed to httpx (``-rl``).
        timeout: Per-run timeout in seconds.

    Returns:
        A :class:`ProbeOutcome`. On a missing binary or non-zero exit, the
        results are empty and the pipeline records the gap.
    """
    if not urls:
        return ProbeOutcome(endpoints=(), technologies=(), missing_binary=False)

    argv = [BINARY, "-json", "-silent", "-sc", "-title", "-server", "-td", "-cl", "-irh", "-tls-grab", "-rl", str(rate)]
    if proxy is not None:
        argv += ["-proxy", proxy]
    result = run_command(argv, timeout=timeout, input_text="\n".join(urls))
    if result.missing_binary:
        return ProbeOutcome(endpoints=(), technologies=(), missing_binary=True)
    if not result.ok:
        logger.warning("httpx failed: exit=%s timed_out=%s", result.exit_code, result.timed_out)
        return ProbeOutcome(endpoints=(), technologies=(), missing_binary=False)

    return parse_probe(result.stdout, source=source)


def parse_probe(text: str, *, source: EndpointSource) -> ProbeOutcome:
    """Parse httpx JSONL into a :class:`ProbeOutcome`. Exposed for testing.

    One JSON object per line. Blank lines and lines that fail JSON decoding are
    skipped (a warning is logged) so a single malformed line does not abort the
    whole parse.

    Args:
        text: httpx stdout in JSONL form.
        source: Discovery origin stamped on every resulting endpoint.

    Returns:
        A :class:`ProbeOutcome` with ``missing_binary`` False.
    """
    endpoints: list[DiscoveredEndpoint] = []
    technologies: dict[str, Technology] = {}
    for line in text.splitlines():
        if not line.strip():
            continue
        try:
            record = json.loads(line)
        except json.JSONDecodeError:
            logger.warning("httpx emitted a non-JSON line; skipping (len=%d)", len(line))
            continue
        if not isinstance(record, dict):
            continue
        url = record.get("url")
        if not isinstance(url, str) or not url:
            continue
        endpoints.append(
            DiscoveredEndpoint(
                url=url,
                method=HttpMethod.GET,
                source=source,
                status=_valid_status(record.get("status_code")),
                content_type=_as_str(record.get("content_type")),
                title=_as_str(record.get("title")),
                content_length=_as_int(record.get("content_length")),
                headers=_headers(record.get("header")),
                cert=_cert(record.get("tls")),
            )
        )
        tech = record.get("tech")
        if isinstance(tech, list):
            for name in tech:
                if isinstance(name, str) and name not in technologies:
                    technologies[name] = Technology(name=name)
    return ProbeOutcome(endpoints=tuple(endpoints), technologies=tuple(technologies.values()), missing_binary=False)


def _headers(value: object) -> tuple[tuple[str, str], ...]:
    if not isinstance(value, dict):
        return ()
    return tuple(sorted((str(k), str(v)) for k, v in value.items()))


def _cert(value: object) -> CertInfo | None:
    if not isinstance(value, dict) or not value:
        return None
    sans = value.get("subject_an")
    issuer_org = value.get("issuer_org")
    issuer = _as_str(value.get("issuer_cn")) or (str(issuer_org[0]) if isinstance(issuer_org, list) and issuer_org else None)
    fingerprints = value.get("fingerprint_hash")
    sha256 = _as_str(fingerprints.get("sha256")) if isinstance(fingerprints, dict) else None
    return CertInfo(
        subject_cn=_as_str(value.get("subject_cn")),
        sans=tuple(s for s in sans if isinstance(s, str)) if isinstance(sans, list) else (),
        issuer=issuer,
        not_before=_as_str(value.get("not_before")),
        not_after=_as_str(value.get("not_after")),
        tls_version=_as_str(value.get("tls_version")),
        sha256=sha256,
    )


def _valid_status(value: object) -> int | None:
    return value if isinstance(value, int) and 100 <= value <= 599 else None


def _as_int(value: object) -> int | None:
    return value if isinstance(value, int) else None


def _as_str(value: object) -> str | None:
    return value if isinstance(value, str) else None
