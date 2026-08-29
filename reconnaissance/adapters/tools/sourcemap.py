"""Source-map (.js.map) recovery.

A ``.js.map`` reconstructs a bundle's original source, which lists endpoints and
routes far more completely than a regex over the minified bundle. This module
extracts endpoint-like strings from a sourcemap's ``sourcesContent``.

Parsing is pure and testable; the pipeline fetches the map (I/O) through the
egress proxy and passes the text here.
"""

from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass

logger = logging.getLogger(__name__)

# Quoted absolute paths ("/api/v2/users") and full URLs found in original source.
_PATH_RE = re.compile(r"""['"`](/[A-Za-z0-9_\-./{}~:?=&%]+)['"`]""")
_URL_RE = re.compile(r"""https?://[A-Za-z0-9._~:/?#\[\]@!$&'()*+,;=%\-]+""")

# Light secret patterns (kind, regex). Not a substitute for a dedicated scanner.
_SECRET_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("aws_access_key", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("google_api_key", re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b")),
    ("slack_token", re.compile(r"\bxox[baprs]-[0-9A-Za-z-]{10,}\b")),
    ("generic_secret", re.compile(r"""(?i)(?:api[_-]?key|secret|token|password)["']?\s*[:=]\s*["']([A-Za-z0-9_\-]{16,})["']""")),
)


@dataclass(frozen=True, slots=True)
class SourcemapResult:
    """Endpoints and original source filenames recovered from a sourcemap."""

    source_files: tuple[str, ...]
    endpoints: tuple[str, ...]
    parsed: bool


def map_url_for(js_url: str) -> str:
    """Return the conventional sourcemap URL for a JS asset (``<js>.map``)."""
    return f"{js_url}.map"


def _extract(source_text: str) -> set[str]:
    found: set[str] = set()
    for match in _PATH_RE.findall(source_text):
        found.add(match)
    for match in _URL_RE.findall(source_text):
        found.add(match.rstrip("\"'`),;"))
    return found


def extract_references(text: str) -> tuple[str, ...]:
    """Extract endpoint-like path/URL strings from raw JavaScript.

    Same path/URL matching used on sourcemap sources, applied to a minified or
    plain ``.js`` body. Catches literals like ``"/search?q="`` and
    ``fetch('/api/v2/users')`` — the query string is preserved so the caller can
    harvest parameter names.
    """
    return tuple(sorted(_extract(text)))


def parse_sourcemap(text: str) -> SourcemapResult:
    """Parse a ``.js.map`` and extract endpoint-like strings from its sources.

    Returns:
        A :class:`SourcemapResult`. On blank/invalid input ``parsed`` is False
        and the tuples are empty.
    """
    stripped = text.strip()
    if not stripped:
        return SourcemapResult(source_files=(), endpoints=(), parsed=False)
    try:
        doc: object = json.loads(stripped)
    except json.JSONDecodeError:
        logger.warning("sourcemap parse failed: not valid json")
        return SourcemapResult(source_files=(), endpoints=(), parsed=False)
    if not isinstance(doc, dict):
        return SourcemapResult(source_files=(), endpoints=(), parsed=False)

    raw_sources = doc.get("sources")
    source_files = tuple(s for s in raw_sources if isinstance(s, str)) if isinstance(raw_sources, list) else ()

    contents = doc.get("sourcesContent")
    endpoints: set[str] = set()
    if isinstance(contents, list):
        for content in contents:
            if isinstance(content, str):
                endpoints |= _extract(content)
    return SourcemapResult(source_files=source_files, endpoints=tuple(sorted(endpoints)), parsed=True)


def find_secrets(text: str) -> tuple[tuple[str, str], ...]:
    """Scan text for likely secrets, returning ``(kind, raw_value)`` pairs.

    Best-effort only — obvious high-signal keys, not a full secret scanner. The
    caller masks the raw value before storage.
    """
    found: list[tuple[str, str]] = []
    seen: set[str] = set()
    for kind, pattern in _SECRET_PATTERNS:
        for match in pattern.finditer(text):
            raw = match.group(1) if match.groups() else match.group(0)
            if raw and raw not in seen:
                seen.add(raw)
                found.append((kind, raw))
    return tuple(found)
