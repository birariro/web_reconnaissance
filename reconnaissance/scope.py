"""URL validation, scope enforcement, and path-pattern normalization.

Pure logic (no I/O): the pipeline validates every target — including URLs
discovered mid-crawl, which are attacker-influenced — through this module
before it is used as an active-scan target. The runtime egress proxy
(:mod:`reconnaissance.adapters.egress`) enforces the same scope for subprocess traffic; this
module is the in-process pre-check.
"""

from __future__ import annotations

import ipaddress
import re
from urllib.parse import urlsplit, urlunsplit

from reconnaissance.models import Scope

ALLOWED_SCHEMES = frozenset({"http", "https"})
DEFAULT_PORTS = {"http": "80", "https": "443"}

_UUID_RE = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")
_LONG_HEX_RE = re.compile(r"^[0-9a-fA-F]{12,}$")
_ALL_DIGITS_RE = re.compile(r"^\d+$")
_HASH_LIKE_RE = re.compile(r"^[0-9a-fA-F]{8,}$")


class InvalidUrlError(ValueError):
    """A URL is malformed or uses a forbidden scheme/userinfo."""


class OutOfScopeError(ValueError):
    """A URL's host is outside the authorized scope."""


def normalize_url(raw: str) -> str:
    """Normalize a URL: lowercase scheme/host, drop fragment and default port.

    Does not validate scope/scheme; call :func:`validate_target` or
    :func:`assert_in_scope` for the trust checks.

    Raises:
        InvalidUrlError: If the URL carries an out-of-range/non-numeric port.
    """
    parts = urlsplit(raw.strip())
    scheme = parts.scheme.lower()
    host = (parts.hostname or "").lower()
    try:
        port = parts.port
    except ValueError as e:
        raise InvalidUrlError(f"invalid port in URL: {raw}") from e
    literal = f"[{host}]" if ":" in host else host  # re-wrap IPv6 literals
    netloc = literal
    if port is not None and str(port) != DEFAULT_PORTS.get(scheme):
        netloc = f"{literal}:{port}"
    path = parts.path or "/"
    return urlunsplit((scheme, netloc, path, parts.query, ""))


def _hostname(raw: str) -> str:
    parts = urlsplit(raw)
    if parts.username is not None or parts.password is not None:
        raise InvalidUrlError(f"URL must not contain userinfo (user:pass@): {raw}")
    if parts.scheme.lower() not in ALLOWED_SCHEMES:
        raise InvalidUrlError(f"URL scheme must be http/https: {raw}")
    host = parts.hostname
    if not host:
        raise InvalidUrlError(f"URL has no host: {raw}")
    return host.lower()


def is_internal_host(host: str) -> bool:
    """True for loopback/private/link-local IPs and localhost-style names."""
    if host in {"localhost", "localhost.localdomain"}:
        return True
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return False
    return ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved


def validate_target(raw: str, *, allow_internal: bool = False) -> tuple[str, str]:
    """Validate a user-supplied scan target.

    Args:
        raw: The target URL.
        allow_internal: Permit loopback/private/link-local hosts (e.g. for
            scanning a local test app). Off by default to block metadata-SSRF
            and accidental internal scans.

    Returns:
        ``(normalized_url, host)``.

    Raises:
        InvalidUrlError: If the scheme is not http/https, userinfo is present,
            there is no host, or the host is internal and ``allow_internal`` is
            False.
    """
    host = _hostname(raw)
    if not allow_internal and is_internal_host(host):
        raise InvalidUrlError(f"refusing internal/loopback target without allow_internal: {host}")
    return normalize_url(raw), host


def assert_in_scope(url: str, scope: Scope, *, active: bool) -> str:
    """Validate and scope-check a URL before it is used as a target.

    Args:
        url: The URL to check (may be attacker-influenced, e.g. from a crawl).
        scope: The authorized scan boundary.
        active: True for active scanning (target host only); False also permits
            allowlisted passive OSINT sources.

    Returns:
        The normalized URL.

    Raises:
        InvalidUrlError: Malformed URL / forbidden scheme / userinfo present.
        OutOfScopeError: Host is neither the target nor an allowed passive source.
    """
    host = _hostname(url)
    if scope.allows_active(host):
        normalized = normalize_url(url)
        if scope.path_prefix and not urlsplit(normalized).path.startswith(scope.path_prefix):
            raise OutOfScopeError(f"path outside prefix: prefix={scope.path_prefix}")
        return normalized
    if not active and scope.allows_passive(host):
        return normalize_url(url)
    raise OutOfScopeError(f"host out of scope: host={host} active={active}")


def is_in_scope(url: str, scope: Scope, *, active: bool) -> bool:
    """Non-raising variant of :func:`assert_in_scope` for filtering."""
    try:
        assert_in_scope(url, scope, active=active)
    except (InvalidUrlError, OutOfScopeError):
        return False
    return True


def _normalize_segment(segment: str) -> str:
    if not segment:
        return segment
    if _ALL_DIGITS_RE.match(segment) or _UUID_RE.match(segment) or _LONG_HEX_RE.match(segment) or _HASH_LIKE_RE.match(segment):
        return "{id}"
    return segment


def path_pattern(url: str) -> str:
    """Collapse variable path segments to ``{id}`` so ``/user/1`` and ``/user/2``
    dedup to one pattern — the key that bounds the convergence loop."""
    parts = urlsplit(url)
    segments = parts.path.split("/")
    normalized = "/".join(_normalize_segment(s) for s in segments)
    return normalized or "/"


def absolutize(base_url: str, ref: str) -> str | None:
    """Resolve a discovered reference (absolute URL or ``/path``) against a base.

    Returns the normalized absolute URL, or None if ``ref`` is a scheme we do
    not follow (``javascript:``, ``data:``, relative fragments) or malformed.
    """
    if ref.startswith(("http://", "https://")):
        try:
            return normalize_url(ref)
        except InvalidUrlError:
            return None
    if ref.startswith("/"):
        parts = urlsplit(base_url)
        try:
            return normalize_url(f"{parts.scheme}://{parts.netloc}{ref}")
        except InvalidUrlError:
            return None
    return None
