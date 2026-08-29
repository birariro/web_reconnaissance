"""Domain models for web-app reconnaissance.

This module is the dependency leaf: it imports nothing from ``reconnaissance`` and is
imported by every other module. All types are frozen dataclasses (immutable
inventory currency) or ``StrEnum`` constant groups.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from enum import StrEnum

# --- constants (O4: no magic numbers) ---------------------------------------

SECRET_VISIBLE_CHARS = 4
MIN_STATUS_CODE = 100
MAX_STATUS_CODE = 599


class HttpMethod(StrEnum):
    """HTTP methods a discovered endpoint may carry.

    GET/HEAD/OPTIONS are safe (non-destructive) and always probed. The
    state-changing verbs are recorded from specs/crawls for inventory, and only
    sent when the operator opts in via ``ScanConfig.send_destructive``.
    """

    GET = "GET"
    HEAD = "HEAD"
    OPTIONS = "OPTIONS"
    POST = "POST"
    PUT = "PUT"
    DELETE = "DELETE"
    PATCH = "PATCH"


SAFE_METHODS = frozenset({HttpMethod.GET, HttpMethod.HEAD, HttpMethod.OPTIONS})


class EndpointSource(StrEnum):
    """Where an endpoint was first discovered."""

    SEED = "seed"
    ROBOTS = "robots"
    SITEMAP = "sitemap"
    GAU = "gau"
    CRAWL = "crawl"
    JS = "js"
    BRUTE = "brute"
    SPEC = "spec"
    AGENT = "agent"


class ParamLocation(StrEnum):
    """Where a parameter is carried."""

    QUERY = "query"
    BODY = "body"
    PATH = "path"
    HEADER = "header"


class Classification(StrEnum):
    """Coarse endpoint classification for triage."""

    STATIC = "static"
    DYNAMIC = "dynamic"
    API = "api"
    AUTH = "auth"
    ADMIN = "admin"
    UNKNOWN = "unknown"


class TerminationReason(StrEnum):
    """Why the convergence loop stopped — surfaced so a truncated scan is not
    mistaken for a complete one."""

    CONVERGED = "converged"
    BUDGET_EXHAUSTED = "budget_exhausted"
    KILLSWITCH = "killswitch"


class ToolName(StrEnum):
    """Recon tool binaries the pipeline shells out to."""

    HTTPX = "httpx"
    KATANA = "katana"
    FFUF = "ffuf"
    ARJUN = "arjun"
    GAU = "gau"


def _mask_secret(raw: str) -> str:
    """Return a non-recoverable preview of a secret, e.g. ``AKIA…××××``."""
    if len(raw) <= SECRET_VISIBLE_CHARS:
        return "×" * len(raw)
    return f"{raw[:SECRET_VISIBLE_CHARS]}…××××"


def fingerprint(raw: str) -> str:
    """Stable SHA-256 fingerprint used to dedup secrets and JS assets."""
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


@dataclass(frozen=True, slots=True)
class CertInfo:
    """TLS certificate details for identification only.

    SANs are recorded, never used to seed new hosts (that would be asset
    expansion, which is out of scope and blocked by the scope guard).
    """

    subject_cn: str | None = None
    sans: tuple[str, ...] = ()
    issuer: str | None = None
    not_before: str | None = None
    not_after: str | None = None
    tls_version: str | None = None
    sha256: str | None = None


@dataclass(frozen=True, slots=True)
class DiscoveredEndpoint:
    """A single discovered request surface.

    Attributes:
        url: Absolute URL as discovered.
        method: HTTP method (safe verbs are probed; state-changing verbs are
            recorded and only sent under ``send_destructive``).
        source: Discovery origin.
        status: HTTP status if the endpoint was probed, else None.
        content_type: Response content-type if probed, else None.
        title: Page title if probed and HTML, else None.
        content_length: Response body length if probed, else None (feeds
            soft-404 detection).
        headers: Response headers as ``(name, value)`` pairs if probed, else
            empty (Server, X-Powered-By, security headers, …).
    """

    url: str
    method: HttpMethod
    source: EndpointSource
    status: int | None = None
    content_type: str | None = None
    title: str | None = None
    content_length: int | None = None
    headers: tuple[tuple[str, str], ...] = ()
    cert: CertInfo | None = None

    def __post_init__(self) -> None:
        if not self.url.strip():
            raise ValueError("DiscoveredEndpoint.url must be non-empty")
        if self.status is not None and not (MIN_STATUS_CODE <= self.status <= MAX_STATUS_CODE):
            raise ValueError(f"DiscoveredEndpoint.status out of range: {self.status}")


@dataclass(frozen=True, slots=True)
class DiscoveredParam:
    """A parameter observed on or associated with an endpoint."""

    name: str
    location: ParamLocation
    source: EndpointSource
    sample_value: str | None = None

    def __post_init__(self) -> None:
        if not self.name.strip():
            raise ValueError("DiscoveredParam.name must be non-empty")


@dataclass(frozen=True, slots=True)
class Technology:
    """A fingerprinted technology on the target."""

    name: str
    version: str | None = None
    category: str | None = None

    def __post_init__(self) -> None:
        if not self.name.strip():
            raise ValueError("Technology.name must be non-empty")


@dataclass(frozen=True, slots=True)
class Secret:
    """A secret discovered in JS/content.

    The raw value is only retained in ``preview`` when the operator passed
    ``reveal=True`` (``--reveal-secrets``); otherwise ``preview`` is masked.
    ``digest`` is always a fingerprint of the raw value, never the value.
    """

    kind: str
    preview: str
    digest: str
    source_url: str

    @classmethod
    def from_raw(cls, kind: str, raw: str, source_url: str, *, reveal: bool = False) -> Secret:
        """Build a Secret, masking the raw value unless ``reveal`` is set."""
        if not raw:
            raise ValueError("Secret raw value must be non-empty")
        return cls(kind=kind, preview=raw if reveal else _mask_secret(raw), digest=fingerprint(raw), source_url=source_url)


@dataclass(frozen=True, slots=True)
class Scope:
    """Authorized scan boundary.

    Active tools may only touch ``target_host`` (optionally under
    ``path_prefix``). Passive tools (gau) may only reach hosts in
    ``passive_sources`` — never the target directly.
    """

    target_host: str
    path_prefix: str | None = None
    passive_sources: frozenset[str] = field(default_factory=frozenset)

    def __post_init__(self) -> None:
        if not self.target_host.strip():
            raise ValueError("Scope.target_host must be non-empty")

    def allows_active(self, host: str) -> bool:
        """True if ``host`` is the authorized target (active scanning allowed)."""
        return host.lower() == self.target_host.lower()

    def allows_passive(self, host: str) -> bool:
        """True if ``host`` is an allowed passive OSINT source."""
        return host.lower() in self.passive_sources


@dataclass(frozen=True, slots=True)
class Budget:
    """Hard bounds that guarantee the convergence loop terminates."""

    max_endpoints: int = 5000
    max_requests: int = 20000
    max_seconds: float = 1800.0
    max_passes: int = 3
    per_pattern_cap: int = 3

    def __post_init__(self) -> None:
        if self.max_passes < 1:
            raise ValueError(f"Budget.max_passes must be >= 1: {self.max_passes}")
        if self.per_pattern_cap < 1:
            raise ValueError(f"Budget.per_pattern_cap must be >= 1: {self.per_pattern_cap}")


@dataclass(frozen=True, slots=True)
class ScanConfig:
    """Everything needed to run one scan."""

    base_url: str
    scope: Scope
    budget: Budget = field(default_factory=Budget)
    reveal_secrets: bool = False
    send_destructive: bool = False

    def __post_init__(self) -> None:
        if not self.base_url.strip():
            raise ValueError("ScanConfig.base_url must be non-empty")
