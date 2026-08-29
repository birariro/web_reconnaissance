"""SQLite persistence for the recon inventory.

Three tables — ``scan``, ``endpoint``, ``parameter`` — plus a small
``error_log``. Many-valued but rarely-joined fields (sources, tech, api,
forms, secrets) live as JSON columns. All SQL is parameterized; connections
are opened per operation via ``with`` (A6). The clock and id generator are
injected (O8) so scans are reproducible in tests.
"""

from __future__ import annotations

import json
import logging
import sqlite3
import uuid
from collections.abc import Callable, Sequence
from contextlib import closing
from dataclasses import asdict, dataclass
from datetime import UTC, datetime

from reconnaissance.models import Classification, DiscoveredEndpoint, DiscoveredParam, ScanConfig, TerminationReason

logger = logging.getLogger(__name__)

_SCHEMA = """
CREATE TABLE IF NOT EXISTS scan (
    id TEXT PRIMARY KEY,
    base_url TEXT NOT NULL,
    scope_json TEXT NOT NULL,
    tech_json TEXT NOT NULL DEFAULT '[]',
    api_json TEXT NOT NULL DEFAULT '[]',
    started_at TEXT NOT NULL,
    finished_at TEXT,
    termination_reason TEXT
);
CREATE TABLE IF NOT EXISTS endpoint (
    id TEXT PRIMARY KEY,
    scan_id TEXT NOT NULL REFERENCES scan(id),
    url TEXT NOT NULL,
    path TEXT NOT NULL,
    path_pattern TEXT NOT NULL,
    method TEXT NOT NULL,
    sources_json TEXT NOT NULL,
    status INTEGER,
    response_sig TEXT,
    content_type TEXT,
    content_length INTEGER,
    title TEXT,
    classification TEXT NOT NULL,
    in_scope INTEGER NOT NULL,
    secrets_json TEXT NOT NULL DEFAULT '[]',
    headers_json TEXT NOT NULL DEFAULT '{}',
    tls_json TEXT NOT NULL DEFAULT '{}',
    first_seen TEXT NOT NULL,
    UNIQUE(scan_id, method, url)
);
CREATE TABLE IF NOT EXISTS parameter (
    id TEXT PRIMARY KEY,
    endpoint_id TEXT NOT NULL REFERENCES endpoint(id),
    name TEXT NOT NULL,
    location TEXT NOT NULL,
    source TEXT NOT NULL,
    sample_value TEXT,
    UNIQUE(endpoint_id, name, location)
);
CREATE TABLE IF NOT EXISTS error_log (
    id TEXT PRIMARY KEY,
    scan_id TEXT NOT NULL REFERENCES scan(id),
    stage TEXT NOT NULL,
    detail TEXT NOT NULL,
    at TEXT NOT NULL
);
"""


class StoreError(RuntimeError):
    """A persistence operation failed."""


@dataclass(frozen=True, slots=True)
class EndpointInsert:
    """Endpoint row ready for persistence (discovery object + derived fields)."""

    endpoint: DiscoveredEndpoint
    path: str
    path_pattern: str
    classification: Classification
    in_scope: bool
    response_sig: str | None = None


def _cert_json(endpoint: DiscoveredEndpoint) -> str | None:
    """Serialize an endpoint's TLS cert to JSON, or None if it has none."""
    return json.dumps(asdict(endpoint.cert)) if endpoint.cert is not None else None


def _utc_now() -> datetime:
    return datetime.now(UTC)


def _new_uuid() -> str:
    return str(uuid.uuid4())


class ScanStore:
    """Reads and writes the recon inventory to a SQLite database."""

    def __init__(self, db_path: str, *, now: Callable[[], datetime] = _utc_now, new_id: Callable[[], str] = _new_uuid) -> None:
        self._db_path = db_path
        self._now = now
        self._new_id = new_id

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self._db_path)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        return conn

    def initialize(self) -> None:
        """Create tables if they do not exist."""
        with closing(self._connect()) as conn, conn:
            conn.executescript(_SCHEMA)

    def create_scan(self, config: ScanConfig) -> str:
        """Insert a scan row and return its id."""
        scan_id = self._new_id()
        scope_json = json.dumps({"target_host": config.scope.target_host, "path_prefix": config.scope.path_prefix, "passive_sources": sorted(config.scope.passive_sources)})
        with closing(self._connect()) as conn, conn:
            conn.execute(
                "INSERT INTO scan (id, base_url, scope_json, started_at) VALUES (?, ?, ?, ?)",
                (scan_id, config.base_url, scope_json, self._now().isoformat()),
            )
        return scan_id

    def add_endpoint(self, scan_id: str, row: EndpointInsert) -> tuple[str, bool]:
        """Insert or merge an endpoint.

        Returns:
            ``(endpoint_id, is_new)``. On a repeat (same scan/method/url) the
            existing row's sources are merged and any newly-probed fields
            (status/title/…) are filled; ``is_new`` is False.
        """
        ep = row.endpoint
        try:
            with closing(self._connect()) as conn, conn:
                existing: sqlite3.Row | None = conn.execute(
                    "SELECT id, sources_json FROM endpoint WHERE scan_id = ? AND method = ? AND url = ?",
                    (scan_id, str(ep.method), ep.url),
                ).fetchone()
                if existing is None:
                    endpoint_id = self._new_id()
                    conn.execute(
                        "INSERT INTO endpoint"
                        " (id, scan_id, url, path, path_pattern, method, sources_json, status, response_sig,"
                        " content_type, content_length, title, classification, in_scope, headers_json, tls_json, first_seen)"
                        " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                        (
                            endpoint_id, scan_id, ep.url, row.path, row.path_pattern, str(ep.method), json.dumps([str(ep.source)]),
                            ep.status, row.response_sig, ep.content_type, ep.content_length, ep.title, str(row.classification),
                            int(row.in_scope), json.dumps(dict(ep.headers)), _cert_json(ep) or "{}", self._now().isoformat(),
                        ),
                    )
                    return endpoint_id, True
                endpoint_id = str(existing["id"])
                sources: list[str] = json.loads(existing["sources_json"])
                if str(ep.source) not in sources:
                    sources.append(str(ep.source))
                headers_json = json.dumps(dict(ep.headers)) if ep.headers else None
                conn.execute(
                    "UPDATE endpoint SET sources_json = ?,"
                    " status = COALESCE(?, status), content_type = COALESCE(?, content_type),"
                    " content_length = COALESCE(?, content_length), title = COALESCE(?, title),"
                    " response_sig = COALESCE(?, response_sig), headers_json = COALESCE(?, headers_json),"
                    " tls_json = COALESCE(?, tls_json)"
                    " WHERE id = ?",
                    (json.dumps(sources), ep.status, ep.content_type, ep.content_length, ep.title, row.response_sig, headers_json, _cert_json(ep), endpoint_id),
                )
                return endpoint_id, False
        except sqlite3.Error as e:
            raise StoreError(f"add_endpoint failed: url={ep.url}") from e

    def add_parameter(self, endpoint_id: str, param: DiscoveredParam) -> None:
        """Insert a parameter, ignoring exact duplicates on the same endpoint."""
        try:
            with closing(self._connect()) as conn, conn:
                conn.execute(
                    "INSERT OR IGNORE INTO parameter (id, endpoint_id, name, location, source, sample_value) VALUES (?, ?, ?, ?, ?, ?)",
                    (self._new_id(), endpoint_id, param.name, str(param.location), str(param.source), param.sample_value),
                )
        except sqlite3.Error as e:
            raise StoreError(f"add_parameter failed: name={param.name}") from e

    def add_secret(self, endpoint_id: str, secret: dict[str, str]) -> None:
        """Append a (masked) secret to an endpoint, deduped by its digest."""
        try:
            with closing(self._connect()) as conn, conn:
                existing: sqlite3.Row | None = conn.execute("SELECT secrets_json FROM endpoint WHERE id = ?", (endpoint_id,)).fetchone()
                if existing is None:
                    return
                secrets: list[dict[str, str]] = json.loads(existing["secrets_json"])
                if any(s.get("digest") == secret.get("digest") for s in secrets):
                    return
                secrets.append(secret)
                conn.execute("UPDATE endpoint SET secrets_json = ? WHERE id = ?", (json.dumps(secrets), endpoint_id))
        except sqlite3.Error as e:
            raise StoreError(f"add_secret failed: endpoint_id={endpoint_id}") from e

    def log_error(self, scan_id: str, stage: str, detail: str) -> None:
        """Record a tool failure / gap so partial coverage is auditable."""
        with closing(self._connect()) as conn, conn:
            conn.execute(
                "INSERT INTO error_log (id, scan_id, stage, detail, at) VALUES (?, ?, ?, ?, ?)",
                (self._new_id(), scan_id, stage, detail, self._now().isoformat()),
            )

    def finish_scan(self, scan_id: str, *, reason: TerminationReason, technologies: Sequence[dict[str, str | None]], api_surfaces: Sequence[dict[str, object]]) -> None:
        """Stamp the terminal state: finish time, termination reason, tech, api."""
        with closing(self._connect()) as conn, conn:
            conn.execute(
                "UPDATE scan SET finished_at = ?, termination_reason = ?, tech_json = ?, api_json = ? WHERE id = ?",
                (self._now().isoformat(), str(reason), json.dumps(list(technologies)), json.dumps(list(api_surfaces)), scan_id),
            )

    def get_scan(self, scan_id: str) -> dict[str, object]:
        """Return the scan row as a dict, or raise if it does not exist."""
        with closing(self._connect()) as conn:
            found: sqlite3.Row | None = conn.execute("SELECT * FROM scan WHERE id = ?", (scan_id,)).fetchone()
        if found is None:
            raise KeyError(f"scan not found: {scan_id}")
        return dict(found)

    def list_endpoints(self, scan_id: str) -> list[dict[str, object]]:
        """Return all endpoints for a scan, ordered by path."""
        with closing(self._connect()) as conn:
            rows: list[sqlite3.Row] = conn.execute("SELECT * FROM endpoint WHERE scan_id = ? ORDER BY path", (scan_id,)).fetchall()
        return [dict(r) for r in rows]

    def list_parameters(self, scan_id: str) -> list[dict[str, object]]:
        """Return all parameters for a scan, joined to their endpoint URL."""
        with closing(self._connect()) as conn:
            rows: list[sqlite3.Row] = conn.execute(
                "SELECT p.*, e.url AS endpoint_url FROM parameter p JOIN endpoint e ON e.id = p.endpoint_id WHERE e.scan_id = ? ORDER BY p.name",
                (scan_id,),
            ).fetchall()
        return [dict(r) for r in rows]
