"""Local egress proxy — the single point where recon traffic is controlled.

Independent subprocesses cannot share an in-process rate limiter, so every tool
is pointed at this proxy (``--proxy``/``-x``/env). The proxy enforces, across
all tools at once:

1. host scope — active target only, plus an allowlisted set of passive OSINT
   hosts; everything else is refused (this also stops SSRF from reaching
   off-scope hosts),
2. a bounded number of concurrent connections (semaphore),
3. a rate limit and request kill-switch.

Honest limits: the rate limiter and kill-switch count **one unit per
connection**. For a cleartext HTTP request that is one request, but inside a
CONNECT/TLS tunnel many requests flow through a single counted connection and
their individual methods are invisible. So over HTTPS the true per-request rate
limit is the one each tool applies to itself (its ``-rl``/``-rate`` flag, which
the pipeline sets); the proxy's job over TLS is scope + concurrency + a
connection kill-switch. Method-level GET-only enforcement therefore applies to
cleartext HTTP here and is enforced by tool configuration for TLS.

The pure :class:`ProxyPolicy` is unit-tested; the socket server is
integration-tested.
"""

from __future__ import annotations

import logging
import select
import socket
import threading
import time
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit

from reconnaissance.models import Scope

logger = logging.getLogger(__name__)

ALLOWED_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})
DEFAULT_MAX_CONCURRENCY = 8
_TUNNEL_CHUNK = 65536
_TUNNEL_IDLE_TIMEOUT = 30.0
_UPSTREAM_CONNECT_TIMEOUT = 10.0


@dataclass(frozen=True, slots=True)
class Decision:
    """Whether a request may proceed, and why not."""

    allowed: bool
    reason: str


class RateLimiter:
    """Thread-safe token bucket bounding global requests-per-second."""

    def __init__(self, rate_per_second: float, *, clock: Callable[[], float] = time.monotonic) -> None:
        if rate_per_second <= 0:
            raise ValueError(f"rate_per_second must be > 0: {rate_per_second}")
        self._rate = rate_per_second
        self._capacity = rate_per_second
        self._tokens = rate_per_second
        self._clock = clock
        self._last = clock()
        self._lock = threading.Lock()

    def try_acquire(self) -> bool:
        """Consume one token if available; return False if the bucket is empty."""
        with self._lock:
            now = self._clock()
            self._tokens = min(self._capacity, self._tokens + (now - self._last) * self._rate)
            self._last = now
            if self._tokens < 1.0:
                return False
            self._tokens -= 1.0
            return True


class ProxyPolicy:
    """Pure allow/deny decision: host scope + rate + global kill-switch."""

    def __init__(
        self,
        scope: Scope,
        *,
        rate_per_second: float,
        max_requests: int,
        max_concurrency: int = DEFAULT_MAX_CONCURRENCY,
        allow_destructive: bool = False,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._scope = scope
        self._limiter = RateLimiter(rate_per_second, clock=clock)
        self._max_requests = max_requests
        self._allow_destructive = allow_destructive
        self._count = 0
        self._lock = threading.Lock()
        self._slots = threading.BoundedSemaphore(max_concurrency)

    def method_allowed(self, method: str) -> bool:
        """Whether ``method`` may leave the proxy (state-changing verbs need opt-in)."""
        return method in ALLOWED_METHODS or self._allow_destructive

    @property
    def request_count(self) -> int:
        """Total connections admitted so far."""
        return self._count

    @contextmanager
    def slot(self) -> Iterator[None]:
        """Bound concurrent connections; blocks until a slot frees."""
        self._slots.acquire()
        try:
            yield
        finally:
            self._slots.release()

    def check(self, host: str) -> Decision:
        """Decide whether a request to ``host`` may proceed."""
        if not host:
            return Decision(allowed=False, reason="missing host")
        if not (self._scope.allows_active(host) or self._scope.allows_passive(host)):
            return Decision(allowed=False, reason=f"out of scope: {host}")
        with self._lock:
            if self._count >= self._max_requests:
                return Decision(allowed=False, reason="request kill-switch tripped")
            if not self._limiter.try_acquire():
                return Decision(allowed=False, reason="rate limit exceeded")
            self._count += 1
        return Decision(allowed=True, reason="ok")


def _host_of(authority: str) -> str:
    # authority may be "host:port" (CONNECT) or empty
    if not authority:
        return ""
    if authority.startswith("["):  # IPv6 literal
        return authority[1 : authority.index("]")].lower() if "]" in authority else authority.lower()
    return authority.rsplit(":", 1)[0].lower() if ":" in authority else authority.lower()


class _Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    @property
    def _policy(self) -> ProxyPolicy:
        policy: ProxyPolicy = self.server.policy  # type: ignore[attr-defined]
        return policy

    def log_message(self, format: str, *args: object) -> None:  # noqa: A002 - stdlib signature
        logger.debug("proxy: %s", format % args)

    def _deny(self, reason: str) -> None:
        logger.warning("proxy denied: reason=%s", reason)
        self.send_error(403, "Forbidden by egress policy")

    def do_CONNECT(self) -> None:  # noqa: N802 - stdlib handler name
        host = _host_of(self.path)
        decision = self._policy.check(host)
        if not decision.allowed:
            self._deny(decision.reason)
            return
        port_part = self.path.rsplit(":", 1)
        port = int(port_part[1]) if len(port_part) == 2 and port_part[1].isdigit() else 443
        with self._policy.slot():
            try:
                upstream = socket.create_connection((host, port), timeout=_UPSTREAM_CONNECT_TIMEOUT)
            except OSError as e:
                logger.warning("proxy upstream connect failed: host=%s err=%s", host, e)
                self.send_error(502, "Bad Gateway")
                return
            self.send_response(200, "Connection Established")
            self.end_headers()
            self._tunnel(self.connection, upstream)

    def _forward_simple(self) -> None:
        parts = urlsplit(self.path)
        host = (parts.hostname or "").lower()
        decision = self._policy.check(host)
        if not decision.allowed:
            self._deny(decision.reason)
            return
        if not self._policy.method_allowed(self.command):
            self._deny(f"method not allowed: {self.command}")
            return
        port = parts.port or 80
        path = parts.path or "/"
        if parts.query:
            path = f"{path}?{parts.query}"
        length = int(self.headers.get("Content-Length", "0") or "0")
        body = self.rfile.read(length) if length > 0 else b""
        head = f"{self.command} {path} HTTP/1.0\r\nHost: {host}\r\nConnection: close\r\n"
        if body:
            head += f"Content-Length: {len(body)}\r\n"
            content_type = self.headers.get("Content-Type")
            if content_type:
                head += f"Content-Type: {content_type}\r\n"
        head += "\r\n"
        with self._policy.slot():
            try:
                upstream = socket.create_connection((host, port), timeout=_UPSTREAM_CONNECT_TIMEOUT)
            except OSError as e:
                logger.warning("proxy upstream connect failed: host=%s err=%s", host, e)
                self.send_error(502, "Bad Gateway")
                return
            with upstream:
                upstream.sendall(head.encode("latin-1") + body)
                while True:
                    chunk = upstream.recv(_TUNNEL_CHUNK)
                    if not chunk:
                        break
                    self.connection.sendall(chunk)

    def do_GET(self) -> None:  # noqa: N802 - stdlib handler name
        self._forward_simple()

    def do_HEAD(self) -> None:  # noqa: N802 - stdlib handler name
        self._forward_simple()

    def do_OPTIONS(self) -> None:  # noqa: N802 - stdlib handler name
        self._forward_simple()

    def do_POST(self) -> None:  # noqa: N802 - stdlib handler name
        self._forward_simple()

    def do_PUT(self) -> None:  # noqa: N802 - stdlib handler name
        self._forward_simple()

    def do_DELETE(self) -> None:  # noqa: N802 - stdlib handler name
        self._forward_simple()

    def do_PATCH(self) -> None:  # noqa: N802 - stdlib handler name
        self._forward_simple()

    def _tunnel(self, client: socket.socket, upstream: socket.socket) -> None:
        with upstream:
            sockets = [client, upstream]
            while True:
                readable, _, exceptional = select.select(sockets, [], sockets, _TUNNEL_IDLE_TIMEOUT)
                if exceptional or not readable:
                    break
                for src in readable:
                    dst = upstream if src is client else client
                    try:
                        data = src.recv(_TUNNEL_CHUNK)
                    except OSError:
                        return
                    if not data:
                        return
                    dst.sendall(data)


class EgressProxy:
    """Threaded forward proxy fronting all recon-tool traffic.

    Use as a context manager: the proxy starts on entry and shuts down on exit.
    Point tools at :attr:`proxy_url`.
    """

    def __init__(self, policy: ProxyPolicy, *, host: str = "127.0.0.1", port: int = 0) -> None:
        self._server = ThreadingHTTPServer((host, port), _Handler)
        self._server.policy = policy  # type: ignore[attr-defined]
        self._server.daemon_threads = True
        self._thread: threading.Thread | None = None

    @property
    def port(self) -> int:
        """The bound TCP port."""
        return int(self._server.server_address[1])

    @property
    def proxy_url(self) -> str:
        """``http://host:port`` to hand to tools."""
        address = self._server.server_address
        raw_host = address[0]
        host = raw_host.decode() if isinstance(raw_host, bytes) else raw_host
        return f"http://{host}:{address[1]}"

    def url_for(self, host: str) -> str:
        """Proxy URL reachable from ``host`` (e.g. ``host.docker.internal``)."""
        return f"http://{host}:{self.port}"

    def start(self) -> None:
        """Begin serving in a background daemon thread."""
        thread = threading.Thread(target=self._server.serve_forever, name="egress-proxy", daemon=True)
        thread.start()
        self._thread = thread

    def stop(self) -> None:
        """Stop serving and release the socket."""
        self._server.shutdown()
        self._server.server_close()
        if self._thread is not None:
            self._thread.join(timeout=5.0)

    def __enter__(self) -> EgressProxy:
        self.start()
        return self

    def __exit__(self, *exc: object) -> None:
        self.stop()
