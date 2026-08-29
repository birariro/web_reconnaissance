"""Optional agent layer: JS-semantic endpoint discovery.

This is pure delta — the deterministic pipeline works without it. The agent
reads JavaScript that regex/sourcemaps could not resolve and proposes endpoints.
It is deliberately constrained:

* fixed, typed tool signatures only — no free-form command, no ``eval``, no
  arbitrary flags;
* every tool re-applies the scope guard, so injected page content cannot steer
  a scan off-target;
* a hard cap on tool calls bounds cost and blast radius.

The LLM turn is injected (``turn_fn``) so the loop is tested without the
anthropic SDK; :func:`enrich` wires the real client.
"""

from __future__ import annotations

import logging
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from urllib.parse import urlsplit

from reconnaissance import scope as scope_mod
from reconnaissance.adapters.store import EndpointInsert, ScanStore
from reconnaissance.models import Classification, DiscoveredEndpoint, EndpointSource, HttpMethod, ScanConfig

logger = logging.getLogger(__name__)

MAX_TOOL_CALLS = 20
_MAX_JS_CHARS = 200_000

TOOL_SCHEMAS: tuple[dict[str, object], ...] = (
    {
        "name": "fetch_js",
        "description": "Fetch the text of an in-scope JavaScript asset to analyze it for endpoints.",
        "input_schema": {"type": "object", "properties": {"url": {"type": "string"}}, "required": ["url"]},
    },
    {
        "name": "record_endpoint",
        "description": "Record a discovered endpoint path (e.g. /api/v2/orders) found in analyzed JavaScript.",
        "input_schema": {"type": "object", "properties": {"path": {"type": "string"}}, "required": ["path"]},
    },
)


@dataclass(frozen=True, slots=True)
class ToolCall:
    """One tool invocation requested by the model."""

    id: str
    name: str
    args: Mapping[str, str]


@dataclass(frozen=True, slots=True)
class ToolResult:
    """The outcome handed back to the model for one tool call."""

    id: str
    content: str


@dataclass(frozen=True, slots=True)
class AgentReply:
    """One model turn: tool calls to run, plus whether it is finished."""

    tool_calls: tuple[ToolCall, ...] = ()
    done: bool = False


TurnFn = Callable[[Sequence[ToolResult]], AgentReply]


@dataclass(slots=True)
class AgentToolbox:
    """Scope-guarded, call-capped implementations of the agent's tools."""

    config: ScanConfig
    store: ScanStore
    scan_id: str
    http_get: Callable[[str], str | None]
    calls: int = 0
    recorded: list[str] = field(default_factory=list)

    def _base(self) -> str:
        return scope_mod.normalize_url(self.config.base_url)

    def fetch_js(self, url: str) -> str:
        """Return in-scope JS text (bounded), or an error string if disallowed."""
        if not scope_mod.is_in_scope(url, self.config.scope, active=True):
            return "ERROR: url out of scope"
        body = self.http_get(url)
        if body is None:
            return "ERROR: fetch failed"
        return body[:_MAX_JS_CHARS]

    def record_endpoint(self, path: str) -> str:
        """Record an agent-proposed endpoint, if it resolves in scope."""
        candidate = self._absolutize(path)
        if candidate is None or not scope_mod.is_in_scope(candidate, self.config.scope, active=True):
            return "REJECTED: out of scope"
        endpoint = DiscoveredEndpoint(url=candidate, method=HttpMethod.GET, source=EndpointSource.AGENT)
        parts = urlsplit(candidate)
        row = EndpointInsert(endpoint=endpoint, path=parts.path or "/", path_pattern=scope_mod.path_pattern(candidate), classification=_classify(candidate), in_scope=True)
        self.store.add_endpoint(self.scan_id, row)
        self.recorded.append(candidate)
        return f"recorded {candidate}"

    def _absolutize(self, path: str) -> str | None:
        return scope_mod.absolutize(self._base(), path)


def _classify(url: str) -> Classification:
    from reconnaissance.pipeline import classify_endpoint

    return classify_endpoint(url, None)


def _dispatch(toolbox: AgentToolbox, call: ToolCall) -> ToolResult:
    handlers: dict[str, Callable[[str], str]] = {"fetch_js": lambda a: toolbox.fetch_js(a), "record_endpoint": lambda a: toolbox.record_endpoint(a)}
    handler = handlers.get(call.name)
    if handler is None:
        return ToolResult(id=call.id, content=f"ERROR: unknown tool {call.name}")
    arg_key = "url" if call.name == "fetch_js" else "path"
    value = call.args.get(arg_key, "")
    return ToolResult(id=call.id, content=handler(value))


def drive(toolbox: AgentToolbox, turn_fn: TurnFn, *, max_calls: int = MAX_TOOL_CALLS) -> list[str]:
    """Run the tool loop until the model finishes or the call cap is hit.

    Returns:
        The list of endpoint URLs the agent recorded.
    """
    results: list[ToolResult] = []
    while toolbox.calls < max_calls:
        reply = turn_fn(results)
        if not reply.tool_calls:
            break
        results = []
        for call in reply.tool_calls:
            if toolbox.calls >= max_calls:
                logger.warning("agent tool-call cap reached: cap=%d", max_calls)
                break
            toolbox.calls += 1
            results.append(_dispatch(toolbox, call))
        if reply.done:
            break
    return list(toolbox.recorded)


def enrich(config: ScanConfig, *, db_path: str, scan_id: str) -> None:
    """Run the agent layer against an existing scan (requires anthropic + key).

    Fetches are scope-guarded and routed through a fresh egress proxy carrying
    the same policy as the pipeline.
    """
    try:
        from reconnaissance.adapters.llm import build_turn_fn
    except ImportError:
        logger.warning("agent enrichment skipped: anthropic SDK not installed")
        return

    from reconnaissance.adapters.egress import EgressProxy, ProxyPolicy

    store = ScanStore(db_path)
    policy = ProxyPolicy(config.scope, rate_per_second=10.0, max_requests=config.budget.max_requests)
    with EgressProxy(policy) as proxy:
        proxy_url = proxy.proxy_url

        def http_get(url: str) -> str | None:
            from reconnaissance.pipeline import _real_http_get

            return _real_http_get(url, proxy_url)

        js_urls = [str(e["url"]) for e in store.list_endpoints(scan_id) if urlsplit(str(e["url"])).path.endswith(".js")]
        toolbox = AgentToolbox(config=config, store=store, scan_id=scan_id, http_get=http_get)
        turn_fn = build_turn_fn(config=config, js_urls=js_urls, tools=TOOL_SCHEMAS)
        recorded = drive(toolbox, turn_fn)
    logger.info("agent enrichment complete: scan_id=%s recorded=%d", scan_id, len(recorded))
