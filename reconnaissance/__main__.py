"""reconnaissance CLI entrypoint.

Assembles configuration, enforces the authorization gate, runs the pipeline,
and writes a report. No business logic lives here (A8).
"""

from __future__ import annotations

import argparse
import logging
import sys
from pathlib import Path

from reconnaissance.adapters.store import ScanStore
from reconnaissance.models import Budget, ScanConfig, Scope
from reconnaissance.pipeline import run_scan
from reconnaissance.report import render_html, render_json
from reconnaissance.scope import InvalidUrlError, validate_target

logger = logging.getLogger(__name__)

DEFAULT_PASSIVE_SOURCES = ("web.archive.org", "index.commoncrawl.org", "otx.alienvault.com", "urlscan.io")


def _configure_logging(*, verbose: bool) -> None:
    logging.basicConfig(level=logging.DEBUG if verbose else logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="reconnaissance", description="Web application reconnaissance (discovery/identification only).")
    parser.add_argument("url", help="Target base URL, e.g. https://app.example.com")
    parser.add_argument("--scope-host", default=None, help="Scope host (defaults to the URL host).")
    parser.add_argument("--path-prefix", default=None, help="Restrict active scanning to this path prefix.")
    parser.add_argument("--passive-source", action="append", default=None, help="Allowed passive OSINT host (repeatable).")
    parser.add_argument("--wordlist", default=None, help="Wordlist for directory brute force (enables the brute stage).")
    parser.add_argument("--db", default=None, help="SQLite output path (default scans/<host>.sqlite).")
    parser.add_argument("--out", default=None, help="Report output path (default reports/<host>.<format>).")
    parser.add_argument("--format", choices=("json", "html"), default="json", help="Report format.")
    parser.add_argument("--rate", type=float, default=50.0, help="Global requests-per-second ceiling.")
    parser.add_argument("--max-requests", type=int, default=None, help="Global request kill-switch.")
    parser.add_argument("--max-endpoints", type=int, default=None, help="Endpoint budget.")
    parser.add_argument("--reveal-secrets", action="store_true", help="Store discovered secrets unmasked (sensitive).")
    parser.add_argument("--headless", action="store_true", help="Drive katana headless for JS-heavy targets.")
    parser.add_argument("--allow-internal", action="store_true", help="Permit loopback/private targets (e.g. a local test app).")
    parser.add_argument("--agent", action="store_true", help="Enable the optional JS-semantics agent layer (needs anthropic + API key).")
    parser.add_argument("--verbose", action="store_true", help="Debug logging.")
    return parser


def _build_config(args: argparse.Namespace, host: str, normalized_url: str) -> ScanConfig:
    passive = tuple(args.passive_source) if args.passive_source else DEFAULT_PASSIVE_SOURCES
    scope = Scope(target_host=args.scope_host or host, path_prefix=args.path_prefix, passive_sources=frozenset(passive))
    budget_kwargs: dict[str, int] = {}
    if args.max_requests is not None:
        budget_kwargs["max_requests"] = args.max_requests
    if args.max_endpoints is not None:
        budget_kwargs["max_endpoints"] = args.max_endpoints
    budget = Budget(**budget_kwargs)
    return ScanConfig(base_url=normalized_url, scope=scope, budget=budget, reveal_secrets=args.reveal_secrets)


def main(argv: list[str] | None = None) -> int:
    """Parse args, run one scan, write the report. Returns a process exit code."""
    args = _build_parser().parse_args(argv)
    _configure_logging(verbose=args.verbose)

    try:
        normalized_url, host = validate_target(args.url, allow_internal=args.allow_internal)
    except InvalidUrlError as e:
        print(f"error: invalid target URL: {e}", file=sys.stderr)
        return 2

    config = _build_config(args, host, normalized_url)
    scope_host = config.scope.target_host
    db_path = args.db or f"scans/{scope_host}.sqlite"
    out_path = args.out or f"reports/{scope_host}.{args.format}"
    Path(db_path).parent.mkdir(parents=True, exist_ok=True)
    Path(out_path).parent.mkdir(parents=True, exist_ok=True)

    logger.info("starting scan: url=%s scope_host=%s agent=%s", normalized_url, scope_host, args.agent)
    try:
        result = run_scan(config, db_path=db_path, wordlist=args.wordlist, proxy_rate=args.rate, headless=args.headless)
    except RuntimeError as e:
        print(f"error: {e}", file=sys.stderr)
        return 1

    if args.agent:
        _run_agent(config, db_path, result.scan_id)

    store = ScanStore(db_path)
    rendered = render_html(store, result.scan_id) if args.format == "html" else render_json(store, result.scan_id)
    Path(out_path).write_text(rendered, encoding="utf-8")

    partial = result.termination_reason.value in {"budget_exhausted", "killswitch"}
    print(f"scan {result.scan_id}: endpoints={result.endpoint_count} params={result.parameter_count} termination={result.termination_reason.value}")
    if partial:
        print("warning: coverage is PARTIAL — the scan stopped early; some surface may be undiscovered.", file=sys.stderr)
    print(f"report: {out_path}")
    return 0


def _run_agent(config: ScanConfig, db_path: str, scan_id: str) -> None:
    try:
        from reconnaissance import agent
    except ImportError:
        logger.warning("agent layer unavailable: install the 'agent' extra (anthropic)")
        print("warning: --agent requested but the anthropic SDK is not installed; skipping agent layer.", file=sys.stderr)
        return
    agent.enrich(config, db_path=db_path, scan_id=scan_id)


if __name__ == "__main__":
    raise SystemExit(main())
