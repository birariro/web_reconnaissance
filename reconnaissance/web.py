"""A minimal local web UI for running scans and viewing results.

Stdlib only (``http.server``). Bind to localhost. One scan runs at a time (a
lock), which also keeps the shared tools container from colliding. Every value
shown in a page is HTML-escaped — scanned data (URLs, titles) is attacker-
influenced.

Run: ``reconnaissance-web`` (or ``python -m reconnaissance.web``), then open the printed URL.
"""

from __future__ import annotations

import html
import logging
import threading
import uuid
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

from reconnaissance.adapters.store import ScanStore
from reconnaissance.models import Budget, ScanConfig, Scope
from reconnaissance.pipeline import run_scan
from reconnaissance.report import render_html, render_json
from reconnaissance.scope import InvalidUrlError, validate_target

logger = logging.getLogger(__name__)

DEFAULT_PASSIVE_SOURCES = ("web.archive.org", "index.commoncrawl.org", "otx.alienvault.com", "urlscan.io")
_SCAN_DIR = Path("scans/ui")
_REPORT_DIR = Path("reports")


@dataclass(slots=True)
class _Job:
    id: str
    target: str
    status: str = "running"  # running | done | error
    scan_id: str | None = None
    db_path: str | None = None
    report_path: str | None = None
    detail: str = ""


@dataclass(slots=True)
class _State:
    jobs: dict[str, _Job] = field(default_factory=dict)
    order: list[str] = field(default_factory=list)
    lock: threading.Lock = field(default_factory=threading.Lock)
    run_lock: threading.Lock = field(default_factory=threading.Lock)


_STATE = _State()


@dataclass(frozen=True, slots=True)
class _Options:
    """Scan options mirrored from the CLI, parsed from the web form."""

    wordlist: str | None = None
    allow_internal: bool = False
    scope_host: str | None = None
    rate: float = 50.0
    max_requests: int | None = None
    max_endpoints: int | None = None
    reveal_secrets: bool = False
    headless: bool = False
    agent: bool = False


def _parse_options(form: dict[str, list[str]]) -> _Options:
    return _Options(
        wordlist=_text(form, "wordlist"),
        allow_internal=_flag(form, "allow_internal"),
        scope_host=_text(form, "scope_host"),
        rate=_number(form, "rate", 50.0),
        max_requests=_int(form, "max_requests"),
        max_endpoints=_int(form, "max_endpoints"),
        reveal_secrets=_flag(form, "reveal_secrets"),
        headless=_flag(form, "headless"),
        agent=_flag(form, "agent"),
    )


def _text(form: dict[str, list[str]], key: str) -> str | None:
    return form.get(key, [""])[0].strip() or None


def _flag(form: dict[str, list[str]], key: str) -> bool:
    return bool(form.get(key))


def _number(form: dict[str, list[str]], key: str, default: float) -> float:
    try:
        return float(form.get(key, [""])[0]) or default
    except ValueError:
        return default


def _int(form: dict[str, list[str]], key: str) -> int | None:
    raw = form.get(key, [""])[0].strip()
    if not raw:
        return None
    try:
        return int(raw)
    except ValueError:
        return None


def _run_job(job: _Job, opts: _Options) -> None:
    try:
        normalized, host = validate_target(job.target, allow_internal=opts.allow_internal)
        scope = Scope(target_host=opts.scope_host or host, passive_sources=frozenset(DEFAULT_PASSIVE_SOURCES))
        budget_kwargs: dict[str, int] = {}
        if opts.max_requests is not None:
            budget_kwargs["max_requests"] = opts.max_requests
        if opts.max_endpoints is not None:
            budget_kwargs["max_endpoints"] = opts.max_endpoints
        config = ScanConfig(base_url=normalized, scope=scope, budget=Budget(**budget_kwargs), reveal_secrets=opts.reveal_secrets)
        db_path = str(_SCAN_DIR / f"{job.id}.sqlite")
        Path(db_path).parent.mkdir(parents=True, exist_ok=True)
        with _STATE.run_lock:
            result = run_scan(config, db_path=db_path, wordlist=opts.wordlist, proxy_rate=opts.rate, headless=opts.headless)
            if opts.agent:
                _enrich(config, db_path, result.scan_id)
        report_path = _write_reports(db_path, result.scan_id, scope.target_host, job.id)
        job.scan_id, job.db_path, job.report_path, job.status = result.scan_id, db_path, report_path, "done"
        job.detail = f"endpoints={result.endpoint_count} params={result.parameter_count} termination={result.termination_reason.value} · report={report_path}"
    except (InvalidUrlError, ValueError, RuntimeError, OSError) as e:
        job.status, job.detail = "error", f"{type(e).__name__}: {e}"
        logger.warning("scan job failed: id=%s err=%s", job.id, e)


def _enrich(config: ScanConfig, db_path: str, scan_id: str) -> None:
    """Run the optional agent layer; a failure here must not fail the scan."""
    try:
        from reconnaissance import agent

        agent.enrich(config, db_path=db_path, scan_id=scan_id)
    except (ImportError, RuntimeError, OSError, ValueError) as e:
        logger.warning("agent enrichment skipped: %s", e)


def _write_reports(db_path: str, scan_id: str, host: str, job_id: str) -> str:
    """Persist HTML + JSON reports under the project ``reports/`` directory."""
    _REPORT_DIR.mkdir(parents=True, exist_ok=True)
    store = ScanStore(db_path)
    stem = f"{host}-{job_id}"
    html_path = _REPORT_DIR / f"{stem}.html"
    html_path.write_text(render_html(store, scan_id), encoding="utf-8")
    (_REPORT_DIR / f"{stem}.json").write_text(render_json(store, scan_id), encoding="utf-8")
    return str(html_path)


class _Handler(BaseHTTPRequestHandler):
    def log_message(self, format: str, *args: object) -> None:  # noqa: A002 - stdlib signature
        logger.debug("web: %s", format % args)

    def _send(self, body: str, *, status: int = 200) -> None:
        payload = body.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def do_GET(self) -> None:  # noqa: N802 - stdlib handler name
        path = urlsplit(self.path).path
        if path == "/":
            self._send(_home_page())
        elif path.startswith("/jobs/"):
            self._job_page(path.removeprefix("/jobs/"))
        elif path.startswith("/report/"):
            self._report(path.removeprefix("/report/"))
        else:
            self._send(_layout("Not found", "<p>Not found.</p>"), status=404)

    def do_POST(self) -> None:  # noqa: N802 - stdlib handler name
        if urlsplit(self.path).path != "/scan":
            self._send(_layout("Not found", "<p>Not found.</p>"), status=404)
            return
        length = int(self.headers.get("Content-Length", "0"))
        form = parse_qs(self.rfile.read(length).decode("utf-8"))
        target = form.get("url", [""])[0].strip()
        if not target:
            self._send(_layout("Error", "<p class='warn'>A target URL is required.</p>" + _back()), status=400)
            return
        job = _Job(id=uuid.uuid4().hex[:12], target=target)
        with _STATE.lock:
            _STATE.jobs[job.id] = job
            _STATE.order.insert(0, job.id)
        thread = threading.Thread(target=_run_job, args=(job, _parse_options(form)), daemon=True)
        thread.start()
        self.send_response(303)
        self.send_header("Location", f"/jobs/{job.id}")
        self.end_headers()

    def _job_page(self, job_id: str) -> None:
        job = _STATE.jobs.get(job_id)
        if job is None:
            self._send(_layout("Not found", "<p>Unknown job.</p>" + _back()), status=404)
            return
        if job.status == "running":
            body = f"<p>Scanning <code>{html.escape(job.target)}</code>…</p><p class='meta'>This page refreshes automatically.</p>"
            self._send(_layout("Scanning…", body, refresh=3))
            return
        if job.status == "error":
            self._send(_layout("Scan failed", f"<p class='warn'>{html.escape(job.detail)}</p>" + _back()))
            return
        inner = ""
        if job.db_path and job.scan_id:
            inner = render_html(ScanStore(job.db_path), job.scan_id)
        self._send(inner or _layout("Done", "<p>No results.</p>" + _back()))

    def _report(self, job_id: str) -> None:
        job = _STATE.jobs.get(job_id)
        if job is None or not (job.db_path and job.scan_id):
            self._send(_layout("Not found", "<p>No report.</p>"), status=404)
            return
        self._send(render_html(ScanStore(job.db_path), job.scan_id))


def _layout(title: str, body: str, *, refresh: int | None = None) -> str:
    meta = f"<meta http-equiv='refresh' content='{refresh}'>" if refresh else ""
    return f"""<!doctype html><html lang="en"><head><meta charset="utf-8">{meta}
<title>{html.escape(title)} · reconnaissance</title>
<style>
 body {{ font-family: system-ui, sans-serif; margin: 2rem auto; max-width: 780px; color: #1a1a1a; }}
 h1 {{ font-size: 1.4rem; }} label {{ display:block; margin:.6rem 0 .2rem; font-weight:600; }}
 input[type=text] {{ width:100%; padding:.5rem; font-size:1rem; }}
 .row {{ margin:.4rem 0; }} .warn {{ color:#9b1c1c; }} .meta {{ color:#666; }}
 .cols {{ display:flex; gap:1rem; }} .cols span {{ flex:1; }}
 button {{ margin-top:1rem; padding:.6rem 1.2rem; font-size:1rem; cursor:pointer; }}
 table {{ border-collapse:collapse; width:100%; margin:.6rem 0; font-size:.85rem; }}
 td,th {{ border:1px solid #ddd; padding:.3rem .5rem; text-align:left; }} th {{ background:#f3f4f6; }}
 code {{ font-family: ui-monospace, monospace; }}
</style></head><body><h1>reconnaissance</h1>{body}</body></html>"""


def _back() -> str:
    return "<p><a href='/'>← back</a></p>"


def _home_page() -> str:
    with _STATE.lock:
        jobs = [_STATE.jobs[i] for i in _STATE.order[:20]]
    rows = "".join(
        f"<tr><td><a href='/jobs/{j.id}'>{html.escape(j.target)}</a></td><td>{html.escape(j.status)}</td><td class='meta'>{html.escape(j.detail)}</td></tr>"
        for j in jobs
    )
    recent = f"<h2>Recent scans</h2><table><thead><tr><th>Target</th><th>Status</th><th>Result</th></tr></thead><tbody>{rows}</tbody></table>" if jobs else ""
    form = """
<form method="post" action="/scan">
  <label for="url">Target URL</label>
  <input type="text" id="url" name="url" placeholder="https://app.example.com" autofocus>
  <label for="scope_host">Scope host (optional — defaults to the URL host)</label>
  <input type="text" id="scope_host" name="scope_host" placeholder="app.example.com">
  <label for="wordlist">Wordlist path (optional — enables directory brute force)</label>
  <input type="text" id="wordlist" name="wordlist" placeholder="/path/to/wordlist.txt">
  <div class="cols">
    <span><label for="rate">Rate (req/s)</label><input type="text" id="rate" name="rate" value="50"></span>
    <span><label for="max_requests">Max requests</label><input type="text" id="max_requests" name="max_requests" placeholder="default"></span>
    <span><label for="max_endpoints">Max endpoints</label><input type="text" id="max_endpoints" name="max_endpoints" placeholder="default"></span>
  </div>
  <div class="row"><label><input type="checkbox" name="headless"> Headless crawl (JS-heavy SPA)</label></div>
  <div class="row"><label><input type="checkbox" name="reveal_secrets"> Reveal discovered secrets (unmasked)</label></div>
  <div class="row"><label><input type="checkbox" name="agent"> JS-semantics agent (needs ANTHROPIC_API_KEY)</label></div>
  <div class="row"><label><input type="checkbox" name="allow_internal"> Allow internal/loopback target</label></div>
  <button type="submit">Start scan</button>
</form>"""
    return _layout("reconnaissance", form + recent)


def serve(*, host: str = "127.0.0.1", port: int = 8000) -> None:
    """Start the local web UI (blocking)."""
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    server = ThreadingHTTPServer((host, port), _Handler)
    url = f"http://{host}:{port}"
    print(f"reconnaissance UI: {url}")  # noqa: T201 - user-facing entrypoint output
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        server.shutdown()


def main() -> int:
    """Console entrypoint for the web UI."""
    serve()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
