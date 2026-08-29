"""Render a completed scan to JSON or HTML.

Endpoint URLs, titles, and discovered secrets are attacker-influenced, so the
HTML renderer escapes every interpolated value with :func:`html.escape` (no
template engine, no ``| safe``). Secrets are already masked in the store. The
termination reason is shown prominently so a budget-truncated scan is never
read as complete.
"""

from __future__ import annotations

import html
import json
import logging

from reconnaissance.adapters.store import ScanStore

logger = logging.getLogger(__name__)

_PARTIAL_REASONS = frozenset({"budget_exhausted", "killswitch"})


def build_report(store: ScanStore, scan_id: str) -> dict[str, object]:
    """Assemble the structured (JSON-ready) report for a scan."""
    scan = store.get_scan(scan_id)
    endpoints = store.list_endpoints(scan_id)
    parameters = store.list_parameters(scan_id)
    return {
        "scan": {
            "id": scan["id"],
            "base_url": scan["base_url"],
            "termination_reason": scan["termination_reason"],
            "coverage_partial": scan["termination_reason"] in _PARTIAL_REASONS,
            "started_at": scan["started_at"],
            "finished_at": scan["finished_at"],
            "technologies": json.loads(str(scan["tech_json"])),
            "api_surfaces": json.loads(str(scan["api_json"])),
        },
        "endpoints": [_endpoint_view(e) for e in endpoints],
        "parameters": [_param_view(p) for p in parameters],
        "counts": {"endpoints": len(endpoints), "parameters": len(parameters)},
    }


def _endpoint_view(row: dict[str, object]) -> dict[str, object]:
    headers: dict[str, str] = json.loads(str(row["headers_json"]))
    return {
        "url": row["url"],
        "method": row["method"],
        "status": row["status"],
        "classification": row["classification"],
        "sources": json.loads(str(row["sources_json"])),
        "secrets": json.loads(str(row["secrets_json"])),
        "content_type": row["content_type"],
        "title": row["title"],
        "server": headers.get("server"),
        "headers": headers,
        "tls": json.loads(str(row["tls_json"])),
    }


def _param_view(row: dict[str, object]) -> dict[str, object]:
    return {"endpoint_url": row["endpoint_url"], "name": row["name"], "location": row["location"], "source": row["source"]}


def render_json(store: ScanStore, scan_id: str) -> str:
    """Render the scan as pretty-printed JSON (the primary machine artifact)."""
    return json.dumps(build_report(store, scan_id), indent=2, sort_keys=True)


def render_html(store: ScanStore, scan_id: str) -> str:
    """Render the scan as a single self-contained HTML page (values escaped)."""
    report = build_report(store, scan_id)
    scan = report["scan"]
    assert isinstance(scan, dict)
    counts = report["counts"]
    assert isinstance(counts, dict)
    endpoints = report["endpoints"]
    assert isinstance(endpoints, list)
    parameters = report["parameters"]
    assert isinstance(parameters, list)

    banner = ""
    if scan["coverage_partial"]:
        banner = f"<p class='warn'>Coverage is PARTIAL — scan stopped early ({_esc(scan['termination_reason'])}). Some surface may be undiscovered.</p>"

    rows = "\n".join(_endpoint_row(e) for e in endpoints if isinstance(e, dict))
    param_rows = "\n".join(_param_row(p) for p in parameters if isinstance(p, dict))
    tech = scan["technologies"] if isinstance(scan["technologies"], list) else []
    return _PAGE.format(
        base_url=_esc(scan["base_url"]),
        reason=_esc(scan["termination_reason"]),
        banner=banner,
        endpoint_count=_esc(counts["endpoints"]),
        param_count=_esc(counts["parameters"]),
        technologies=_tech_section(tech),
        tls=_tls_section(endpoints),
        headers=_headers_section(endpoints, str(scan["base_url"])),
        endpoint_rows=rows,
        param_rows=param_rows,
    )


def _tls_section(endpoints: list[object]) -> str:
    cert = next((e["tls"] for e in endpoints if isinstance(e, dict) and isinstance(e.get("tls"), dict) and e["tls"]), None)
    if not isinstance(cert, dict):
        return "<p class='meta'>No TLS certificate captured (HTTP target or not probed).</p>"
    sans = cert.get("sans")
    fields = {
        "Subject CN": cert.get("subject_cn"),
        "Issuer": cert.get("issuer"),
        "Valid from": cert.get("not_before"),
        "Valid until": cert.get("not_after"),
        "TLS": cert.get("tls_version"),
        "SHA-256": cert.get("sha256"),
        "SANs": ", ".join(str(s) for s in sans) if isinstance(sans, list) else "",
    }
    rows = "".join(f"<tr><td>{_esc(k)}</td><td class='url'>{_esc(v)}</td></tr>" for k, v in fields.items() if v)
    return f"<table><tbody>{rows}</tbody></table>"


def _tech_section(technologies: list[object]) -> str:
    if not technologies:
        return "<p class='meta'>No technologies fingerprinted.</p>"
    items = "".join(f"<li>{_esc(t.get('name'))}{_cat(t)}</li>" for t in technologies if isinstance(t, dict))
    return f"<ul class='tech'>{items}</ul>"


def _cat(tech: dict[str, object]) -> str:
    category = tech.get("category")
    version = tech.get("version")
    parts = [str(p) for p in (category, version) if p]
    return f" <span class='meta'>({_esc(' · '.join(parts))})</span>" if parts else ""


def _headers_section(endpoints: list[object], base_url: str) -> str:
    home = next((e for e in endpoints if isinstance(e, dict) and e.get("url") == base_url and e.get("headers")), None)
    if home is None:
        home = next((e for e in endpoints if isinstance(e, dict) and e.get("headers")), None)
    if home is None or not isinstance(home.get("headers"), dict):
        return "<p class='meta'>No response headers captured.</p>"
    headers: dict[str, object] = home["headers"]
    rows = "".join(f"<tr><td>{_esc(k)}</td><td class='url'>{_esc(v)}</td></tr>" for k, v in sorted(headers.items()))
    return f"<p class='meta'>Response headers for <code>{_esc(home.get('url'))}</code>:</p><table><tbody>{rows}</tbody></table>"


def _esc(value: object) -> str:
    return html.escape(str(value)) if value is not None else ""


def _endpoint_row(e: dict[str, object]) -> str:
    sources = ", ".join(str(s) for s in e["sources"]) if isinstance(e["sources"], list) else ""
    return (
        "<tr>"
        f"<td>{_esc(e['method'])}</td>"
        f"<td class='url'>{_esc(e['url'])}</td>"
        f"<td>{_esc(e['status'])}</td>"
        f"<td>{_esc(e['classification'])}</td>"
        f"<td>{_esc(e.get('server'))}</td>"
        f"<td>{_esc(sources)}</td>"
        f"<td>{_esc(e['title'])}</td>"
        "</tr>"
    )


def _param_row(p: dict[str, object]) -> str:
    return f"<tr><td>{_esc(p['name'])}</td><td>{_esc(p['location'])}</td><td class='url'>{_esc(p['endpoint_url'])}</td><td>{_esc(p['source'])}</td></tr>"


_PAGE = """<!doctype html>
<html lang="en"><head><meta charset="utf-8"><title>reconnaissance report</title>
<style>
 body {{ font-family: system-ui, sans-serif; margin: 2rem; color: #1a1a1a; }}
 h1 {{ font-size: 1.4rem; }}
 .warn {{ background: #fde8e8; border: 1px solid #e02424; padding: .6rem .8rem; border-radius: 6px; color: #9b1c1c; }}
 table {{ border-collapse: collapse; width: 100%; margin: 1rem 0; font-size: .86rem; }}
 th, td {{ border: 1px solid #ddd; padding: .35rem .5rem; text-align: left; vertical-align: top; }}
 th {{ background: #f3f4f6; }}
 .url {{ font-family: ui-monospace, monospace; word-break: break-all; }}
 .meta {{ color: #555; }}
 ul.tech {{ columns: 3; list-style: square inside; }}
</style></head><body>
<h1>Web app recon — {base_url}</h1>
<p class="meta">Termination: <strong>{reason}</strong> · Endpoints: {endpoint_count} · Parameters: {param_count}</p>
{banner}
<h2>Technologies</h2>
{technologies}
<h2>TLS certificate</h2>
{tls}
<h2>Response headers</h2>
{headers}
<h2>Endpoints</h2>
<table><thead><tr><th>Method</th><th>URL</th><th>Status</th><th>Class</th><th>Server</th><th>Sources</th><th>Title</th></tr></thead>
<tbody>
{endpoint_rows}
</tbody></table>
<h2>Parameters</h2>
<table><thead><tr><th>Name</th><th>Location</th><th>Endpoint</th><th>Source</th></tr></thead>
<tbody>
{param_rows}
</tbody></table>
</body></html>
"""
