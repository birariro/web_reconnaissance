"""Tool parsers must survive valid-JSON-but-malformed rows without crashing."""

from __future__ import annotations

from reconnaissance.adapters.tools import arjun, ffuf, httpx, katana
from reconnaissance.models import EndpointSource


def test_httpx_parse_skips_rows_missing_url_and_out_of_range_status() -> None:
    text = "\n".join(
        [
            '{"status_code": 200}',  # no url -> skip
            '{"url": "https://app.example.com/a", "status_code": 0}',  # bad status -> None, kept
            '{"url": "https://app.example.com/b", "status_code": 200}',
            "not json at all",  # skip
            "[1,2,3]",  # not a dict -> skip
        ]
    )
    outcome = httpx.parse_probe(text, source=EndpointSource.CRAWL)
    urls = {e.url for e in outcome.endpoints}
    assert urls == {"https://app.example.com/a", "https://app.example.com/b"}
    assert next(e for e in outcome.endpoints if e.url.endswith("/a")).status is None


def test_katana_parse_skips_non_dict_request_and_response() -> None:
    text = "\n".join(
        [
            '{"request": "oops", "response": {}}',  # request not a dict -> skip
            '{"request": {"endpoint": "https://app.example.com/x", "method": "POST"}, "response": null}',  # response null ok, method forced GET
            '{"request": {}, "response": {}}',  # no endpoint -> skip
        ]
    )
    outcome = katana.parse_crawl(text)
    assert [e.url for e in outcome.endpoints] == ["https://app.example.com/x"]
    assert outcome.endpoints[0].method.value == "POST"


def test_ffuf_parse_skips_rows_missing_url() -> None:
    text = '{"results": [{"status": 200}, {"url": "https://app.example.com/ok", "status": 200, "length": 10}, "notadict"]}'
    outcome = ffuf.parse_fuzz(text)
    assert [e.url for e in outcome.endpoints] == ["https://app.example.com/ok"]


def test_arjun_parse_skips_non_dict_entries() -> None:
    text = '{"https://app.example.com/s": {"params": ["q", 5, "lang"]}, "bad": "notadict"}'
    outcome = arjun.parse_params(text)
    assert {p.name for p in outcome.params} == {"q", "lang"}
