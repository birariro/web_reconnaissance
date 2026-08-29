"""Tests for the agent tool loop: scope guard, call cap, dispatch (no live LLM)."""

from __future__ import annotations

from collections.abc import Sequence
from pathlib import Path

from reconnaissance.adapters.store import ScanStore
from reconnaissance.agent import AgentReply, AgentToolbox, ToolCall, ToolResult, drive
from reconnaissance.models import ScanConfig, Scope

HOST = "app.example.com"
BASE = "https://app.example.com/"


def _toolbox(tmp_path: Path, *, js: str = "") -> AgentToolbox:
    store = ScanStore(str(tmp_path / "s.sqlite"))
    store.initialize()
    config = ScanConfig(base_url=BASE, scope=Scope(target_host=HOST))
    scan_id = store.create_scan(config)
    return AgentToolbox(config=config, store=store, scan_id=scan_id, http_get=lambda url: js)


def test_record_endpoint_rejects_out_of_scope(tmp_path: Path) -> None:
    toolbox = _toolbox(tmp_path)
    assert toolbox.record_endpoint("https://evil.com/api").startswith("REJECTED")
    assert toolbox.recorded == []


def test_record_endpoint_admits_in_scope_path(tmp_path: Path) -> None:
    toolbox = _toolbox(tmp_path)
    assert toolbox.record_endpoint("/api/v2/orders").startswith("recorded")
    assert "https://app.example.com/api/v2/orders" in toolbox.recorded


def test_fetch_js_refuses_out_of_scope_url(tmp_path: Path) -> None:
    toolbox = _toolbox(tmp_path, js="console.log(1)")
    assert toolbox.fetch_js("https://cdn.evil.com/x.js") == "ERROR: url out of scope"
    assert toolbox.fetch_js("https://app.example.com/app.js") == "console.log(1)"


def test_drive_records_endpoint_then_stops(tmp_path: Path) -> None:
    # Given a model that records one endpoint then finishes
    toolbox = _toolbox(tmp_path)
    replies = iter(
        [
            AgentReply(tool_calls=(ToolCall(id="t1", name="record_endpoint", args={"path": "/api/v2/login"}),), done=False),
            AgentReply(tool_calls=(), done=True),
        ]
    )

    def turn_fn(_results: Sequence[ToolResult]) -> AgentReply:
        return next(replies)

    # When driven
    recorded = drive(toolbox, turn_fn)
    # Then the in-scope endpoint is recorded
    assert recorded == ["https://app.example.com/api/v2/login"]


def test_drive_enforces_tool_call_cap(tmp_path: Path) -> None:
    # Given a model that never stops asking to record endpoints
    toolbox = _toolbox(tmp_path)

    def turn_fn(_results: Sequence[ToolResult]) -> AgentReply:
        return AgentReply(tool_calls=(ToolCall(id="t", name="record_endpoint", args={"path": "/a"}),), done=False)

    # When driven with a low cap
    drive(toolbox, turn_fn, max_calls=3)
    # Then no more than the cap number of calls were made
    assert toolbox.calls == 3
