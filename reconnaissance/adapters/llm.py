"""Anthropic-backed turn function for the agent layer.

Imported lazily by :func:`reconnaissance.agent.enrich`; if the ``anthropic`` package
is not installed this module fails to import and enrichment is skipped. Isolated
here so the rest of the package has no hard dependency on the SDK.
"""

from __future__ import annotations

import logging
import os
from collections.abc import Sequence
from typing import Any, cast

import anthropic

from reconnaissance.agent import AgentReply, ToolCall, ToolResult, TurnFn
from reconnaissance.models import ScanConfig

logger = logging.getLogger(__name__)

MODEL = "claude-sonnet-5"
MAX_TOKENS = 2048

_SYSTEM = (
    "You are a web-app reconnaissance assistant. You are given URLs of in-scope JavaScript assets. "
    "Fetch them with fetch_js and read them to find API endpoint paths that a regex would miss "
    "(paths built by string concatenation, template literals, route tables). For each real endpoint "
    "path you find, call record_endpoint with the path. Only record paths on the target app. "
    "Do not invent endpoints. When you have analyzed the provided assets, stop."
)


def build_turn_fn(*, config: ScanConfig, js_urls: Sequence[str], tools: Sequence[dict[str, object]]) -> TurnFn:
    """Build a turn function backed by the Anthropic Messages API."""
    client = anthropic.Anthropic(api_key=os.environ.get("ANTHROPIC_API_KEY"))
    messages: list[dict[str, Any]] = [
        {
            "role": "user",
            "content": (f"Target: {config.base_url}\nIn-scope JS assets to analyze:\n" + "\n".join(js_urls) if js_urls else "No JS assets were found; you may stop."),
        }
    ]

    def turn(results: Sequence[ToolResult]) -> AgentReply:
        if results:
            messages.append({"role": "user", "content": [{"type": "tool_result", "tool_use_id": r.id, "content": r.content} for r in results]})
        response = client.messages.create(model=MODEL, max_tokens=MAX_TOKENS, system=_SYSTEM, tools=cast(Any, list(tools)), messages=cast(Any, messages))
        assistant_content: list[dict[str, Any]] = []
        tool_calls: list[ToolCall] = []
        for block in response.content:
            if block.type == "text":
                assistant_content.append({"type": "text", "text": block.text})
            elif block.type == "tool_use":
                assistant_content.append({"type": "tool_use", "id": block.id, "name": block.name, "input": block.input})
                args = block.input if isinstance(block.input, dict) else {}
                tool_calls.append(ToolCall(id=block.id, name=block.name, args={k: str(v) for k, v in args.items()}))
        messages.append({"role": "assistant", "content": assistant_content})
        return AgentReply(tool_calls=tuple(tool_calls), done=response.stop_reason != "tool_use")

    return turn
