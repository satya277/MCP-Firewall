"""Pure helpers for MCP protocol concerns: naming, fingerprints and result/denial shaping."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field
from typing import Any

from mcp import types

from mcp_firewall.application.interfaces.upstream import ToolInfo, UpstreamResult
from mcp_firewall.application.services.interception_service import InterceptionOutcome
from mcp_firewall.domain.enums.request_status import RequestStatus

_BAD_CHARS = re.compile(r"[^A-Za-z0-9_-]")
MAX_TOOL_NAME = 64


def tool_fingerprint(name: str, description: str, input_schema: dict[str, Any]) -> str:
    """Stable fingerprint of a tool definition used for change detection (rug-pull defense)."""
    body = json.dumps(
        {"name": name, "description": description, "schema": input_schema},
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        default=str,
    )
    return hashlib.sha256(body.encode("utf-8")).hexdigest()


def _short_hash(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()[:6]


@dataclass(slots=True)
class ToolNameMap:
    """Maps the names exposed to the client back to (server, upstream tool)."""

    namespace: bool = True
    by_exposed: dict[str, ToolInfo] = field(default_factory=dict)

    def build(self, tools: list[ToolInfo]) -> list[tuple[str, ToolInfo]]:
        mapping: dict[str, ToolInfo] = {}  # swapped in atomically so concurrent calls never see a partial map
        out: list[tuple[str, ToolInfo]] = []
        for tool in sorted(tools, key=lambda t: (t.server, t.name)):
            raw = f"{tool.server}__{tool.name}" if self.namespace else tool.name
            name = _BAD_CHARS.sub("_", raw)
            if len(name) > MAX_TOOL_NAME or name != raw:
                name = f"{name[: MAX_TOOL_NAME - 7]}_{_short_hash(raw)}"
            if name in mapping:  # collision after sanitising
                name = f"{name[: MAX_TOOL_NAME - 7]}_{_short_hash(raw + tool.server)}"
            mapping[name] = tool
            out.append((name, tool))
        self.by_exposed = mapping
        return out

    def resolve(self, exposed: str) -> ToolInfo | None:
        return self.by_exposed.get(exposed)


def denial_result(outcome: InterceptionOutcome) -> types.CallToolResult:
    """What Claude receives when a call was blocked, expired or otherwise not executed."""
    labels = {
        RequestStatus.REJECTED: "BLOCKED by the user",
        RequestStatus.EXPIRED: "NOT EXECUTED (approval timed out)",
        RequestStatus.DENIED: "DENIED by security policy",
        RequestStatus.CANCELLED: "CANCELLED",
        RequestStatus.FAILED: "NOT EXECUTED",
        RequestStatus.EXECUTION_UNKNOWN: "OUTCOME UNKNOWN",
    }
    label = labels.get(outcome.status, outcome.status.value)
    text = f"[MCP Firewall] Tool call {label}: {outcome.message}."
    if outcome.status is RequestStatus.EXECUTION_UNKNOWN:
        text += " Do not assume it succeeded or failed, and do not retry automatically."
    else:
        text += " The tool was not executed; do not retry unless the user asks."
    if outcome.request_id:
        text += f" (request {outcome.request_id})"
    return types.CallToolResult(content=[types.TextContent(type="text", text=text)], isError=True)


def tool_result(result: UpstreamResult) -> types.CallToolResult:
    payload = result.payload
    if isinstance(payload, types.CallToolResult):
        return payload
    if isinstance(payload, types.ErrorData):
        return types.CallToolResult(
            content=[types.TextContent(type="text", text=f"Upstream error: {payload.message}")], isError=True
        )
    return types.CallToolResult(
        content=[types.TextContent(type="text", text=result.summary or "unexpected upstream result")],
        isError=True,
    )


def resource_contents(result: UpstreamResult) -> list[Any]:
    payload = result.payload
    if isinstance(payload, types.ReadResourceResult):
        return list(payload.contents)
    raise ValueError(result.summary or "resource read failed")
