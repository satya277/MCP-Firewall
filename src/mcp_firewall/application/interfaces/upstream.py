"""Ports for the upstream MCP servers, human notification, metrics and sanitization."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Protocol, runtime_checkable

from mcp_firewall.domain.entities.mcp_request import McpRequest


@dataclass(frozen=True, slots=True)
class ToolInfo:
    server: str
    name: str  # name on the upstream server
    description: str
    input_schema: dict[str, Any]
    fingerprint: str
    raw: Any = None  # opaque transport object (mcp.types.Tool) for the protocol layer


@dataclass(frozen=True, slots=True)
class UpstreamResult:
    is_error: bool
    payload: Any  # opaque protocol result (mcp.types.CallToolResult / ReadResourceResult)
    summary: str = ""


@runtime_checkable
class UpstreamGateway(Protocol):
    """The set of upstream MCP servers the firewall protects."""

    def server_names(self) -> list[str]: ...

    async def list_tools(self) -> list[ToolInfo]: ...

    async def execute(self, request: McpRequest) -> UpstreamResult:
        """Send exactly ``request`` upstream.

        Raises UpstreamUnavailableError if the call was definitely NOT sent, and
        UpstreamTimeoutError / UpstreamCommunicationError if it may have been executed.
        """
        ...


@runtime_checkable
class ApproverNotifier(Protocol):
    """Best-effort hook to make sure a human interface is reachable (e.g. launch the tray app)."""

    async def ensure_approver(self) -> None: ...


class NullNotifier:
    async def ensure_approver(self) -> None:
        return None


@runtime_checkable
class Sanitizer(Protocol):
    def sanitize(self, value: Any) -> Any: ...

    def redact_text(self, text: str) -> str: ...


@runtime_checkable
class MetricsPort(Protocol):
    def request_finished(self, status: str, operation: str) -> None: ...

    def approval_latency(self, seconds: float, outcome: str) -> None: ...

    def pending_changed(self, delta: int) -> None: ...

    def security_event(self, kind: str) -> None: ...


class NullMetrics:
    def request_finished(self, status: str, operation: str) -> None:
        return None

    def approval_latency(self, seconds: float, outcome: str) -> None:
        return None

    def pending_changed(self, delta: int) -> None:
        return None

    def security_event(self, kind: str) -> None:
        return None
