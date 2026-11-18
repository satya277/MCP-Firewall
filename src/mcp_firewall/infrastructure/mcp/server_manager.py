"""The MCP *server* face of the firewall: what Claude connects to.

It re-exposes the upstream tools, and routes every ``tools/call`` (and, optionally,
``resources/read``) through the InterceptionService before anything reaches an upstream.
"""

from __future__ import annotations

import base64
import contextvars
from typing import Any

import structlog
from mcp import types
from mcp.server.lowlevel import NotificationOptions, Server
from mcp.server.lowlevel.helper_types import ReadResourceContents
from pydantic import AnyUrl

from mcp_firewall.application.services.interception_service import IncomingCall, InterceptionService
from mcp_firewall.domain.entities.approval import Principal
from mcp_firewall.domain.entities.mcp_request import RESOURCES_READ, TOOLS_CALL
from mcp_firewall.domain.enums.request_status import RequestStatus
from mcp_firewall.infrastructure.mcp.client_manager import UpstreamManager
from mcp_firewall.infrastructure.mcp.protocol_handler import (
    ToolNameMap,
    denial_result,
    resource_contents,
    tool_result,
)

log = structlog.get_logger("gateway")

# Set by the HTTP transport after authenticating the MCP client; unset for STDIO.
current_principal: contextvars.ContextVar[Principal | None] = contextvars.ContextVar(
    "mcpfw_principal", default=None
)


class FirewallMcpServer:
    def __init__(
        self,
        upstream: UpstreamManager,
        interception: InterceptionService,
        *,
        default_client_id: str = "claude-desktop",
        tenant_id: str = "default",
        intercept_resources: bool = True,
    ) -> None:
        self._upstream = upstream
        self._interception = interception
        self._default_client = default_client_id
        self._tenant = tenant_id
        self._intercept_resources = intercept_resources
        self._names = ToolNameMap(namespace=upstream.config.namespace_tools)
        self._resource_servers: dict[str, str] = {}
        self.server: Server = Server("mcp-firewall")

    # -- identity -------------------------------------------------------------------------
    def _identity(self) -> tuple[str, str, str]:
        """(client_id, tenant_id, user_id) for the current request."""
        client = self._default_client
        try:
            info = self.server.request_context.session.client_params.clientInfo  # type: ignore[union-attr]
            if info and info.name:
                client = info.name
        except Exception:
            log.debug("client_info_unavailable")
        principal = current_principal.get()
        tenant = principal.tenant_id if principal else self._tenant
        user = principal.id if principal else "local"
        return client[:64], tenant, user

    # -- build ----------------------------------------------------------------------------
    async def build(self) -> Server:
        server = self.server

        @server.list_tools()
        async def list_tools() -> list[types.Tool]:
            return await self._list_tools()

        @server.call_tool(validate_input=False)  # the firewall validates against the upstream schema itself
        async def call_tool(name: str, arguments: dict[str, Any] | None) -> types.CallToolResult:
            return await self._call_tool(name, arguments)

        if await self._any_resources():

            @server.list_resources()
            async def list_resources() -> list[types.Resource]:
                return await self._list_resources()

            @server.read_resource()
            async def read_resource(uri: AnyUrl) -> list[ReadResourceContents]:
                return await self._read_resource(str(uri))

        return server

    def initialization_options(self):
        return self.server.create_initialization_options(
            notification_options=NotificationOptions(), experimental_capabilities={}
        )

    async def _any_resources(self) -> bool:
        for name in self._upstream.server_names():
            conn = self._upstream.connection(name)
            if conn and conn.connected and await conn.supports_resources():
                return True
        return False

    # -- tools ----------------------------------------------------------------------------
    async def _list_tools(self) -> list[types.Tool]:
        tools = await self._upstream.list_tools()
        exposed: list[types.Tool] = []
        for name, info in self._names.build(tools):
            exposed.append(info.raw.model_copy(update={"name": name}))
        return exposed

    async def _call_tool(self, name: str, arguments: dict[str, Any] | None) -> types.CallToolResult:
        info = self._names.resolve(name)
        if info is None:
            await self._list_tools()  # a stateless HTTP client may call without listing first
            info = self._names.resolve(name)
        if info is None:
            return types.CallToolResult(
                content=[types.TextContent(type="text", text=f"[MCP Firewall] Unknown tool: {name}")],
                isError=True,
            )
        client, tenant, user = self._identity()
        outcome = await self._interception.intercept(
            IncomingCall(
                operation=TOOLS_CALL,
                client_id=client,
                server=info.server,
                tool=info.name,
                arguments=arguments,
                tenant_id=tenant,
                user_id=user,
                description=info.description,
                input_schema=info.input_schema,
                fingerprint=info.fingerprint,
                keepalive=self._keepalive(),
            )
        )
        if outcome.result is not None and outcome.status is RequestStatus.COMPLETED:
            return tool_result(outcome.result)
        return denial_result(outcome)

    def _keepalive(self):
        """Progress notifications stop clients from timing out while a human decides."""
        try:
            ctx = self.server.request_context
            token = ctx.meta.progressToken if ctx.meta else None
            session = ctx.session
            request_id = ctx.request_id
        except Exception:
            return None
        if token is None:
            return None

        async def ping(elapsed: float) -> None:
            await session.send_progress_notification(
                token,
                progress=elapsed,
                message="MCP Firewall: waiting for user approval",
                related_request_id=request_id,
            )

        return ping

    # -- resources ------------------------------------------------------------------------
    async def _list_resources(self) -> list[types.Resource]:
        self._resource_servers = {}
        out: list[types.Resource] = []
        for name in self._upstream.server_names():
            conn = self._upstream.connection(name)
            if not conn or not conn.connected or not await conn.supports_resources():
                continue
            try:
                for res in await conn.list_resources():
                    uri = str(res.uri)
                    if uri in self._resource_servers:
                        log.warning("resource_uri_collision", uri=uri, server=name)
                        continue
                    self._resource_servers[uri] = name
                    out.append(res)
            except Exception as exc:
                log.warning("list_resources_failed", server=name, error=str(exc)[:200])
        return out

    async def _read_resource(self, uri: str) -> list[ReadResourceContents]:
        server = self._resource_servers.get(uri)
        if server is None:
            await self._list_resources()
            server = self._resource_servers.get(uri)
        if server is None:
            raise ValueError("unknown resource")
        client, tenant, user = self._identity()
        if not self._intercept_resources:
            raise ValueError("resource reads are disabled")
        outcome = await self._interception.intercept(
            IncomingCall(
                operation=RESOURCES_READ,
                client_id=client,
                server=server,
                tool=uri,
                arguments={"uri": uri},
                tenant_id=tenant,
                user_id=user,
                keepalive=self._keepalive(),
            )
        )
        if outcome.result is None or outcome.status is not RequestStatus.COMPLETED:
            raise ValueError(f"[MCP Firewall] resource read not permitted: {outcome.message}")
        contents: list[ReadResourceContents] = []
        for item in resource_contents(outcome.result):
            if isinstance(item, types.TextResourceContents):
                contents.append(ReadResourceContents(content=item.text, mime_type=item.mimeType))
            else:
                contents.append(
                    ReadResourceContents(content=base64.b64decode(item.blob), mime_type=item.mimeType)
                )
        return contents
