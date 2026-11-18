"""Upstream MCP connections (the firewall acts as an MCP *client* here).

Each upstream is owned by one supervisor task (anyio cancel scopes must be entered and exited in
the same task). Connections are re-established with backoff; while down, calls fail with
UpstreamUnavailableError and are never sent.
"""

from __future__ import annotations

import asyncio
import contextlib
import shutil
from datetime import timedelta
from pathlib import Path
from typing import Any

import anyio
import httpx
import structlog
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client
from mcp.client.streamable_http import streamablehttp_client
from mcp.shared.exceptions import McpError
from pydantic import AnyUrl

from mcp_firewall.application.interfaces.upstream import ToolInfo, UpstreamResult
from mcp_firewall.config import ServerConfig, ServersConfig
from mcp_firewall.domain.canonical import canonical_json
from mcp_firewall.domain.entities.mcp_request import RESOURCES_READ, TOOLS_CALL, McpRequest
from mcp_firewall.domain.exceptions import (
    FirewallError,
    UpstreamCommunicationError,
    UpstreamTimeoutError,
    UpstreamUnavailableError,
)
from mcp_firewall.infrastructure.mcp.protocol_handler import tool_fingerprint
from mcp_firewall.infrastructure.security.secrets_manager import resolve_refs
from mcp_firewall.infrastructure.security.ssrf import UnsafeUpstreamError, validate_remote_url_async

log = structlog.get_logger("upstream")
_PING_INTERVAL = 15.0


def _no_redirect_client(
    headers: dict[str, str] | None = None,
    timeout: httpx.Timeout | None = None,
    auth: httpx.Auth | None = None,
) -> httpx.AsyncClient:
    """httpx client with redirects disabled (a redirect could bounce us to an internal address)."""
    return httpx.AsyncClient(
        headers=headers, timeout=timeout or httpx.Timeout(30.0, read=300.0), auth=auth, follow_redirects=False
    )


def resolve_executable(command: str, allowed: list[str]) -> str:
    """Allowlist check + resolution to an absolute path. Never uses a shell."""
    base = Path(command).name.lower()
    if base not in {a.lower() for a in allowed}:
        raise FirewallError(f"executable {command!r} is not in allowed_executables")
    resolved = shutil.which(command)
    if resolved is None:
        raise FirewallError(f"executable {command!r} was not found on PATH")
    return resolved


class UpstreamConnection:
    def __init__(self, config: ServerConfig, servers: ServersConfig, execution_timeout: float) -> None:
        self.config = config
        self._servers = servers
        self._exec_timeout = execution_timeout
        self._session: ClientSession | None = None
        self._ready = asyncio.Event()
        self._stop = asyncio.Event()
        self._task: asyncio.Task[None] | None = None
        self.last_error: str | None = None

    @property
    def name(self) -> str:
        return self.config.name

    @property
    def connected(self) -> bool:
        return self._session is not None and self._ready.is_set()

    def start(self) -> None:
        self._task = asyncio.create_task(self._supervise(), name=f"upstream-{self.name}")

    async def stop(self) -> None:
        self._stop.set()
        if self._task:
            self._task.cancel()
            with contextlib.suppress(asyncio.CancelledError, Exception, BaseExceptionGroup):
                await self._task

    async def wait_ready(self, wait_seconds: float) -> bool:
        with contextlib.suppress(TimeoutError):
            await asyncio.wait_for(self._ready.wait(), wait_seconds)
        return self._ready.is_set()

    async def _supervise(self) -> None:
        backoff = 1.0
        while not self._stop.is_set():
            try:
                async with self._open() as session:
                    await asyncio.wait_for(session.initialize(), self.config.connect_timeout_seconds)
                    self._session = session
                    self._ready.set()
                    self.last_error = None
                    backoff = 1.0
                    log.info("upstream_connected", server=self.name)
                    await self._watch(session)
            except asyncio.CancelledError:
                raise
            except (Exception, BaseExceptionGroup) as exc:
                self.last_error = f"{type(exc).__name__}: {exc}"[:300]
                log.warning("upstream_connection_failed", server=self.name, error=self.last_error)
            finally:
                self._session = None
                self._ready.clear()
            if self._stop.is_set():
                break
            await asyncio.sleep(backoff)
            backoff = min(backoff * 2, 30.0)

    async def _watch(self, session: ClientSession) -> None:
        """Return (so we reconnect) once the upstream stops answering pings."""
        while not self._stop.is_set():
            await asyncio.sleep(_PING_INTERVAL)
            try:
                await asyncio.wait_for(session.send_ping(), 10.0)
            except (Exception, BaseExceptionGroup):
                log.warning("upstream_ping_failed", server=self.name)
                return

    @contextlib.asynccontextmanager
    async def _open(self):
        cfg = self.config
        if cfg.transport == "stdio":
            assert cfg.command
            command = resolve_executable(resolve_refs(cfg.command), self._servers.allowed_executables)
            env = {k: resolve_refs(v) for k, v in cfg.env.items()}
            params = StdioServerParameters(
                command=command, args=[resolve_refs(a) for a in cfg.args], env=env or None, cwd=cfg.cwd
            )
            async with stdio_client(params) as (read, write), ClientSession(read, write) as session:
                yield session
        else:
            assert cfg.url
            url = resolve_refs(cfg.url)
            await validate_remote_url_async(
                url,
                allowed_hosts=frozenset(h.lower() for h in cfg.allowed_hosts),
                allow_insecure_loopback=cfg.allow_insecure_loopback,
            )
            headers = {k: resolve_refs(v) for k, v in cfg.headers.items()}
            async with (
                streamablehttp_client(
                    url, headers=headers or None, httpx_client_factory=_no_redirect_client
                ) as (
                    read,
                    write,
                    _,
                ),
                ClientSession(read, write) as session,
            ):
                yield session

    # -- operations -----------------------------------------------------------------------
    def _require(self) -> ClientSession:
        if not self.connected or self._session is None:
            raise UpstreamUnavailableError(f"upstream {self.name!r} is not connected")
        return self._session

    async def list_tools(self) -> list[ToolInfo]:
        session = self._require()
        tools: list[ToolInfo] = []
        cursor: str | None = None
        for _ in range(50):  # bounded pagination
            page = await session.list_tools(cursor)
            for tool in page.tools:
                schema = tool.inputSchema or {}
                tools.append(
                    ToolInfo(
                        server=self.name,
                        name=tool.name,
                        description=tool.description or "",
                        input_schema=schema,
                        fingerprint=tool_fingerprint(tool.name, tool.description or "", schema),
                        raw=tool,
                    )
                )
            cursor = page.nextCursor
            if not cursor:
                break
        return tools

    async def list_resources(self) -> list[Any]:
        session = self._require()
        out: list[Any] = []
        cursor: str | None = None
        for _ in range(50):
            page = await session.list_resources(cursor)
            out.extend(page.resources)
            cursor = page.nextCursor
            if not cursor:
                break
        return out

    async def supports_resources(self) -> bool:
        session = self._session
        caps = session.get_server_capabilities() if session else None
        return bool(caps and caps.resources)

    async def execute(self, request: McpRequest) -> UpstreamResult:
        session = self._require()
        timeout = timedelta(seconds=self._exec_timeout)
        try:
            if request.operation == TOOLS_CALL:
                result = await session.call_tool(
                    request.tool, request.arguments, read_timeout_seconds=timeout
                )
                summary = "tool reported an error" if result.isError else "ok"
                return UpstreamResult(bool(result.isError), result, summary)
            if request.operation == RESOURCES_READ:
                result = await session.read_resource(AnyUrl(request.tool))
                return UpstreamResult(False, result, "ok")
        except McpError as exc:
            if exc.error.code == 408:  # SDK request timeout: the call was sent, outcome unknown
                raise UpstreamTimeoutError("upstream timed out") from exc
            # otherwise the upstream answered with a JSON-RPC error
            text = f"upstream error: {exc.error.message}"[:300]
            return UpstreamResult(True, exc.error, text)
        except TimeoutError as exc:
            raise UpstreamTimeoutError("upstream timed out") from exc
        except (anyio.ClosedResourceError, anyio.BrokenResourceError, anyio.EndOfStream, OSError) as exc:
            raise UpstreamCommunicationError("connection to upstream lost") from exc
        raise UpstreamUnavailableError(f"unsupported operation {request.operation}")


class UpstreamManager:
    """Implements the UpstreamGateway port over a set of upstream connections."""

    def __init__(self, servers: ServersConfig, execution_timeout: float = 120.0) -> None:
        self._servers = servers
        self._conns: dict[str, UpstreamConnection] = {
            s.name: UpstreamConnection(s, servers, execution_timeout) for s in servers.servers if s.enabled
        }

    @property
    def config(self) -> ServersConfig:
        return self._servers

    def server_names(self) -> list[str]:
        return list(self._conns)

    def connection(self, name: str) -> UpstreamConnection | None:
        return self._conns.get(name)

    async def start(self, wait: float = 20.0) -> None:
        for conn in self._conns.values():
            conn.start()
        if self._conns:
            await asyncio.gather(*(c.wait_ready(wait) for c in self._conns.values()))

    async def stop(self) -> None:
        await asyncio.gather(*(c.stop() for c in self._conns.values()), return_exceptions=True)

    async def list_tools(self) -> list[ToolInfo]:
        results = await asyncio.gather(
            *(c.list_tools() for c in self._conns.values()), return_exceptions=True
        )
        tools: list[ToolInfo] = []
        for conn, res in zip(self._conns.values(), results, strict=True):
            if isinstance(res, BaseException):
                log.warning("list_tools_failed", server=conn.name, error=str(res)[:200])
                continue
            tools.extend(res)
        return tools

    async def execute(self, request: McpRequest) -> UpstreamResult:
        conn = self._conns.get(request.server)
        if conn is None:
            raise UpstreamUnavailableError(f"unknown upstream {request.server!r}")
        return await conn.execute(request)

    def health(self) -> dict[str, dict[str, Any]]:
        return {n: {"connected": c.connected, "error": c.last_error} for n, c in self._conns.items()}


__all__ = [
    "UnsafeUpstreamError",
    "UpstreamConnection",
    "UpstreamManager",
    "canonical_json",
    "resolve_executable",
]
