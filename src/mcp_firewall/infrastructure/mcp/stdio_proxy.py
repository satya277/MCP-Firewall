"""Local STDIO gateway: the process Claude Desktop launches as its "MCP server".

Inside this process:
  Claude Desktop --stdio--> FirewallMcpServer --> InterceptionService --> UpstreamManager --> real MCP servers
and an embedded, loopback-only, token-protected approval API that the desktop agent connects to.
stdout carries protocol messages only; every diagnostic goes to stderr.
"""

from __future__ import annotations

import asyncio
import contextlib
import os
import socket
import time
from pathlib import Path

import structlog
import uvicorn
from mcp.server.stdio import stdio_server

from mcp_firewall.bootstrap import Container, build_container
from mcp_firewall.config import Settings, load_policy_file, load_servers
from mcp_firewall.domain.entities.approval import Principal
from mcp_firewall.domain.enums.decision import Role
from mcp_firewall.infrastructure.agent_launcher import AgentLauncher
from mcp_firewall.infrastructure.discovery import GatewayInfo, publish_gateway, remove_gateway
from mcp_firewall.infrastructure.mcp.client_manager import UpstreamManager
from mcp_firewall.infrastructure.mcp.server_manager import FirewallMcpServer
from mcp_firewall.infrastructure.security.authentication import generate_token
from mcp_firewall.interfaces.api.app import create_app
from mcp_firewall.interfaces.api.websocket import ConnectionRegistry

log = structlog.get_logger("stdio-gateway")


class EmbeddedServer(uvicorn.Server):
    """uvicorn without its own signal handling (the host process owns signals)."""

    @contextlib.contextmanager
    def capture_signals(self):
        yield


async def start_local_api(
    container: Container, connections: ConnectionRegistry, token: str
) -> tuple[EmbeddedServer, asyncio.Task[None], int]:
    container.approver_auth.add(
        Principal(id="local-user", role=Role.ADMIN, tenant_id=container.settings.tenant_id), token
    )
    app = create_app(container, allowed_hosts=["127.0.0.1", "localhost"], connections=connections)
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(("127.0.0.1", 0))  # ephemeral loopback port: no conflicts between gateway processes
    port = sock.getsockname()[1]
    config = uvicorn.Config(app, log_config=None, access_log=False, lifespan="off", ws_max_size=8192)
    server = EmbeddedServer(config)
    task = asyncio.create_task(server.serve(sockets=[sock]), name="local-approval-api")
    deadline = time.monotonic() + 10
    while not server.started:
        if task.done() or time.monotonic() > deadline:
            raise RuntimeError("local approval API failed to start")
        await asyncio.sleep(0.05)
    return server, task, port


async def run_stdio_gateway(settings: Settings, servers_path: Path, policies_path: Path) -> None:
    servers = load_servers(servers_path)
    policy = load_policy_file(policies_path)
    upstream = UpstreamManager(servers, settings.execution_timeout_seconds + 5)
    connections = ConnectionRegistry()
    notifier = AgentLauncher(settings.run_dir, connections) if settings.auto_start_agent else None
    container = build_container(
        settings, policy=policy, upstream=upstream, notifier=notifier, policies_file=policies_path
    )
    token = generate_token()
    api_server: EmbeddedServer | None = None
    api_task: asyncio.Task[None] | None = None
    try:
        await container.start()
        api_server, api_task, port = await start_local_api(container, connections, token)
        publish_gateway(
            settings.run_dir,
            GatewayInfo(
                id=container.owner_id,
                pid=os.getpid(),
                url=f"http://127.0.0.1:{port}",
                token=token,
                started=time.time(),
                servers=upstream.server_names(),
            ),
        )
        log.info("gateway_ready", servers=upstream.server_names(), api_port=port, policy=policy.version)

        gateway = FirewallMcpServer(
            upstream,
            container.interception,
            default_client_id=settings.client_id,
            tenant_id=settings.tenant_id,
        )
        server = await gateway.build()
        async with stdio_server() as (read_stream, write_stream):
            await server.run(read_stream, write_stream, gateway.initialization_options())
    finally:
        remove_gateway(settings.run_dir)
        if api_server is not None:
            api_server.should_exit = True
        if api_task is not None:
            with contextlib.suppress(asyncio.CancelledError, Exception):
                await asyncio.wait_for(api_task, 5)
        await container.stop()
        log.info("gateway_stopped")
