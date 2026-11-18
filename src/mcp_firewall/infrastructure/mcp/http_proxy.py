"""Remote gateway: MCP over Streamable HTTP (Claude Web custom connector) + approval API + dashboard.

Claude Web ──HTTPS──> /mcp (bearer token, or secret path) ──> same interception pipeline as STDIO.
Approvers connect to /api/v1/ws (desktop agent or /dashboard) and decide via authenticated POSTs.
TLS is expected to be terminated in front of this process (reverse proxy / tunnel / load balancer).
"""

from __future__ import annotations

import hmac
from contextlib import asynccontextmanager
from pathlib import Path

import structlog
from fastapi import FastAPI
from mcp.server.streamable_http_manager import StreamableHTTPSessionManager
from mcp.server.transport_security import TransportSecuritySettings
from starlette.responses import JSONResponse
from starlette.routing import Route
from starlette.types import Receive, Scope, Send

from mcp_firewall.bootstrap import Container, build_container
from mcp_firewall.config import Settings, load_policy_file, load_servers
from mcp_firewall.infrastructure.mcp.client_manager import UpstreamManager
from mcp_firewall.infrastructure.mcp.server_manager import FirewallMcpServer, current_principal
from mcp_firewall.infrastructure.security.authorization import RateLimiter
from mcp_firewall.interfaces.api.app import create_app

log = structlog.get_logger("http-gateway")
MAX_MCP_BODY = 1_048_576


class McpEndpoint:
    """ASGI app guarding the Streamable HTTP transport with authentication and rate limiting."""

    def __init__(self, container: Container, settings: Settings) -> None:
        self._container = container
        self._secret = settings.mcp_path_secret
        self._limiter = RateLimiter(rate_per_second=20, burst=60)
        self._fail_limiter = RateLimiter(rate_per_second=0.2, burst=10)
        self.manager: StreamableHTTPSessionManager | None = None

    async def _reject(self, scope: Scope, receive: Receive, send: Send, status: int, msg: str) -> None:
        headers = {"WWW-Authenticate": "Bearer"} if status == 401 else None
        await JSONResponse({"error": msg}, status_code=status, headers=headers)(scope, receive, send)

    def _authenticate(self, scope: Scope):
        headers = dict(scope.get("headers") or [])
        auth = headers.get(b"authorization", b"").decode("latin-1")
        scheme, _, token = auth.partition(" ")
        if scheme.lower() == "bearer" and token:
            principal = self._container.client_auth.authenticate(token.strip())
            if principal is not None:
                return principal
        secret = (scope.get("path_params") or {}).get("secret")
        if self._secret and secret and hmac.compare_digest(secret.encode(), self._secret.encode()):
            from mcp_firewall.domain.entities.approval import Principal
            from mcp_firewall.domain.enums.decision import Role

            return Principal("claude-web-connector", Role.VIEWER, self._container.settings.tenant_id)
        return None

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http" or self.manager is None:
            return await self._reject(scope, receive, send, 404, "not found")
        ip = (scope.get("client") or ("unknown", 0))[0]
        if self._fail_limiter.blocked(f"mcp-fail:{ip}"):
            return await self._reject(scope, receive, send, 429, "too many failed attempts")
        principal = self._authenticate(scope)
        if principal is None:
            self._fail_limiter.allow(f"mcp-fail:{ip}")
            return await self._reject(scope, receive, send, 401, "unauthorized")
        if not self._limiter.allow(principal.id):
            return await self._reject(scope, receive, send, 429, "rate limited")
        length = dict(scope.get("headers") or []).get(b"content-length", b"0")
        if length.isdigit() and int(length) > MAX_MCP_BODY:
            return await self._reject(scope, receive, send, 413, "payload too large")
        token = current_principal.set(principal)
        try:
            await self.manager.handle_request(scope, receive, send)
        finally:
            current_principal.reset(token)


def create_remote_app(settings: Settings, servers_path: Path, policies_path: Path) -> FastAPI:
    if not (settings.mcp_client_tokens or settings.mcp_path_secret):
        raise RuntimeError("refusing to start: set MCPFW_MCP_CLIENT_TOKENS and/or MCPFW_MCP_PATH_SECRET")
    if not settings.approver_tokens:
        raise RuntimeError("refusing to start: set MCPFW_APPROVER_TOKENS (nobody could approve requests)")

    servers = load_servers(servers_path)
    policy = load_policy_file(policies_path)
    upstream = UpstreamManager(servers, settings.execution_timeout_seconds + 5)
    container = build_container(settings, policy=policy, upstream=upstream, policies_file=policies_path)
    endpoint = McpEndpoint(container, settings)

    @asynccontextmanager
    async def mcp_lifespan(app: FastAPI):
        gateway = FirewallMcpServer(
            upstream, container.interception, default_client_id="claude-web", tenant_id=settings.tenant_id
        )
        server = await gateway.build()
        hosts = settings.allowed_hosts or ["127.0.0.1:*", "localhost:*"]
        security = TransportSecuritySettings(
            enable_dns_rebinding_protection=True,
            allowed_hosts=[h if ":" in h or h.endswith("*") else f"{h}:*" for h in hosts] + hosts,
            allowed_origins=settings.allowed_origins or ["http://127.0.0.1:*", "http://localhost:*"],
        )
        # Stateless: any gateway instance can serve any request; durable state lives in the database.
        manager = StreamableHTTPSessionManager(
            server, json_response=False, stateless=True, security_settings=security
        )
        endpoint.manager = manager
        async with manager.run():
            log.info("remote_gateway_ready", servers=upstream.server_names(), policy=policy.version)
            yield

    app = create_app(container, manage_lifecycle=True, lifespan_hook=mcp_lifespan)
    app.router.routes.append(Route("/mcp", endpoint=endpoint))
    app.router.routes.append(Route("/mcp/{secret}", endpoint=endpoint))
    return app
