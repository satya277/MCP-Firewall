"""FastAPI application factory for the approval API (+ dashboard), shared by local and remote modes."""

from __future__ import annotations

from contextlib import asynccontextmanager
from pathlib import Path

import structlog
from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse
from starlette.middleware.trustedhost import TrustedHostMiddleware
from starlette.types import ASGIApp, Receive, Scope, Send

from mcp_firewall.bootstrap import Container
from mcp_firewall.interfaces.api.routes import approvals, health, policies, requests
from mcp_firewall.interfaces.api.websocket import ConnectionRegistry, origin_allowed
from mcp_firewall.interfaces.api.websocket import router as ws_router

log = structlog.get_logger("api")
STATIC = Path(__file__).parent / "static"
MAX_BODY = 64 * 1024
_SECURITY_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Cache-Control": "no-store",
}
_DASHBOARD_CSP = (
    "default-src 'none'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; "
    "connect-src 'self' ws: wss:; img-src 'self' data:; base-uri 'none'; form-action 'none'; frame-ancestors 'none'"
)


class SecurityHeadersMiddleware:
    """Pure-ASGI (not BaseHTTPMiddleware) so streaming responses and client-disconnect detection keep working.

    Enforces: body-size cap on /api, Origin check on state-changing requests, and security headers.
    """

    def __init__(self, app: ASGIApp, allowed_origins: list[str]) -> None:
        self.app = app
        self._allowed_origins = allowed_origins

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        headers = {k.decode("latin-1").lower(): v.decode("latin-1") for k, v in scope.get("headers", [])}
        path = scope.get("path", "")
        length = headers.get("content-length", "")
        if path.startswith("/api/") and length.isdigit() and int(length) > MAX_BODY:
            await JSONResponse({"error": "payload_too_large"}, status_code=413)(scope, receive, send)
            return
        if scope["method"] not in ("GET", "HEAD", "OPTIONS") and not origin_allowed(
            headers.get("origin"), headers.get("host"), self._allowed_origins
        ):
            await JSONResponse({"error": "origin_not_allowed"}, status_code=403)(scope, receive, send)
            return

        async def send_with_headers(message) -> None:
            if message["type"] == "http.response.start":
                existing = {k.lower() for k, _ in message.get("headers", [])}
                extra = [(k.lower().encode(), v.encode()) for k, v in _SECURITY_HEADERS.items()]
                message["headers"] = list(message.get("headers", [])) + [
                    h for h in extra if h[0] not in existing
                ]
                if path.startswith("/dashboard"):
                    message["headers"].append((b"content-security-policy", _DASHBOARD_CSP.encode()))
            await send(message)

        await self.app(scope, receive, send_with_headers)


def create_app(
    container: Container,
    *,
    manage_lifecycle: bool = False,
    allowed_hosts: list[str] | None = None,
    connections: ConnectionRegistry | None = None,
    lifespan_hook=None,
) -> FastAPI:
    @asynccontextmanager
    async def lifespan(app: FastAPI):
        if manage_lifecycle:
            await container.start()
        try:
            if lifespan_hook is not None:
                async with lifespan_hook(app):
                    yield
            else:
                yield
        finally:
            if manage_lifecycle:
                await container.stop()

    app = FastAPI(
        title="MCP Firewall approval API",
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
        lifespan=lifespan,
    )
    app.state.container = container
    app.state.connections = connections or ConnectionRegistry()

    hosts = allowed_hosts or container.settings.allowed_hosts or ["127.0.0.1", "localhost"]
    app.add_middleware(SecurityHeadersMiddleware, allowed_origins=container.settings.allowed_origins)
    app.add_middleware(TrustedHostMiddleware, allowed_hosts=hosts)

    async def unhandled(request: Request, exc: Exception):
        log.exception("unhandled_api_error", path=request.url.path)
        return JSONResponse({"error": "internal_error"}, status_code=500)

    app.include_router(health.router)
    app.include_router(requests.router)
    app.include_router(approvals.router)
    app.include_router(policies.router)
    app.include_router(ws_router)

    @app.get("/dashboard", response_class=HTMLResponse, include_in_schema=False)
    async def dashboard() -> HTMLResponse:
        return HTMLResponse((STATIC / "dashboard.html").read_text(encoding="utf-8"))

    return app
