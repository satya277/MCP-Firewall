"""Authentication dependencies and request-level security helpers for the approval API."""

from __future__ import annotations

from fastapi import HTTPException, Request, status

from mcp_firewall.domain.entities.approval import Principal
from mcp_firewall.domain.enums.decision import Role
from mcp_firewall.infrastructure.security.authorization import RateLimiter

# Failed-auth throttle: protects the token space from online guessing.
_auth_failures = RateLimiter(rate_per_second=0.2, burst=10)


def client_ip(request_or_ws) -> str:
    client = request_or_ws.client
    return client.host if client else "unknown"


def bearer_token(request: Request) -> str | None:
    header = request.headers.get("authorization", "")
    scheme, _, value = header.partition(" ")
    return value.strip() if scheme.lower() == "bearer" and value else None


def authenticate(request: Request, token: str | None) -> Principal:
    ip = client_ip(request)
    if _auth_failures.blocked(f"fail:{ip}"):
        raise HTTPException(status.HTTP_429_TOO_MANY_REQUESTS, "too many failed authentication attempts")
    principal = request.app.state.container.approver_auth.authenticate(token)
    if principal is None:
        _auth_failures.allow(f"fail:{ip}")  # each failure consumes a token
        raise HTTPException(
            status.HTTP_401_UNAUTHORIZED,
            "invalid or missing credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return principal


def require(minimum: Role):
    async def dependency(request: Request) -> Principal:
        principal = authenticate(request, bearer_token(request))
        if not principal.can(minimum):
            raise HTTPException(status.HTTP_403_FORBIDDEN, f"requires role {minimum.name.lower()}")
        return principal

    return dependency


def ws_blocked(ip: str) -> bool:
    return _auth_failures.blocked(f"fail:{ip}")


def ws_failure(ip: str) -> None:
    _auth_failures.allow(f"fail:{ip}")


def reset_auth_throttle() -> None:
    """Test helper: clear failed-auth state."""
    _auth_failures._buckets.clear()
