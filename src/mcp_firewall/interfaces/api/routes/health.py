"""Liveness, readiness, status and metrics endpoints."""

from __future__ import annotations

from fastapi import APIRouter, Depends, Request, Response
from fastapi.responses import JSONResponse

from mcp_firewall.domain.entities.approval import Principal
from mcp_firewall.domain.enums.decision import Role
from mcp_firewall.domain.enums.request_status import RequestStatus
from mcp_firewall.interfaces.api.auth import require

router = APIRouter(tags=["health"])


@router.get("/healthz")
async def healthz():
    return {"status": "ok"}


@router.get("/readyz")
async def readyz(request: Request):
    container = request.app.state.container
    db_ok = await container.db.ping()
    upstream = container.upstream.health() if container.upstream else {}
    ready = db_ok
    body = {"database": db_ok, "upstreams": {n: h["connected"] for n, h in upstream.items()}}
    return JSONResponse({"ready": ready, **body}, status_code=200 if ready else 503)


@router.get("/api/v1/me")
async def me(principal: Principal = Depends(require(Role.VIEWER))):
    return {"id": principal.id, "role": principal.role.name.lower(), "tenant_id": principal.tenant_id}


@router.get("/api/v1/status")
async def status(request: Request, principal: Principal = Depends(require(Role.VIEWER))):
    container = request.app.state.container
    pending = await container.repo.count_in_states({RequestStatus.PENDING_APPROVAL})
    registry = request.app.state.connections
    return {
        "pending": pending,
        "approvers_connected": registry.count(),
        "kill_switch": await container.interception.is_kill_switch_on(),
        "policy_version": container.policy_engine.policy.version,
        "upstreams": container.upstream.health() if container.upstream else {},
    }


@router.get("/metrics")
async def metrics(request: Request, principal: Principal = Depends(require(Role.VIEWER))):
    return Response(request.app.state.container.metrics.render(), media_type="text/plain; version=0.0.4")
