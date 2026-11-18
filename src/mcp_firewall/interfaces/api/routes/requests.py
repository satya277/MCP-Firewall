"""Read endpoints for requests and the audit trail."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query, Request

from mcp_firewall.application.services.views import record_view
from mcp_firewall.domain.entities.approval import Principal
from mcp_firewall.domain.enums.decision import Role
from mcp_firewall.domain.enums.request_status import RequestStatus
from mcp_firewall.interfaces.api.auth import require

router = APIRouter(prefix="/api/v1", tags=["requests"])


def _tenant_filter(principal: Principal) -> str | None:
    return None if principal.role is Role.ADMIN else principal.tenant_id


@router.get("/requests")
async def list_requests(
    request: Request,
    status: str = Query("pending", pattern=r"^[A-Za-z_]{1,24}$"),
    limit: int = Query(100, ge=1, le=500),
    principal: Principal = Depends(require(Role.VIEWER)),
):
    container = request.app.state.container
    statuses: set[RequestStatus] | None
    if status == "pending":
        statuses = {RequestStatus.PENDING_APPROVAL}
    elif status == "all":
        statuses = None
    else:
        try:
            statuses = {RequestStatus(status.upper())}
        except ValueError:
            raise HTTPException(400, "unknown status") from None
    records = await container.repo.list_requests(
        statuses=statuses, tenant_id=_tenant_filter(principal), limit=limit
    )
    return {"requests": [record_view(r) for r in records]}


@router.get("/requests/{request_id}")
async def get_request(
    request_id: str, request: Request, principal: Principal = Depends(require(Role.VIEWER))
):
    container = request.app.state.container
    record = await container.repo.get(request_id)
    tenant = _tenant_filter(principal)
    if record is None or (tenant and record.request.tenant_id != tenant):
        raise HTTPException(404, "unknown request")
    return record_view(record)


@router.get("/audit")
async def audit(
    request: Request,
    request_id: str | None = Query(None, max_length=64),
    after_seq: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=500),
    principal: Principal = Depends(require(Role.VIEWER)),
):
    container = request.app.state.container
    events = await container.audit_log.list_events(request_id=request_id, after_seq=after_seq, limit=limit)
    tenant = _tenant_filter(principal)
    return {
        "events": [
            {
                "seq": e.seq,
                "id": e.id,
                "ts": e.timestamp,
                "type": e.event_type,
                "request_id": e.request_id,
                "actor": e.actor_id,
                "metadata": e.metadata,
                "hash": e.hash,
            }
            for e in events
            if tenant is None or e.tenant_id == tenant
        ]  # fmt: skip
    }


@router.get("/audit/verify")
async def verify_audit(request: Request, principal: Principal = Depends(require(Role.ADMIN))):
    ok, checked, error = await request.app.state.container.audit_log.verify_chain()
    return {"ok": ok, "checked": checked, "error": error}
