"""Approval endpoints: submit one authenticated, request-bound decision."""

from __future__ import annotations

from typing import Literal

from fastapi import APIRouter, Depends, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

from mcp_firewall.application.services.views import record_view
from mcp_firewall.domain.entities.approval import Principal
from mcp_firewall.domain.enums.decision import Role
from mcp_firewall.domain.exceptions import ApprovalError
from mcp_firewall.infrastructure.security.authorization import RateLimiter
from mcp_firewall.interfaces.api.auth import require

router = APIRouter(prefix="/api/v1", tags=["approvals"])
_decision_limiter = RateLimiter(rate_per_second=20, burst=60)

STATUS_FOR_CODE = {
    "unknown_request": 404,
    "already_decided": 409,
    "expired": 410,
    "hash_mismatch": 409,
    "not_authorized": 403,
    "strong_confirmation_required": 428,
}


class DecisionBody(BaseModel):
    decision: Literal["allow", "block"]
    request_hash: str = Field(min_length=64, max_length=64, pattern=r"^[0-9a-f]{64}$")
    confirm: bool = False
    reason: str | None = Field(default=None, max_length=500)


@router.post("/requests/{request_id}/decision")
async def decide(
    request_id: str,
    body: DecisionBody,
    request: Request,
    principal: Principal = Depends(require(Role.APPROVER)),
):
    if not _decision_limiter.allow(principal.id):
        return JSONResponse({"error": "rate_limited", "message": "too many decisions"}, status_code=429)
    container = request.app.state.container
    try:
        if body.decision == "allow":
            record = await container.approve(
                principal, request_id, body.request_hash, confirmed=body.confirm, reason=body.reason
            )
        else:
            record = await container.reject(principal, request_id, body.request_hash, reason=body.reason)
    except ApprovalError as exc:
        return JSONResponse(
            {"error": exc.code, "message": str(exc)}, status_code=STATUS_FOR_CODE.get(exc.code, 400)
        )
    return {"status": record.status.value, "request": record_view(record)}


def reset_decision_limiter() -> None:
    _decision_limiter._buckets.clear()
