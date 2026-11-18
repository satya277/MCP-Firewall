"""Policy inspection/reload and the emergency kill switch."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel

from mcp_firewall.domain.entities.approval import Principal
from mcp_firewall.domain.enums.decision import Role
from mcp_firewall.interfaces.api.auth import require

router = APIRouter(prefix="/api/v1", tags=["policy"])


class KillSwitchBody(BaseModel):
    enabled: bool


@router.get("/policy")
async def get_policy(request: Request, principal: Principal = Depends(require(Role.VIEWER))):
    policy = request.app.state.container.policy_engine.policy
    return {
        "version": policy.version,
        "default_action": policy.default_action.value,
        "rules": [
            {
                "id": r.id, "action": r.action.value, "priority": r.priority, "servers": list(r.servers),
                "tools": list(r.tools), "description": r.description, "enabled": r.enabled,
                "conditions": len(r.conditions),
            }
            for r in policy.rules
        ],
    }  # fmt: skip


@router.post("/policy/reload")
async def reload_policy(request: Request, principal: Principal = Depends(require(Role.ADMIN))):
    try:
        version = await request.app.state.container.reload_policy(actor=principal.id)
    except Exception as exc:
        # The previously loaded policy stays active; do not echo parser internals.
        raise HTTPException(400, f"policy file is invalid: {type(exc).__name__}") from exc
    return {"version": version}


@router.get("/killswitch")
async def get_kill_switch(request: Request, principal: Principal = Depends(require(Role.VIEWER))):
    return {"enabled": await request.app.state.container.interception.is_kill_switch_on()}


@router.post("/killswitch")
async def set_kill_switch(
    body: KillSwitchBody, request: Request, principal: Principal = Depends(require(Role.ADMIN))
):
    container = request.app.state.container
    await container.set_kill_switch(body.enabled, principal.id)
    return {"enabled": body.enabled}
