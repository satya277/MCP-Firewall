"""Use cases: a human approves or blocks one pending request."""

from __future__ import annotations

from mcp_firewall.application.services.approval_service import ApprovalService
from mcp_firewall.domain.entities.approval import ApprovalDecision, Principal
from mcp_firewall.domain.entities.mcp_request import RequestRecord
from mcp_firewall.domain.enums.decision import Decision


class ApproveRequest:
    def __init__(self, approvals: ApprovalService) -> None:
        self._approvals = approvals

    async def __call__(
        self,
        principal: Principal,
        request_id: str,
        request_hash: str,
        *,
        confirmed: bool = False,
        reason: str | None = None,
    ) -> RequestRecord:
        decision = ApprovalDecision(
            request_id=request_id,
            decision=Decision.ALLOW,
            decided_by=principal.id,
            request_hash=request_hash,
            reason=reason,
            confirmed=confirmed,
        )
        return await self._approvals.submit_decision(principal, decision)
