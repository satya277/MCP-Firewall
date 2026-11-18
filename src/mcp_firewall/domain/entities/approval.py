"""Approval decision and authenticated principal entities."""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from uuid import uuid4

from mcp_firewall.domain.enums.decision import Decision, Role


@dataclass(frozen=True, slots=True)
class Principal:
    """An authenticated actor (approver, admin, viewer, or an MCP client)."""

    id: str
    role: Role
    tenant_id: str = "default"
    email: str = ""

    def can(self, minimum: Role) -> bool:
        return self.role >= minimum


@dataclass(frozen=True, slots=True)
class ApprovalDecision:
    """One verdict, bound to a request id and the canonical hash the approver was shown."""

    request_id: str
    decision: Decision
    decided_by: str
    request_hash: str
    reason: str | None = None
    confirmed: bool = False  # explicit extra confirmation for high-risk requests
    id: str = field(default_factory=lambda: str(uuid4()))
    decided_at: float = field(default_factory=time.time)
