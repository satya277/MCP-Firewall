"""Audit event entity (tamper-evident hash chain is applied by the audit adapter)."""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any
from uuid import uuid4


class AuditEventType:
    REQUEST_RECEIVED = "request.received"
    REQUEST_VALIDATED = "request.validated"
    REQUEST_DENIED = "request.denied"
    POLICY_EVALUATED = "policy.evaluated"
    APPROVAL_PROMPTED = "approval.prompted"
    APPROVAL_DECIDED = "approval.decided"
    APPROVAL_REJECTED_ATTEMPT = "approval.attempt_rejected"
    REQUEST_EXPIRED = "request.expired"
    REQUEST_CANCELLED = "request.cancelled"
    EXECUTION_STARTED = "execution.started"
    EXECUTION_FINISHED = "execution.finished"
    EXECUTION_FAILED = "execution.failed"
    EXECUTION_UNKNOWN = "execution.unknown"
    INTEGRITY_VIOLATION = "security.integrity_violation"
    KILL_SWITCH = "security.kill_switch"
    TOOL_SCHEMA_CHANGED = "security.tool_schema_changed"
    POLICY_RELOADED = "policy.reloaded"
    GATEWAY_STARTED = "gateway.started"
    GATEWAY_STOPPED = "gateway.stopped"


@dataclass(frozen=True, slots=True)
class AuditEvent:
    event_type: str
    tenant_id: str = "default"
    request_id: str | None = None
    actor_id: str = "system"
    metadata: dict[str, Any] = field(default_factory=dict)
    id: str = field(default_factory=lambda: str(uuid4()))
    timestamp: float = field(default_factory=time.time)
    seq: int = 0
    prev_hash: str = ""
    hash: str = ""
