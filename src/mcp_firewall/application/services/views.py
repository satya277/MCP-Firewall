"""Serializable, sanitized views of a request for the approval UI / API / events."""

from __future__ import annotations

from typing import Any

from mcp_firewall.domain.entities.mcp_request import RequestRecord


def record_view(record: RequestRecord) -> dict[str, Any]:
    req = record.request
    return {
        "id": record.id,
        "status": record.status.value,
        "operation": req.operation,
        "client": req.client_id,
        "tenant_id": req.tenant_id,
        "server": req.server,
        "tool": req.tool,
        "description": record.description[:500],  # untrusted metadata, display only
        "arguments": record.display_arguments,
        "request_hash": req.request_hash,
        "risk": {"level": record.risk.level.label, "reasons": list(record.risk.reasons)},
        "strong_confirmation": record.strong_confirmation,
        "approver_role": record.approver_role,
        "schema_changed": record.schema_changed,
        "policy": {
            "action": record.policy_action.value if record.policy_action else None,
            "rule": record.matched_rule_id,
            "version": record.policy_version,
        },
        "created_at": record.created_at,
        "expires_at": record.expires_at,
        "decided_by": record.decided_by,
        "decided_at": record.decided_at,
        "decision_reason": record.decision_reason,
        "outcome": record.outcome,
    }
