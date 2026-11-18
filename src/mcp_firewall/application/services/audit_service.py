"""Thin wrapper that writes audit events for a request, with metadata sanitized."""

from __future__ import annotations

from typing import Any

import structlog

from mcp_firewall.application.interfaces.approval_repository import AuditLog
from mcp_firewall.application.interfaces.upstream import Sanitizer
from mcp_firewall.domain.entities.audit import AuditEvent
from mcp_firewall.domain.entities.mcp_request import RequestRecord

log = structlog.get_logger("audit")


class AuditService:
    def __init__(self, log_store: AuditLog, sanitizer: Sanitizer) -> None:
        self._store = log_store
        self._sanitizer = sanitizer

    async def record(
        self, event_type: str, record: RequestRecord | None = None, *, actor: str = "system", **metadata: Any
    ) -> AuditEvent:
        meta = dict(metadata)
        tenant = "default"
        if record is not None:
            tenant = record.request.tenant_id
            meta.update(
                server=record.request.server,
                tool=record.request.tool,
                operation=record.request.operation,
                client=record.request.client_id,
                request_hash=record.request.request_hash,
                status=record.status.value,
            )
            if record.matched_rule_id:
                meta.setdefault("rule", record.matched_rule_id)
            if record.policy_version:
                meta.setdefault("policy_version", record.policy_version)
        event = AuditEvent(
            event_type=event_type,
            tenant_id=tenant,
            request_id=record.id if record else None,
            actor_id=actor,
            metadata=self._sanitizer.sanitize(meta),
        )
        return await self._store.append(event)

    async def record_safely(self, *args: Any, **kwargs: Any) -> None:
        """For paths that must not fail because auditing did (e.g. cleanup)."""
        try:
            await self.record(*args, **kwargs)
        except Exception:
            log.exception("audit_write_failed")
