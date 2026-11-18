"""Approval orchestration: one independent waiter, deadline and decision per request.

* The request is persisted *before* anyone is notified.
* Only one decision can win: the repository performs an atomic conditional update.
* A per-request ``asyncio.Future`` wakes the waiting task in this process; a periodic
  reconciliation against the repository also covers lost events and other workers.
* Anything unexpected resolves to "not approved" (fail closed).
"""

from __future__ import annotations

import asyncio
import contextlib
import time
from collections.abc import Awaitable, Callable

import structlog

from mcp_firewall.application.interfaces.approval_repository import RequestRepository
from mcp_firewall.application.interfaces.event_publisher import EventBus, EventType, FirewallEvent
from mcp_firewall.application.interfaces.upstream import MetricsPort, NullMetrics
from mcp_firewall.application.services.audit_service import AuditService
from mcp_firewall.application.services.views import record_view
from mcp_firewall.domain.entities.approval import ApprovalDecision, Principal
from mcp_firewall.domain.entities.audit import AuditEventType
from mcp_firewall.domain.entities.mcp_request import RequestRecord
from mcp_firewall.domain.enums.decision import Decision, Role
from mcp_firewall.domain.enums.request_status import RequestStatus
from mcp_firewall.domain.exceptions import (
    AlreadyDecidedError,
    ApprovalExpiredError,
    HashMismatchError,
    NotAuthorizedError,
    StrongConfirmationRequired,
    UnknownRequestError,
)

log = structlog.get_logger("approval")

Keepalive = Callable[[float], Awaitable[None]]
_DECIDED = frozenset({RequestStatus.APPROVED, RequestStatus.REJECTED})
_FINAL_WAIT = frozenset(
    {RequestStatus.APPROVED, RequestStatus.REJECTED, RequestStatus.EXPIRED, RequestStatus.CANCELLED}
)


class ApprovalService:
    def __init__(
        self,
        repo: RequestRepository,
        audit: AuditService,
        bus: EventBus,
        *,
        poll_interval: float = 2.0,
        keepalive_interval: float = 10.0,
        metrics: MetricsPort | None = None,
    ) -> None:
        self._repo = repo
        self._audit = audit
        self._bus = bus
        self._poll_interval = poll_interval
        self._keepalive_interval = keepalive_interval
        self._metrics = metrics or NullMetrics()
        self._waiters: dict[str, asyncio.Future[RequestStatus]] = {}
        self._listener: asyncio.Task[None] | None = None

    @property
    def pending_count(self) -> int:
        return len(self._waiters)

    # -- lifecycle -------------------------------------------------------------------------
    async def start(self) -> None:
        if self._listener is None:
            self._listener = asyncio.create_task(self._listen(), name="approval-listener")

    async def stop(self) -> None:
        if self._listener:
            self._listener.cancel()
            with contextlib.suppress(asyncio.CancelledError, Exception):
                await self._listener
            self._listener = None

    async def _listen(self) -> None:
        """Wake local waiters when a decision made by another worker/process arrives."""
        async for event in self._bus.subscribe():
            if event.type == EventType.APPROVAL_DECIDED and event.request_id:
                status = event.payload.get("status")
                if status in {s.value for s in _FINAL_WAIT}:
                    self._wake(event.request_id, RequestStatus(status))

    def _wake(self, request_id: str, status: RequestStatus) -> None:
        fut = self._waiters.get(request_id)
        if fut is not None and not fut.done():
            fut.set_result(status)

    # -- waiting side (gateway) ------------------------------------------------------------
    async def await_decision(
        self, record: RequestRecord, keepalive: Keepalive | None = None
    ) -> RequestStatus:
        """Block until this request is approved/rejected/expired/cancelled. Never raises on timeout."""
        loop = asyncio.get_running_loop()
        fut: asyncio.Future[RequestStatus] = loop.create_future()
        self._waiters[record.id] = fut
        self._metrics.pending_changed(1)
        started = time.monotonic()
        last_keepalive = started
        try:
            await self._publish_requested(record)
            while True:
                remaining = record.expires_at - time.time()
                if remaining <= 0:
                    return await self._expire(record)
                try:
                    status = await asyncio.wait_for(
                        asyncio.shield(fut), timeout=min(self._poll_interval, remaining)
                    )
                    return await self._confirm(record.id, status)
                except TimeoutError:
                    current = await self._repo.get(record.id)
                    if current is None:
                        return RequestStatus.CANCELLED
                    if current.status in _FINAL_WAIT:
                        return current.status
                    if current.status is not RequestStatus.PENDING_APPROVAL:
                        return current.status
                now = time.monotonic()
                if keepalive and now - last_keepalive >= self._keepalive_interval:
                    last_keepalive = now
                    with contextlib.suppress(Exception):
                        await keepalive(now - started)
        except asyncio.CancelledError:
            await asyncio.shield(self._cancel_pending(record.id, "client cancelled or disconnected"))
            raise
        finally:
            self._waiters.pop(record.id, None)
            self._metrics.pending_changed(-1)

    async def _confirm(self, request_id: str, hinted: RequestStatus) -> RequestStatus:
        """Trust the durable state, not the in-memory hint."""
        current = await self._repo.get(request_id)
        return current.status if current else RequestStatus.CANCELLED

    async def _publish_requested(self, record: RequestRecord) -> None:
        await self._audit.record(
            AuditEventType.APPROVAL_PROMPTED, record, actor="system", risk=record.risk.level.label
        )
        await self._bus.publish(
            FirewallEvent(
                type=EventType.APPROVAL_REQUESTED,
                request_id=record.id,
                tenant_id=record.request.tenant_id,
                payload=record_view(record),
            )
        )

    async def _expire(self, record: RequestRecord) -> RequestStatus:
        moved = await self._repo.transition(
            record.id, {RequestStatus.PENDING_APPROVAL}, RequestStatus.EXPIRED, outcome="approval timed out"
        )
        if moved is None:  # a decision slipped in at the deadline; honour durable state
            current = await self._repo.get(record.id)
            return current.status if current else RequestStatus.EXPIRED
        await self._audit.record(AuditEventType.REQUEST_EXPIRED, moved)
        await self._announce(moved)
        self._metrics.approval_latency(time.time() - record.created_at, "expired")
        return RequestStatus.EXPIRED

    async def _cancel_pending(self, request_id: str, reason: str) -> None:
        try:
            moved = await self._repo.transition(
                request_id, {RequestStatus.PENDING_APPROVAL}, RequestStatus.CANCELLED, outcome=reason
            )
            if moved:
                await self._audit.record(AuditEventType.REQUEST_CANCELLED, moved, reason=reason)
                await self._announce(moved)
        except Exception:
            log.exception("cancel_pending_failed", request_id=request_id)

    async def _announce(self, record: RequestRecord) -> None:
        with contextlib.suppress(Exception):
            await self._bus.publish(
                FirewallEvent(
                    type=EventType.APPROVAL_DECIDED,
                    request_id=record.id,
                    tenant_id=record.request.tenant_id,
                    payload={"status": record.status.value, "request": record_view(record)},
                )
            )

    # -- deciding side (approval API / UI) ---------------------------------------------------
    async def submit_decision(self, principal: Principal, decision: ApprovalDecision) -> RequestRecord:
        """Authorize, validate and atomically apply one decision. Raises ApprovalError subclasses."""
        record = await self._repo.get(decision.request_id)
        if record is None or not self._visible(principal, record):
            raise UnknownRequestError("unknown request")

        if not principal.can(Role.parse(record.approver_role)):
            await self._reject_attempt(record, principal, "insufficient_role")
            raise NotAuthorizedError("you are not allowed to decide this request")

        if decision.request_hash != record.request.request_hash:
            await self._reject_attempt(record, principal, "hash_mismatch")
            raise HashMismatchError("decision does not match the request that was displayed")

        if record.status is not RequestStatus.PENDING_APPROVAL:
            await self._reject_attempt(record, principal, f"late_or_duplicate:{record.status.value}")
            if record.status is RequestStatus.EXPIRED:
                raise ApprovalExpiredError("request has expired")
            raise AlreadyDecidedError(f"request is already {record.status.value}")

        if decision.decision is Decision.ALLOW and record.strong_confirmation and not decision.confirmed:
            raise StrongConfirmationRequired("this high-risk request needs explicit confirmation")

        now = time.time()
        if now >= record.expires_at:
            expired = await self._repo.transition(
                record.id,
                {RequestStatus.PENDING_APPROVAL},
                RequestStatus.EXPIRED,
                outcome="approval timed out",
            )
            if expired:
                await self._audit.record(AuditEventType.REQUEST_EXPIRED, expired)
                await self._announce(expired)
            await self._reject_attempt(record, principal, "late_decision")
            raise ApprovalExpiredError("request has expired")

        target = RequestStatus.APPROVED if decision.decision is Decision.ALLOW else RequestStatus.REJECTED
        updated = await self._repo.apply_decision(decision, target, now)
        if updated is None:
            await self._reject_attempt(record, principal, "lost_race")
            raise AlreadyDecidedError("request was decided or expired concurrently")

        await self._audit.record(
            AuditEventType.APPROVAL_DECIDED,
            updated,
            actor=principal.id,
            decision=decision.decision.value,
            reason=decision.reason,
        )
        self._metrics.approval_latency(now - record.created_at, decision.decision.value)
        await self._announce(updated)
        self._wake(updated.id, updated.status)
        return updated

    @staticmethod
    def _visible(principal: Principal, record: RequestRecord) -> bool:
        return principal.role is Role.ADMIN or principal.tenant_id == record.request.tenant_id

    async def _reject_attempt(self, record: RequestRecord, principal: Principal, why: str) -> None:
        self._metrics.security_event(f"decision_rejected:{why.split(':')[0]}")
        await self._audit.record(
            AuditEventType.APPROVAL_REJECTED_ATTEMPT, record, actor=principal.id, why=why
        )
