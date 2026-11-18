"""Interception service: the orchestrated workflow from the architecture document (section 7).

receive -> validate -> freeze+hash -> persist -> policy -> (deny | allow | wait for human)
        -> verify hash -> dispatch exact args -> record outcome

Every unexpected failure on this path resolves to "not executed" (fail closed).
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import time
from dataclasses import dataclass, field
from typing import Any

import structlog
from jsonschema.exceptions import SchemaError
from jsonschema.validators import validator_for

from mcp_firewall.application.interfaces.approval_repository import (
    RequestRepository,
    SettingsRepository,
    ToolRegistryRepository,
)
from mcp_firewall.application.interfaces.event_publisher import EventBus, EventType, FirewallEvent
from mcp_firewall.application.interfaces.upstream import (
    ApproverNotifier,
    MetricsPort,
    NullMetrics,
    NullNotifier,
    Sanitizer,
    UpstreamResult,
)
from mcp_firewall.application.services.approval_service import ApprovalService, Keepalive
from mcp_firewall.application.services.audit_service import AuditService
from mcp_firewall.application.services.execution_service import ExecutionService
from mcp_firewall.application.services.policy_service import PolicyEngine, assess_risk
from mcp_firewall.application.services.views import record_view
from mcp_firewall.domain.entities.audit import AuditEventType
from mcp_firewall.domain.entities.mcp_request import McpRequest, RequestRecord, RiskAssessment
from mcp_firewall.domain.enums.decision import PolicyAction
from mcp_firewall.domain.enums.request_status import OPEN_STATES, RequestStatus
from mcp_firewall.domain.exceptions import FirewallError, InvalidRequestError

log = structlog.get_logger("interception")

KILL_SWITCH_KEY = "kill_switch"
_MAX_DISPLAY_CHARS = 20_000
_MAX_DISPLAY_STRING = 4_000


@dataclass(frozen=True, slots=True)
class IncomingCall:
    operation: str
    client_id: str
    server: str
    tool: str
    arguments: dict[str, Any] | None
    tenant_id: str = "default"
    user_id: str = "local"
    description: str = ""
    input_schema: dict[str, Any] | None = None
    fingerprint: str | None = None
    keepalive: Keepalive | None = None


@dataclass(slots=True)
class InterceptionOutcome:
    status: RequestStatus
    request_id: str | None
    message: str = ""
    result: UpstreamResult | None = None
    extra: dict[str, Any] = field(default_factory=dict)

    @property
    def executed(self) -> bool:
        return self.result is not None


@dataclass(frozen=True, slots=True)
class InterceptionConfig:
    approval_timeout: float = 60.0
    max_pending: int = 100
    max_argument_bytes: int = 262_144
    owner_id: str = "gateway"


class _CallContext:
    """Per-call scratch state so cleanup after cancellation/errors can find the live request."""

    __slots__ = ("request_id",)

    def __init__(self) -> None:
        self.request_id: str | None = None


class InterceptionService:
    def __init__(
        self,
        *,
        repo: RequestRepository,
        settings: SettingsRepository,
        tools: ToolRegistryRepository,
        audit: AuditService,
        policy: PolicyEngine,
        approvals: ApprovalService,
        executor: ExecutionService,
        sanitizer: Sanitizer,
        bus: EventBus,
        config: InterceptionConfig | None = None,
        notifier: ApproverNotifier | None = None,
        metrics: MetricsPort | None = None,
    ) -> None:
        self._repo = repo
        self._settings = settings
        self._tools = tools
        self._audit = audit
        self._policy = policy
        self._approvals = approvals
        self._executor = executor
        self._sanitizer = sanitizer
        self._bus = bus
        self._cfg = config or InterceptionConfig()
        self._notifier = notifier or NullNotifier()
        self._metrics = metrics or NullMetrics()
        self._inflight = 0

    async def is_kill_switch_on(self) -> bool:
        return (await self._settings.get_setting(KILL_SWITCH_KEY)) == "1"

    # ------------------------------------------------------------------------------------
    async def intercept(self, call: IncomingCall) -> InterceptionOutcome:
        ctx = _CallContext()
        try:
            return await self._run(call, ctx)
        except asyncio.CancelledError:
            await asyncio.shield(self._abandon(ctx, "client cancelled or disconnected", cancelled=True))
            raise
        except InvalidRequestError as exc:
            await self._audit.record_safely(
                AuditEventType.REQUEST_DENIED, None, reason=str(exc), server=call.server, tool=call.tool
            )
            self._metrics.request_finished(RequestStatus.DENIED.value, call.operation)
            return InterceptionOutcome(RequestStatus.DENIED, None, f"malformed request: {exc}")
        except Exception as exc:
            log.exception("interception_failed", server=call.server, tool=call.tool)
            await self._abandon(ctx, f"internal error: {type(exc).__name__}")
            self._metrics.request_finished(RequestStatus.DENIED.value, call.operation)
            return InterceptionOutcome(
                RequestStatus.DENIED, ctx.request_id, "internal error; request was not executed"
            )

    async def _run(self, call: IncomingCall, ctx: _CallContext) -> InterceptionOutcome:
        if self._approvals.pending_count + self._inflight >= self._cfg.max_pending:
            await self._audit.record_safely(
                AuditEventType.REQUEST_DENIED, None, reason="pending queue full", tool=call.tool
            )
            self._metrics.security_event("queue_full")
            return InterceptionOutcome(
                RequestStatus.DENIED, None, "too many requests are pending; try again later"
            )

        request = McpRequest.create(
            operation=call.operation,
            client_id=call.client_id,
            server=call.server,
            tool=call.tool,
            arguments=call.arguments,
            tenant_id=call.tenant_id,
            user_id=call.user_id,
            max_argument_bytes=self._cfg.max_argument_bytes,
        )
        now = time.time()
        record = RequestRecord(
            request=request,
            created_at=now,
            expires_at=now + self._cfg.approval_timeout,
            owner_id=self._cfg.owner_id,
            display_arguments=self._display(request),
            description=self._sanitizer.redact_text(call.description or ""),
        )
        self._inflight += 1
        try:
            await self._repo.create(record)  # persisted BEFORE anyone is notified
            ctx.request_id = record.id
            await self._audit.record(AuditEventType.REQUEST_RECEIVED, record)
            return await self._process(call, record)
        finally:
            self._inflight -= 1

    async def _process(self, call: IncomingCall, record: RequestRecord) -> InterceptionOutcome:
        if await self.is_kill_switch_on():
            return await self._deny(record, "kill switch is engaged", AuditEventType.KILL_SWITCH)

        error = self._validate_schema(record.request, call.input_schema)
        if error:
            return await self._deny(record, f"arguments do not match the tool schema: {error}")
        moved = await self._repo.transition(record.id, {RequestStatus.RECEIVED}, RequestStatus.VALIDATED)
        if moved is None:
            return InterceptionOutcome(RequestStatus.CANCELLED, record.id, "request was cancelled")
        record.status = RequestStatus.VALIDATED
        await self._audit.record(AuditEventType.REQUEST_VALIDATED, record)

        decision = self._policy.evaluate(record.request)
        level, reasons = assess_risk(record.request)
        if decision.risk is not None:
            level = decision.risk
        schema_changed = False
        if call.fingerprint is not None:
            schema_changed = await self._schema_changed(call)
        action, strong = decision.action, decision.strong_confirmation
        if schema_changed and action is not PolicyAction.DENY:
            action, strong = PolicyAction.REQUIRE_APPROVAL, True
            reasons.append("The tool definition changed since it was last trusted")
        record.policy_action = action
        record.matched_rule_id = decision.rule_id
        record.policy_version = decision.policy_version
        record.risk = RiskAssessment(level, reasons)
        record.strong_confirmation = strong
        record.approver_role = decision.approver_role
        record.schema_changed = schema_changed
        await self._audit.record(
            AuditEventType.POLICY_EVALUATED,
            record,
            action=action.value,
            reason=decision.reason,
            matched=list(decision.matched),
        )

        if action is PolicyAction.DENY:
            return await self._deny(
                record, f"denied by policy ({decision.reason})", extra_fields=record_policy(record)
            )

        if action is PolicyAction.ALLOW:
            actor = f"policy:{decision.rule_id or 'default'}"
            moved = await self._repo.transition(
                record.id,
                {RequestStatus.VALIDATED},
                RequestStatus.APPROVED,
                decided_by=actor,
                decided_at=time.time(),
                **record_policy(record),
            )
            if moved is None:
                return InterceptionOutcome(RequestStatus.CANCELLED, record.id, "request was cancelled")
            record.status = RequestStatus.APPROVED
            return await self._execute(record)

        moved = await self._repo.transition(
            record.id, {RequestStatus.VALIDATED}, RequestStatus.PENDING_APPROVAL, **record_policy(record)
        )
        if moved is None:
            return InterceptionOutcome(RequestStatus.CANCELLED, record.id, "request was cancelled")
        record.status = RequestStatus.PENDING_APPROVAL
        await self._notifier.ensure_approver()
        final = await self._approvals.await_decision(record, call.keepalive)
        if final is not RequestStatus.APPROVED:
            return await self._finish_unapproved(record, final)
        if schema_changed and call.fingerprint is not None:
            await self._tools.acknowledge_tool(
                server=call.server, tool=call.tool, fingerprint=call.fingerprint
            )
        refreshed = await self._repo.get(record.id)
        return await self._execute(refreshed or record)

    async def _execute(self, record: RequestRecord) -> InterceptionOutcome:
        result = await self._executor.execute(record)
        self._metrics.request_finished(result.status.value, record.request.operation)
        await self._announce(record.id)
        if result.status is RequestStatus.COMPLETED and result.result is not None:
            return InterceptionOutcome(result.status, record.id, "", result.result)
        return InterceptionOutcome(result.status, record.id, result.message or "execution did not complete")

    async def _finish_unapproved(self, record: RequestRecord, final: RequestStatus) -> InterceptionOutcome:
        self._metrics.request_finished(final.value, record.request.operation)
        current = await self._repo.get(record.id)
        reason = (current.decision_reason if current else None) or ""
        messages = {
            RequestStatus.REJECTED: "the user blocked this request",
            RequestStatus.EXPIRED: "no approval was given in time",
            RequestStatus.CANCELLED: "the request was cancelled",
        }
        msg = messages.get(final, f"request ended in state {final.value}")
        if reason and final is RequestStatus.REJECTED:
            msg += f" ({reason})"
        return InterceptionOutcome(final, record.id, msg)

    async def _deny(
        self,
        record: RequestRecord,
        reason: str,
        event: str = AuditEventType.REQUEST_DENIED,
        extra_fields: dict[str, Any] | None = None,
    ) -> InterceptionOutcome:
        await self._repo.transition(
            record.id, set(OPEN_STATES), RequestStatus.DENIED, outcome=reason[:500], **(extra_fields or {})
        )
        record.status = RequestStatus.DENIED
        await self._audit.record(event, record, reason=reason)
        self._metrics.request_finished(RequestStatus.DENIED.value, record.request.operation)
        await self._announce(record.id)
        return InterceptionOutcome(RequestStatus.DENIED, record.id, reason)

    async def _announce(self, request_id: str) -> None:
        with contextlib.suppress(Exception):
            current = await self._repo.get(request_id)
            if current:
                await self._bus.publish(
                    FirewallEvent(
                        type=EventType.REQUEST_UPDATED,
                        request_id=request_id,
                        tenant_id=current.request.tenant_id,
                        payload=record_view(current),
                    )
                )

    async def _abandon(self, ctx: _CallContext, reason: str, cancelled: bool = False) -> None:
        """Move any still-open request of this call to a terminal state."""
        request_id = ctx.request_id
        if request_id is None:
            return
        target = RequestStatus.CANCELLED if cancelled else RequestStatus.DENIED
        with contextlib.suppress(Exception):
            moved = await self._repo.transition(request_id, set(OPEN_STATES), target, outcome=reason)
            if moved:
                await self._audit.record_safely(
                    AuditEventType.REQUEST_CANCELLED if cancelled else AuditEventType.REQUEST_DENIED,
                    moved,
                    reason=reason,
                )

    # ------------------------------------------------------------------------------------
    def _display(self, request: McpRequest) -> str:
        safe = self._sanitizer.sanitize(request.arguments)
        text = json.dumps(safe, indent=2, ensure_ascii=False, sort_keys=True)
        if len(text) > _MAX_DISPLAY_CHARS:
            text = text[:_MAX_DISPLAY_CHARS] + f"\n... [display truncated; {len(text)} characters total]"
        return text

    @staticmethod
    def _validate_schema(request: McpRequest, schema: dict[str, Any] | None) -> str | None:
        if not schema:
            return None
        try:
            validator = validator_for(schema)(schema)
        except SchemaError:
            log.warning("invalid_upstream_schema", tool=request.tool)
            return None
        errors = sorted(validator.iter_errors(request.arguments), key=lambda e: list(e.path))
        return errors[0].message[:300] if errors else None

    async def _schema_changed(self, call: IncomingCall) -> bool:
        if call.fingerprint is None:
            return False
        result = await self._tools.observe_tool(
            server=call.server, tool=call.tool, fingerprint=call.fingerprint, description=call.description
        )
        return result.changed

    async def sweep(self, execution_grace: float = 30.0) -> int:
        """Reaper: expire abandoned requests / mark stuck executions unknown. Safe to run often."""
        reaped = await self._repo.reap_expired(time.time(), execution_grace)
        for item in reaped:
            await self._audit.record_safely(
                AuditEventType.REQUEST_EXPIRED
                if item.current is RequestStatus.EXPIRED
                else AuditEventType.EXECUTION_UNKNOWN,
                None,
                request_id_ref=item.id,
                previous=item.previous.value,
                current=item.current.value,
                reaped=True,
            )
            await self._announce(item.id)
        return len(reaped)


def record_policy(record: RequestRecord) -> dict[str, Any]:
    """Policy-derived columns persisted alongside the status transition."""
    return {
        "policy_action": record.policy_action.value if record.policy_action else None,
        "matched_rule_id": record.matched_rule_id,
        "policy_version": record.policy_version,
        "risk_level": record.risk.level.value,
        "risk_reasons": json.dumps(record.risk.reasons),
        "strong_confirmation": int(record.strong_confirmation),
        "approver_role": record.approver_role,
        "schema_changed": int(record.schema_changed),
    }


__all__ = [
    "IncomingCall",
    "InterceptionConfig",
    "InterceptionOutcome",
    "InterceptionService",
    "FirewallError",
]
