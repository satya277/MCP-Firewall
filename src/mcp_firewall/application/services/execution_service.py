"""Execution dispatcher: forwards only the exact, hash-verified, approved request upstream."""

from __future__ import annotations

import asyncio
import contextlib
from collections import defaultdict

import structlog

from mcp_firewall.application.interfaces.approval_repository import RequestRepository
from mcp_firewall.application.interfaces.upstream import UpstreamGateway, UpstreamResult
from mcp_firewall.application.services.audit_service import AuditService
from mcp_firewall.domain.entities.audit import AuditEventType
from mcp_firewall.domain.entities.mcp_request import RequestRecord
from mcp_firewall.domain.enums.request_status import RequestStatus
from mcp_firewall.domain.exceptions import (
    FirewallError,
    IntegrityError,
    KillSwitchActive,
    UpstreamCommunicationError,
    UpstreamTimeoutError,
    UpstreamUnavailableError,
)

log = structlog.get_logger("execution")


class ExecutionResult:
    __slots__ = ("message", "result", "status")

    def __init__(
        self, status: RequestStatus, result: UpstreamResult | None = None, message: str = ""
    ) -> None:
        self.status = status
        self.result = result
        self.message = message


class ExecutionService:
    def __init__(
        self,
        repo: RequestRepository,
        upstream: UpstreamGateway,
        audit: AuditService,
        *,
        execution_timeout: float = 120.0,
        max_concurrent_per_server: int = 8,
        kill_switch_check=None,
    ) -> None:
        self._repo = repo
        self._upstream = upstream
        self._audit = audit
        self._timeout = execution_timeout
        self._limit = max_concurrent_per_server
        self._semaphores: dict[str, asyncio.Semaphore] = defaultdict(lambda: asyncio.Semaphore(self._limit))
        self._kill_switch_check = kill_switch_check

    async def execute(self, record: RequestRecord) -> ExecutionResult:
        request = record.request
        try:
            request.verify_integrity()
            if self._kill_switch_check is not None and await self._kill_switch_check():
                raise KillSwitchActive("kill switch engaged")
        except IntegrityError:
            await self._finish(
                record, RequestStatus.FAILED, AuditEventType.INTEGRITY_VIOLATION, "integrity check failed"
            )
            return ExecutionResult(RequestStatus.FAILED, message="request integrity check failed")
        except KillSwitchActive:
            await self._finish(
                record, RequestStatus.FAILED, AuditEventType.KILL_SWITCH, "kill switch engaged"
            )
            return ExecutionResult(RequestStatus.FAILED, message="kill switch engaged")

        started = await self._repo.transition(record.id, {RequestStatus.APPROVED}, RequestStatus.EXECUTING)
        if started is None:  # expired/cancelled/already executing elsewhere: never run twice
            return ExecutionResult(RequestStatus.CANCELLED, message="request is no longer approved")
        await self._audit.record(AuditEventType.EXECUTION_STARTED, started)

        async with self._semaphores[request.server]:
            try:
                result = await asyncio.wait_for(self._upstream.execute(request), self._timeout)
            except UpstreamUnavailableError as exc:
                await self._finish(started, RequestStatus.FAILED, AuditEventType.EXECUTION_FAILED, str(exc))
                return ExecutionResult(RequestStatus.FAILED, message=f"upstream unavailable: {exc}")
            except (TimeoutError, UpstreamTimeoutError):
                await self._finish(
                    started,
                    RequestStatus.EXECUTION_UNKNOWN,
                    AuditEventType.EXECUTION_UNKNOWN,
                    "upstream timed out",
                )
                return ExecutionResult(
                    RequestStatus.EXECUTION_UNKNOWN,
                    message="upstream timed out; the operation may or may not have completed",
                )
            except (UpstreamCommunicationError, FirewallError) as exc:
                await self._finish(
                    started, RequestStatus.EXECUTION_UNKNOWN, AuditEventType.EXECUTION_UNKNOWN, str(exc)
                )
                return ExecutionResult(
                    RequestStatus.EXECUTION_UNKNOWN,
                    message="connection to upstream was lost; the operation may or may not have completed",
                )
            except asyncio.CancelledError:
                await asyncio.shield(
                    self._finish(
                        started,
                        RequestStatus.EXECUTION_UNKNOWN,
                        AuditEventType.EXECUTION_UNKNOWN,
                        "client cancelled",
                    )
                )
                raise
            except Exception as exc:
                log.exception("execution_error", request_id=record.id)
                await self._finish(
                    started,
                    RequestStatus.EXECUTION_UNKNOWN,
                    AuditEventType.EXECUTION_UNKNOWN,
                    type(exc).__name__,
                )
                return ExecutionResult(RequestStatus.EXECUTION_UNKNOWN, message="unexpected upstream error")

        outcome = result.summary or ("tool reported an error" if result.is_error else "ok")
        await self._finish(started, RequestStatus.COMPLETED, AuditEventType.EXECUTION_FINISHED, outcome,
                           is_error=result.is_error)  # fmt: skip
        return ExecutionResult(RequestStatus.COMPLETED, result=result)

    async def _finish(
        self, record: RequestRecord, status: RequestStatus, event: str, outcome: str, **meta: object
    ) -> None:
        moved = None
        expected = (
            {RequestStatus.APPROVED, RequestStatus.EXECUTING}
            if status is RequestStatus.FAILED
            else {RequestStatus.EXECUTING}
        )
        with contextlib.suppress(Exception):
            moved = await self._repo.transition(record.id, expected, status, outcome=outcome[:500])
        await self._audit.record_safely(event, moved or record, outcome=outcome[:500], **meta)
