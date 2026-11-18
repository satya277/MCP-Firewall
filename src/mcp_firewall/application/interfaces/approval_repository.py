"""Persistence ports. The application layer depends on these, never on SQLite/PostgreSQL."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Protocol, runtime_checkable

from mcp_firewall.domain.entities.approval import ApprovalDecision, Principal
from mcp_firewall.domain.entities.audit import AuditEvent
from mcp_firewall.domain.entities.mcp_request import RequestRecord
from mcp_firewall.domain.entities.policy import PolicySet
from mcp_firewall.domain.enums.request_status import RequestStatus


@dataclass(frozen=True, slots=True)
class ToolFingerprintResult:
    first_seen: bool
    changed: bool
    previous: str | None = None


@dataclass(frozen=True, slots=True)
class ReapedRequest:
    id: str
    tenant_id: str
    previous: RequestStatus
    current: RequestStatus


@runtime_checkable
class RequestRepository(Protocol):
    """Durable request lifecycle storage. All state changes are atomic compare-and-set updates."""

    async def create(self, record: RequestRecord) -> None: ...

    async def get(self, request_id: str) -> RequestRecord | None: ...

    async def transition(
        self,
        request_id: str,
        expected: set[RequestStatus] | frozenset[RequestStatus],
        target: RequestStatus,
        **fields: Any,
    ) -> RequestRecord | None:
        """``UPDATE ... WHERE id=? AND status IN (expected)``. Returns None if the race was lost."""
        ...

    async def apply_decision(
        self, decision: ApprovalDecision, target: RequestStatus, now: float
    ) -> RequestRecord | None:
        """Atomically PENDING_APPROVAL->target (only while unexpired) and store the decision row."""
        ...

    async def list_requests(
        self, *, statuses: set[RequestStatus] | None = None, tenant_id: str | None = None, limit: int = 100
    ) -> list[RequestRecord]: ...

    async def reap_expired(self, now: float, execution_grace: float) -> list[ReapedRequest]:
        """Expire abandoned open requests past their deadline; mark stuck EXECUTING as unknown."""
        ...

    async def count_in_states(self, statuses: set[RequestStatus]) -> int: ...


@runtime_checkable
class SettingsRepository(Protocol):
    async def get_setting(self, key: str) -> str | None: ...

    async def set_setting(self, key: str, value: str) -> None: ...


@runtime_checkable
class ToolRegistryRepository(Protocol):
    async def observe_tool(
        self, *, server: str, tool: str, fingerprint: str, description: str
    ) -> ToolFingerprintResult:
        """Record the tool fingerprint (trust-on-first-use) and report whether it changed."""
        ...

    async def acknowledge_tool(self, *, server: str, tool: str, fingerprint: str) -> None: ...


@runtime_checkable
class IdentityRepository(Protocol):
    async def upsert_principal(self, principal: Principal) -> None: ...

    async def save_policy_snapshot(self, policy: PolicySet, tenant_id: str = "default") -> None: ...

    async def upsert_server(self, *, name: str, transport: str, endpoint_ref: str, enabled: bool) -> None: ...


@runtime_checkable
class AuditLog(Protocol):
    """Append-only, hash-chained audit trail."""

    async def append(self, event: AuditEvent) -> AuditEvent: ...

    async def list_events(
        self, *, request_id: str | None = None, limit: int = 200, after_seq: int = 0
    ) -> list[AuditEvent]: ...

    async def verify_chain(self) -> tuple[bool, int, str | None]:
        """Returns (ok, events_checked, error_description)."""
        ...
