"""Immutable MCP request context plus the mutable lifecycle record that tracks it."""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field, replace
from typing import Any
from uuid import uuid4

from mcp_firewall.domain.canonical import canonical_json, compute_request_hash
from mcp_firewall.domain.enums.decision import PolicyAction, RiskLevel
from mcp_firewall.domain.enums.request_status import RequestStatus, can_transition
from mcp_firewall.domain.exceptions import IntegrityError, InvalidRequestError, InvalidTransitionError

TOOLS_CALL = "tools/call"
RESOURCES_READ = "resources/read"
SUPPORTED_OPERATIONS = frozenset({TOOLS_CALL, RESOURCES_READ})


@dataclass(frozen=True, slots=True)
class McpRequest:
    """The frozen description of what the client asked for.

    ``canonical_arguments`` is the single source of truth: it is what is hashed, shown to the
    approver and (after re-verification) dispatched upstream.
    """

    operation: str
    client_id: str
    tenant_id: str
    user_id: str
    server: str
    tool: str
    canonical_arguments: str
    request_hash: str

    @classmethod
    def create(
        cls,
        *,
        operation: str,
        client_id: str,
        server: str,
        tool: str,
        arguments: dict[str, Any] | None,
        tenant_id: str = "default",
        user_id: str = "local",
        max_argument_bytes: int = 262_144,
    ) -> McpRequest:
        if operation not in SUPPORTED_OPERATIONS:
            raise InvalidRequestError(f"unsupported operation: {operation}")
        if not server or not tool or len(server) > 128 or len(tool) > 256:
            raise InvalidRequestError("invalid server or tool name")
        if arguments is not None and not isinstance(arguments, dict):
            raise InvalidRequestError("arguments must be an object")
        canonical = canonical_json(arguments or {})
        if len(canonical.encode("utf-8")) > max_argument_bytes:
            raise InvalidRequestError("arguments exceed the maximum allowed size")
        request_hash = compute_request_hash(
            operation=operation, client_id=client_id, server=server, tool=tool, canonical_arguments=canonical
        )
        return cls(operation, client_id, tenant_id, user_id, server, tool, canonical, request_hash)

    @property
    def arguments(self) -> dict[str, Any]:
        """A fresh copy of the frozen arguments (mutating it cannot affect the request)."""
        return json.loads(self.canonical_arguments)

    def verify_integrity(self, expected_hash: str | None = None) -> None:
        """Recompute the hash and raise if it differs from the stored (or an expected) hash."""
        recomputed = compute_request_hash(
            operation=self.operation,
            client_id=self.client_id,
            server=self.server,
            tool=self.tool,
            canonical_arguments=self.canonical_arguments,
        )
        if recomputed != self.request_hash or (expected_hash is not None and recomputed != expected_hash):
            raise IntegrityError("request does not match the approved hash")


@dataclass(slots=True)
class RiskAssessment:
    level: RiskLevel = RiskLevel.MEDIUM
    reasons: list[str] = field(default_factory=list)


@dataclass(slots=True)
class RequestRecord:
    """Lifecycle state of one intercepted request. Persisted; transitions are checked."""

    request: McpRequest
    id: str = field(default_factory=lambda: str(uuid4()))
    status: RequestStatus = RequestStatus.RECEIVED
    created_at: float = field(default_factory=time.time)
    expires_at: float = 0.0
    updated_at: float = field(default_factory=time.time)
    owner_id: str = ""
    policy_action: PolicyAction | None = None
    matched_rule_id: str | None = None
    policy_version: str = ""
    risk: RiskAssessment = field(default_factory=RiskAssessment)
    strong_confirmation: bool = False
    approver_role: str = "approver"
    schema_changed: bool = False
    display_arguments: str = "{}"  # sanitized JSON shown to humans / logs
    description: str = ""  # tool description (UNTRUSTED metadata, display only)
    decided_by: str | None = None
    decided_at: float | None = None
    decision_reason: str | None = None
    outcome: str | None = None  # short, non-sensitive result / error summary

    def transition(self, target: RequestStatus) -> None:
        if not can_transition(self.status, target):
            raise InvalidTransitionError(f"{self.status} -> {target} is not allowed")
        self.status = target
        self.updated_at = time.time()

    def snapshot(self, **changes: Any) -> RequestRecord:
        return replace(self, **changes)
