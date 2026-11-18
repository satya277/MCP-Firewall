"""SQL implementation of the repository ports (works on SQLite and PostgreSQL)."""

from __future__ import annotations

import json
import time
from typing import Any

from mcp_firewall.application.interfaces.approval_repository import ReapedRequest, ToolFingerprintResult
from mcp_firewall.domain.entities.approval import ApprovalDecision, Principal
from mcp_firewall.domain.entities.mcp_request import McpRequest, RequestRecord, RiskAssessment
from mcp_firewall.domain.entities.policy import PolicySet
from mcp_firewall.domain.enums.decision import PolicyAction, RiskLevel
from mcp_firewall.domain.enums.request_status import OPEN_STATES, RequestStatus, can_transition
from mcp_firewall.domain.exceptions import InvalidTransitionError
from mcp_firewall.infrastructure.persistence.database import Database, Row
from mcp_firewall.infrastructure.security.secrets_manager import SecretBox

_UPDATABLE = frozenset(
    {
        "expires_at", "policy_action", "matched_rule_id", "policy_version", "risk_level", "risk_reasons",
        "strong_confirmation", "approver_role", "schema_changed", "decided_by", "decided_at",
        "decision_reason", "outcome",
    }
)  # fmt: skip


def _placeholders(n: int) -> str:
    return ",".join("?" * n)


class SqlRepository:
    """Implements RequestRepository, SettingsRepository, ToolRegistryRepository, IdentityRepository."""

    def __init__(self, db: Database, box: SecretBox) -> None:
        self._db = db
        self._box = box

    # -- mapping --------------------------------------------------------------------------
    def _to_record(self, row: Row) -> RequestRecord:
        request = McpRequest(
            operation=row["operation"],
            client_id=row["client_id"],
            tenant_id=row["tenant_id"],
            user_id=row["user_id"],
            server=row["server_id"],
            tool=row["tool_name"],
            canonical_arguments=self._box.decrypt(row["arguments_ref"]),
            request_hash=row["request_hash"],
        )
        return RequestRecord(
            request=request,
            id=row["id"],
            status=RequestStatus(row["status"]),
            created_at=row["created_at"],
            expires_at=row["expires_at"],
            updated_at=row["updated_at"],
            owner_id=row["owner_id"],
            policy_action=PolicyAction(row["policy_action"]) if row["policy_action"] else None,
            matched_rule_id=row["matched_rule_id"],
            policy_version=row["policy_version"],
            risk=RiskAssessment(RiskLevel(row["risk_level"]), json.loads(row["risk_reasons"])),
            strong_confirmation=bool(row["strong_confirmation"]),
            approver_role=row["approver_role"],
            schema_changed=bool(row["schema_changed"]),
            display_arguments=row["display_arguments"],
            description=row["description"],
            decided_by=row["decided_by"],
            decided_at=row["decided_at"],
            decision_reason=row["decision_reason"],
            outcome=row["outcome"],
        )

    # -- RequestRepository ----------------------------------------------------------------
    async def create(self, record: RequestRecord) -> None:
        r = record.request
        await self._db.execute(
            """INSERT INTO intercepted_requests
               (id, tenant_id, user_id, client_id, server_id, tool_name, operation, arguments_ref,
                display_arguments, description, request_hash, status, owner_id, created_at, updated_at,
                expires_at, policy_version, risk_level, risk_reasons, strong_confirmation, approver_role,
                schema_changed)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (
                record.id, r.tenant_id, r.user_id, r.client_id, r.server, r.tool, r.operation,
                self._box.encrypt(r.canonical_arguments), record.display_arguments, record.description,
                r.request_hash, record.status.value, record.owner_id, record.created_at, record.updated_at,
                record.expires_at, record.policy_version, record.risk.level.value,
                json.dumps(record.risk.reasons), int(record.strong_confirmation), record.approver_role,
                int(record.schema_changed),
            ),
        )  # fmt: skip

    async def get(self, request_id: str) -> RequestRecord | None:
        row = await self._db.fetchone("SELECT * FROM intercepted_requests WHERE id = ?", (request_id,))
        return self._to_record(row) if row else None

    async def transition(
        self,
        request_id: str,
        expected: set[RequestStatus] | frozenset[RequestStatus],
        target: RequestStatus,
        **fields: Any,
    ) -> RequestRecord | None:
        legal = [s for s in expected if can_transition(s, target)]
        if not legal:
            raise InvalidTransitionError(f"no expected state may transition to {target}")
        unknown = set(fields) - _UPDATABLE
        if unknown:
            raise ValueError(f"fields cannot be updated: {sorted(unknown)}")
        assignments = ["status = ?", "updated_at = ?", *[f"{k} = ?" for k in fields]]
        params: list[Any] = [target.value, time.time(), *fields.values()]
        sql = (
            f"UPDATE intercepted_requests SET {', '.join(assignments)} "  # noqa: S608 - whitelisted columns
            f"WHERE id = ? AND status IN ({_placeholders(len(legal))})"
        )
        params += [request_id, *[s.value for s in legal]]
        changed = await self._db.execute(sql, tuple(params))
        if changed != 1:
            return None
        return await self.get(request_id)

    async def apply_decision(
        self, decision: ApprovalDecision, target: RequestStatus, now: float
    ) -> RequestRecord | None:
        async with self._db.transaction() as tx:
            changed = await tx.execute(
                """UPDATE intercepted_requests
                   SET status = ?, updated_at = ?, decided_by = ?, decided_at = ?, decision_reason = ?
                   WHERE id = ? AND status = ? AND expires_at > ?""",
                (
                    target.value, now, decision.decided_by, decision.decided_at, decision.reason,
                    decision.request_id, RequestStatus.PENDING_APPROVAL.value, now,
                ),
            )  # fmt: skip
            if changed != 1:
                return None
            await tx.execute(
                """INSERT INTO approval_decisions
                   (id, request_id, decision, decided_by, request_hash, decided_at, reason, confirmed)
                   VALUES (?,?,?,?,?,?,?,?)""",
                (
                    decision.id, decision.request_id, decision.decision.value, decision.decided_by,
                    decision.request_hash, decision.decided_at, decision.reason, int(decision.confirmed),
                ),
            )  # fmt: skip
        return await self.get(decision.request_id)

    async def list_requests(
        self, *, statuses: set[RequestStatus] | None = None, tenant_id: str | None = None, limit: int = 100
    ) -> list[RequestRecord]:
        clauses, params = [], []
        if statuses:
            clauses.append(f"status IN ({_placeholders(len(statuses))})")
            params += [s.value for s in statuses]
        if tenant_id:
            clauses.append("tenant_id = ?")
            params.append(tenant_id)
        where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        rows = await self._db.fetchall(
            f"SELECT * FROM intercepted_requests {where} ORDER BY created_at DESC LIMIT ?",  # noqa: S608
            (*params, max(1, min(limit, 1000))),
        )
        return [self._to_record(r) for r in rows]

    async def count_in_states(self, statuses: set[RequestStatus]) -> int:
        row = await self._db.fetchone(
            f"SELECT COUNT(*) AS n FROM intercepted_requests WHERE status IN ({_placeholders(len(statuses))})",  # noqa: S608
            tuple(s.value for s in statuses),
        )
        return int(row["n"]) if row else 0

    async def reap_expired(self, now: float, execution_grace: float) -> list[ReapedRequest]:
        reaped: list[ReapedRequest] = []
        open_values = [s.value for s in OPEN_STATES]
        async with self._db.transaction() as tx:
            stale = await tx.fetchall(
                f"SELECT id, tenant_id, status FROM intercepted_requests "  # noqa: S608
                f"WHERE status IN ({_placeholders(len(open_values))}) AND expires_at < ?",
                (*open_values, now),
            )
            for row in stale:
                n = await tx.execute(
                    "UPDATE intercepted_requests SET status = ?, updated_at = ?, outcome = ? "
                    "WHERE id = ? AND status = ?",
                    (RequestStatus.EXPIRED.value, now, "expired (reaped)", row["id"], row["status"]),
                )
                if n == 1:
                    reaped.append(
                        ReapedRequest(
                            row["id"], row["tenant_id"], RequestStatus(row["status"]), RequestStatus.EXPIRED
                        )
                    )
            stuck = await tx.fetchall(
                "SELECT id, tenant_id FROM intercepted_requests WHERE status = ? AND updated_at < ?",
                (RequestStatus.EXECUTING.value, now - execution_grace),
            )
            for row in stuck:
                n = await tx.execute(
                    "UPDATE intercepted_requests SET status = ?, updated_at = ?, outcome = ? "
                    "WHERE id = ? AND status = ?",
                    (
                        RequestStatus.EXECUTION_UNKNOWN.value, now, "execution outcome lost (reaped)",
                        row["id"], RequestStatus.EXECUTING.value,
                    ),
                )  # fmt: skip
                if n == 1:
                    reaped.append(
                        ReapedRequest(
                            row["id"],
                            row["tenant_id"],
                            RequestStatus.EXECUTING,
                            RequestStatus.EXECUTION_UNKNOWN,
                        )
                    )
        return reaped

    # -- SettingsRepository ---------------------------------------------------------------
    async def get_setting(self, key: str) -> str | None:
        row = await self._db.fetchone("SELECT value FROM settings WHERE key = ?", (key,))
        return row["value"] if row else None

    async def set_setting(self, key: str, value: str) -> None:
        await self._db.execute(
            "INSERT INTO settings (key, value) VALUES (?, ?) ON CONFLICT (key) DO UPDATE SET value = excluded.value",
            (key, value),
        )

    # -- ToolRegistryRepository -----------------------------------------------------------
    async def observe_tool(
        self, *, server: str, tool: str, fingerprint: str, description: str
    ) -> ToolFingerprintResult:
        async with self._db.transaction() as tx:
            row = await tx.fetchone(
                "SELECT input_schema_hash, acknowledged_hash FROM mcp_tools WHERE server_id = ? AND tool_name = ?",
                (server, tool),
            )
            if row is None:  # trust on first use
                await tx.execute(
                    "INSERT INTO mcp_tools (server_id, tool_name, description, input_schema_hash, "
                    "acknowledged_hash, discovered_at) VALUES (?,?,?,?,?,?)",
                    (server, tool, description[:1000], fingerprint, fingerprint, time.time()),
                )
                return ToolFingerprintResult(first_seen=True, changed=False)
            await tx.execute(
                "UPDATE mcp_tools SET input_schema_hash = ?, description = ? WHERE server_id = ? AND tool_name = ?",
                (fingerprint, description[:1000], server, tool),
            )
            return ToolFingerprintResult(
                first_seen=False,
                changed=fingerprint != row["acknowledged_hash"],
                previous=row["acknowledged_hash"],
            )

    async def acknowledge_tool(self, *, server: str, tool: str, fingerprint: str) -> None:
        await self._db.execute(
            "UPDATE mcp_tools SET acknowledged_hash = ? WHERE server_id = ? AND tool_name = ?",
            (fingerprint, server, tool),
        )

    # -- IdentityRepository ---------------------------------------------------------------
    async def upsert_principal(self, principal: Principal) -> None:
        await self._db.execute(
            "INSERT INTO users (id, email, role, tenant_id, created_at) VALUES (?,?,?,?,?) "
            "ON CONFLICT (id) DO UPDATE SET role = excluded.role, tenant_id = excluded.tenant_id",
            (principal.id, principal.email, principal.role.name.lower(), principal.tenant_id, time.time()),
        )

    async def save_policy_snapshot(self, policy: PolicySet, tenant_id: str = "default") -> None:
        rules = [
            {
                "id": r.id, "action": r.action.value, "priority": r.priority, "servers": r.servers,
                "tools": r.tools, "clients": r.clients, "operations": r.operations, "enabled": r.enabled,
                "conditions": [{"path": c.path, "op": c.op, "value": c.value} for c in r.conditions],
            }
            for r in policy.rules
        ]  # fmt: skip
        await self._db.execute(
            "INSERT INTO security_policies (tenant_id, version, name, rules, priority, enabled, loaded_at) "
            "VALUES (?,?,?,?,?,?,?) ON CONFLICT (tenant_id, version) DO NOTHING",
            (tenant_id, policy.version, "default", json.dumps(rules), 0, 1, time.time()),
        )

    async def upsert_server(self, *, name: str, transport: str, endpoint_ref: str, enabled: bool) -> None:
        await self._db.execute(
            "INSERT INTO mcp_servers (id, tenant_id, name, transport, endpoint_ref, enabled) VALUES (?,?,?,?,?,?) "
            "ON CONFLICT (id) DO UPDATE SET transport = excluded.transport, endpoint_ref = excluded.endpoint_ref, "
            "enabled = excluded.enabled",
            (name, "default", name, transport, endpoint_ref, int(enabled)),
        )
