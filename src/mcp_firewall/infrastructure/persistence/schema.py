"""Schema (portable across SQLite and PostgreSQL) and migrations bootstrap."""

from __future__ import annotations

from mcp_firewall.infrastructure.persistence.database import Database

SCHEMA_VERSION = 1

_TABLES = [
    """CREATE TABLE IF NOT EXISTS schema_info (key TEXT PRIMARY KEY, value TEXT NOT NULL)""",
    """CREATE TABLE IF NOT EXISTS users (
        id TEXT PRIMARY KEY, email TEXT NOT NULL DEFAULT '', role TEXT NOT NULL,
        tenant_id TEXT NOT NULL, created_at DOUBLE PRECISION NOT NULL)""",
    """CREATE TABLE IF NOT EXISTS mcp_servers (
        id TEXT PRIMARY KEY, tenant_id TEXT NOT NULL, name TEXT NOT NULL, transport TEXT NOT NULL,
        endpoint_ref TEXT NOT NULL, enabled INTEGER NOT NULL, configuration_version INTEGER NOT NULL DEFAULT 1)""",
    """CREATE TABLE IF NOT EXISTS mcp_tools (
        server_id TEXT NOT NULL, tool_name TEXT NOT NULL, description TEXT NOT NULL DEFAULT '',
        input_schema_hash TEXT NOT NULL, acknowledged_hash TEXT NOT NULL,
        discovered_at DOUBLE PRECISION NOT NULL, PRIMARY KEY (server_id, tool_name))""",
    """CREATE TABLE IF NOT EXISTS intercepted_requests (
        id TEXT PRIMARY KEY, tenant_id TEXT NOT NULL, user_id TEXT NOT NULL, client_id TEXT NOT NULL,
        server_id TEXT NOT NULL, tool_name TEXT NOT NULL, operation TEXT NOT NULL,
        arguments_ref TEXT NOT NULL, display_arguments TEXT NOT NULL, description TEXT NOT NULL DEFAULT '',
        request_hash TEXT NOT NULL, status TEXT NOT NULL, owner_id TEXT NOT NULL,
        created_at DOUBLE PRECISION NOT NULL, updated_at DOUBLE PRECISION NOT NULL,
        expires_at DOUBLE PRECISION NOT NULL,
        policy_action TEXT, matched_rule_id TEXT, policy_version TEXT NOT NULL DEFAULT '',
        risk_level INTEGER NOT NULL DEFAULT 2, risk_reasons TEXT NOT NULL DEFAULT '[]',
        strong_confirmation INTEGER NOT NULL DEFAULT 0, approver_role TEXT NOT NULL DEFAULT 'approver',
        schema_changed INTEGER NOT NULL DEFAULT 0,
        decided_by TEXT, decided_at DOUBLE PRECISION, decision_reason TEXT, outcome TEXT)""",
    """CREATE TABLE IF NOT EXISTS approval_decisions (
        id TEXT PRIMARY KEY, request_id TEXT NOT NULL UNIQUE, decision TEXT NOT NULL,
        decided_by TEXT NOT NULL, request_hash TEXT NOT NULL, decided_at DOUBLE PRECISION NOT NULL,
        reason TEXT, confirmed INTEGER NOT NULL DEFAULT 0)""",
    """CREATE TABLE IF NOT EXISTS security_policies (
        tenant_id TEXT NOT NULL, version TEXT NOT NULL, name TEXT NOT NULL, rules TEXT NOT NULL,
        priority INTEGER NOT NULL DEFAULT 0, enabled INTEGER NOT NULL DEFAULT 1,
        loaded_at DOUBLE PRECISION NOT NULL, PRIMARY KEY (tenant_id, version))""",
    """CREATE TABLE IF NOT EXISTS audit_logs (
        seq BIGINT PRIMARY KEY, id TEXT NOT NULL UNIQUE, tenant_id TEXT NOT NULL, request_id TEXT,
        event_type TEXT NOT NULL, actor_id TEXT NOT NULL, timestamp DOUBLE PRECISION NOT NULL,
        metadata TEXT NOT NULL, prev_hash TEXT NOT NULL, hash TEXT NOT NULL)""",
    """CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT NOT NULL)""",
]

_INDEXES = [
    "CREATE INDEX IF NOT EXISTS idx_requests_status ON intercepted_requests (status)",
    "CREATE INDEX IF NOT EXISTS idx_requests_tenant_user ON intercepted_requests (tenant_id, user_id)",
    "CREATE INDEX IF NOT EXISTS idx_requests_created ON intercepted_requests (created_at)",
    "CREATE INDEX IF NOT EXISTS idx_decisions_request ON approval_decisions (request_id)",
    "CREATE INDEX IF NOT EXISTS idx_audit_request ON audit_logs (request_id)",
]

_SQLITE_TRIGGERS = [
    """CREATE TRIGGER IF NOT EXISTS audit_no_update BEFORE UPDATE ON audit_logs
       BEGIN SELECT RAISE(ABORT, 'audit log is append-only'); END""",
    """CREATE TRIGGER IF NOT EXISTS audit_no_delete BEFORE DELETE ON audit_logs
       BEGIN SELECT RAISE(ABORT, 'audit log is append-only'); END""",
]

_PG_TRIGGERS = [
    """CREATE OR REPLACE FUNCTION mcpfw_audit_append_only() RETURNS trigger AS $$
       BEGIN RAISE EXCEPTION 'audit log is append-only'; END; $$ LANGUAGE plpgsql""",
    "DROP TRIGGER IF EXISTS audit_append_only ON audit_logs",
    """CREATE TRIGGER audit_append_only BEFORE UPDATE OR DELETE ON audit_logs
       FOR EACH ROW EXECUTE FUNCTION mcpfw_audit_append_only()""",
]


async def ensure_schema(db: Database) -> None:
    async with db.transaction(exclusive=True) as tx:
        for stmt in _TABLES + _INDEXES:
            await tx.execute(stmt)
        for stmt in _SQLITE_TRIGGERS if db.dialect == "sqlite" else _PG_TRIGGERS:
            await tx.execute(stmt)
        await tx.execute(
            "INSERT INTO schema_info (key, value) VALUES ('version', ?) ON CONFLICT (key) DO NOTHING",
            (str(SCHEMA_VERSION),),
        )
