"""PostgreSQL adapter tests. Run with a real server:

set MCPFW_TEST_POSTGRES_URL=postgresql://mcpfw:testpw@localhost:54329/mcpfw
"""

from __future__ import annotations

import asyncio
import os
import time

import pytest
from cryptography.fernet import Fernet

PG_URL = os.environ.get("MCPFW_TEST_POSTGRES_URL")
pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(not PG_URL, reason="set MCPFW_TEST_POSTGRES_URL to run PostgreSQL tests"),
]

from mcp_firewall.bootstrap import build_container  # noqa: E402
from mcp_firewall.config import parse_policy  # noqa: E402
from mcp_firewall.domain.entities.approval import ApprovalDecision  # noqa: E402
from mcp_firewall.domain.entities.audit import AuditEvent  # noqa: E402
from mcp_firewall.domain.entities.mcp_request import McpRequest, RequestRecord  # noqa: E402
from mcp_firewall.domain.enums.decision import Decision  # noqa: E402
from mcp_firewall.domain.enums.request_status import RequestStatus as S  # noqa: E402
from mcp_firewall.infrastructure.persistence.postgres import PostgresDatabase  # noqa: E402
from mcp_firewall.infrastructure.persistence.repositories.sql_audit import SqlAuditLog  # noqa: E402
from mcp_firewall.infrastructure.persistence.repositories.sql_repository import SqlRepository  # noqa: E402
from mcp_firewall.infrastructure.persistence.schema import ensure_schema  # noqa: E402
from mcp_firewall.infrastructure.security.secrets_manager import SecretBox  # noqa: E402
from tests.conftest import APPROVER, DEFAULT_POLICY, FakeUpstream, make_settings  # noqa: E402
from tests.integration.test_pipeline import incoming  # noqa: E402


@pytest.fixture
async def pg():
    db = PostgresDatabase(PG_URL)
    await db.start()
    await db.execute("DROP SCHEMA public CASCADE")
    await db.execute("CREATE SCHEMA public")
    await ensure_schema(db)
    yield db
    await db.stop()


def record(status=S.PENDING_APPROVAL, expires_in=60.0):
    req = McpRequest.create(
        operation="tools/call", client_id="c", server="demo", tool="echo", arguments={"a": 1}
    )
    now = time.time()
    return RequestRecord(
        request=req, status=status, created_at=now, expires_at=now + expires_in, owner_id="w"
    )


async def test_schema_is_idempotent_and_roundtrips(pg):
    await ensure_schema(pg)
    repo = SqlRepository(pg, SecretBox(Fernet.generate_key()))
    rec = record()
    await repo.create(rec)
    loaded = await repo.get(rec.id)
    assert loaded.request == rec.request and loaded.status is S.PENDING_APPROVAL


async def test_one_decision_wins_across_pool_connections(pg):
    repo = SqlRepository(pg, SecretBox(Fernet.generate_key()))
    rec = record()
    await repo.create(rec)

    async def go(i):
        d = ApprovalDecision(
            rec.id, Decision.ALLOW if i % 2 else Decision.BLOCK, f"u{i}", rec.request.request_hash
        )
        return await repo.apply_decision(d, S.APPROVED if i % 2 else S.REJECTED, time.time())

    results = await asyncio.gather(*[go(i) for i in range(30)])
    assert sum(r is not None for r in results) == 1


async def test_audit_chain_concurrent_and_append_only(pg):
    audit = SqlAuditLog(pg)
    await asyncio.gather(*[audit.append(AuditEvent(event_type="t", metadata={"i": i})) for i in range(40)])
    ok, checked, err = await audit.verify_chain()
    assert ok and checked == 40, err
    with pytest.raises(Exception, match="append-only"):
        await pg.execute("UPDATE audit_logs SET actor_id = 'x' WHERE seq = 1")
    with pytest.raises(Exception, match="append-only"):
        await pg.execute("DELETE FROM audit_logs WHERE seq = 1")


async def test_reaper_and_tool_registry(pg):
    repo = SqlRepository(pg, SecretBox(Fernet.generate_key()))
    stale, live = record(expires_in=-10), record()
    await repo.create(stale)
    await repo.create(live)
    reaped = await repo.reap_expired(time.time(), 30)
    assert [r.id for r in reaped] == [stale.id] and (await repo.get(live.id)).status is S.PENDING_APPROVAL
    kw = {"server": "s", "tool": "t", "description": "d"}
    assert (await repo.observe_tool(fingerprint="a", **kw)).first_seen
    assert (await repo.observe_tool(fingerprint="b", **kw)).changed
    await repo.set_setting("k", "v")
    assert await repo.get_setting("k") == "v"


async def test_full_pipeline_on_postgres_with_concurrency(tmp_path, pg):
    upstream = FakeUpstream()
    c = build_container(
        make_settings(tmp_path, approval_timeout_seconds=20, max_pending_requests=500),
        policy=parse_policy(DEFAULT_POLICY),
        upstream=upstream,  # type: ignore[arg-type]
        db=pg,
        box=SecretBox(Fernet.generate_key()),
    )
    await c.start()
    sub = c.bus.subscribe()

    async def approve_all():
        async for ev in sub:
            if ev.type == "approval.requested":
                asyncio.create_task(
                    c.approve(APPROVER, ev.request_id, ev.payload["request_hash"], confirmed=True)
                )

    answerer = asyncio.create_task(approve_all())
    try:
        outs = await asyncio.gather(
            *[c.interception.intercept(incoming("create_file", {"i": i})) for i in range(50)]
        )
        assert all(o.status is S.COMPLETED for o in outs) and len(upstream.executed) == 50
        ok, _, err = await c.audit_log.verify_chain()
        assert ok, err
    finally:
        answerer.cancel()
        sub.close()
        await c.bus.stop()
        await c.approvals.stop()
