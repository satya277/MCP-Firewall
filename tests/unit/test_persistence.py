"""Unit tests: SQL repository (atomic transitions), audit hash chain, tool registry, event bus."""

from __future__ import annotations

import asyncio
import json
import time

import pytest
from cryptography.fernet import Fernet

from mcp_firewall.application.interfaces.event_publisher import FirewallEvent
from mcp_firewall.domain.entities.approval import ApprovalDecision
from mcp_firewall.domain.entities.audit import AuditEvent
from mcp_firewall.domain.entities.mcp_request import McpRequest, RequestRecord
from mcp_firewall.domain.enums.decision import Decision
from mcp_firewall.domain.enums.request_status import RequestStatus as S
from mcp_firewall.domain.exceptions import InvalidTransitionError
from mcp_firewall.infrastructure.events.event_bus import RESYNC, InMemoryEventBus
from mcp_firewall.infrastructure.persistence.repositories.sql_audit import SqlAuditLog
from mcp_firewall.infrastructure.persistence.repositories.sql_repository import SqlRepository
from mcp_firewall.infrastructure.persistence.schema import ensure_schema
from mcp_firewall.infrastructure.persistence.sqlite import SqliteDatabase
from mcp_firewall.infrastructure.security.secrets_manager import SecretBox


@pytest.fixture
async def stack():
    db = SqliteDatabase(":memory:")
    await db.start()
    await ensure_schema(db)
    repo = SqlRepository(db, SecretBox(Fernet.generate_key()))
    yield db, repo, SqlAuditLog(db)
    await db.stop()


def record(args=None, expires_in=60.0, status=S.RECEIVED) -> RequestRecord:
    req = McpRequest.create(
        operation="tools/call", client_id="c", server="demo", tool="echo", arguments=args or {"a": 1}
    )
    now = time.time()
    return RequestRecord(
        request=req, status=status, created_at=now, expires_at=now + expires_in, owner_id="w1"
    )


async def test_roundtrip_preserves_request_and_encrypts_arguments(stack):
    db, repo, _ = stack
    rec = record({"secret": "TOPSECRET-VALUE"})
    await repo.create(rec)
    row = await db.fetchone("SELECT arguments_ref FROM intercepted_requests WHERE id = ?", (rec.id,))
    assert "TOPSECRET-VALUE" not in row["arguments_ref"]
    loaded = await repo.get(rec.id)
    assert loaded.request == rec.request
    loaded.request.verify_integrity()


async def test_transition_is_compare_and_set(stack):
    _, repo, _ = stack
    rec = record()
    await repo.create(rec)
    assert await repo.transition(rec.id, {S.RECEIVED}, S.VALIDATED)
    assert await repo.transition(rec.id, {S.RECEIVED}, S.VALIDATED) is None  # wrong expected state
    with pytest.raises(InvalidTransitionError):
        await repo.transition(rec.id, {S.VALIDATED}, S.COMPLETED)
    with pytest.raises(ValueError):
        await repo.transition(rec.id, {S.VALIDATED}, S.APPROVED, request_hash="x")  # non-updatable column


async def test_only_one_concurrent_decision_wins(stack):
    _, repo, _ = stack
    rec = record(status=S.PENDING_APPROVAL)
    await repo.create(rec)

    async def decide(i, verdict):
        d = ApprovalDecision(rec.id, verdict, f"u{i}", rec.request.request_hash)
        target = S.APPROVED if verdict is Decision.ALLOW else S.REJECTED
        return await repo.apply_decision(d, target, time.time())

    results = await asyncio.gather(
        *[decide(i, Decision.ALLOW if i % 2 else Decision.BLOCK) for i in range(20)]
    )
    assert sum(r is not None for r in results) == 1
    final = await repo.get(rec.id)
    assert final.status in (S.APPROVED, S.REJECTED)


async def test_late_decision_rejected_by_repository(stack):
    _, repo, _ = stack
    rec = record(expires_in=-1, status=S.PENDING_APPROVAL)
    await repo.create(rec)
    d = ApprovalDecision(rec.id, Decision.ALLOW, "u", rec.request.request_hash)
    assert await repo.apply_decision(d, S.APPROVED, time.time()) is None


async def test_decision_row_unique_per_request(stack):
    db, repo, _ = stack
    rec = record(status=S.PENDING_APPROVAL)
    await repo.create(rec)
    d = ApprovalDecision(rec.id, Decision.ALLOW, "u", rec.request.request_hash)
    await repo.apply_decision(d, S.APPROVED, time.time())
    with pytest.raises(Exception):  # noqa: B017,PT011 - integrity error from the UNIQUE constraint
        await db.execute(
            "INSERT INTO approval_decisions (id, request_id, decision, decided_by, request_hash, decided_at) "
            "VALUES ('x', ?, 'allow', 'u', 'h', 1.0)",
            (rec.id,),
        )


async def test_reaper_expires_abandoned_and_marks_stuck_executions(stack):
    _, repo, _ = stack
    stale_pending = record(expires_in=-10, status=S.PENDING_APPROVAL)
    stale_approved = record(expires_in=-10, status=S.APPROVED)
    live = record(expires_in=60, status=S.PENDING_APPROVAL)
    executing = record(expires_in=-10, status=S.EXECUTING)
    executing.updated_at = time.time() - 1000
    for r in (stale_pending, stale_approved, live, executing):
        await repo.create(r)
    reaped = {x.id: x for x in await repo.reap_expired(time.time(), execution_grace=30)}
    assert reaped[stale_pending.id].current is S.EXPIRED
    assert reaped[stale_approved.id].current is S.EXPIRED
    assert reaped[executing.id].current is S.EXECUTION_UNKNOWN
    assert live.id not in reaped
    assert (await repo.get(live.id)).status is S.PENDING_APPROVAL


async def test_tool_fingerprint_tofu_change_and_acknowledge(stack):
    _, repo, _ = stack
    kw = {"server": "demo", "tool": "echo", "description": "d"}
    first = await repo.observe_tool(fingerprint="f1", **kw)
    assert first.first_seen and not first.changed
    assert not (await repo.observe_tool(fingerprint="f1", **kw)).changed
    changed = await repo.observe_tool(fingerprint="f2", **kw)
    assert changed.changed and changed.previous == "f1"
    assert (await repo.observe_tool(fingerprint="f2", **kw)).changed  # still unacknowledged
    await repo.acknowledge_tool(server="demo", tool="echo", fingerprint="f2")
    assert not (await repo.observe_tool(fingerprint="f2", **kw)).changed


async def test_settings_upsert(stack):
    _, repo, _ = stack
    assert await repo.get_setting("k") is None
    await repo.set_setting("k", "1")
    await repo.set_setting("k", "2")
    assert await repo.get_setting("k") == "2"


async def test_audit_chain_verifies_and_detects_tampering(stack):
    db, _, audit = stack
    for i in range(5):
        await audit.append(AuditEvent(event_type="t", metadata={"i": i, "nested": {"x": [1, 2]}}))
    ok, checked, err = await audit.verify_chain()
    assert ok and checked == 5 and err is None
    # the database itself refuses updates/deletes
    with pytest.raises(Exception):  # noqa: B017,PT011
        await db.execute("UPDATE audit_logs SET actor_id = 'evil' WHERE seq = 2")
    with pytest.raises(Exception):  # noqa: B017,PT011
        await db.execute("DELETE FROM audit_logs WHERE seq = 2")
    # simulate an attacker bypassing the trigger
    await db.execute("DROP TRIGGER audit_no_update")
    await db.execute("UPDATE audit_logs SET metadata = ? WHERE seq = 3", (json.dumps({"i": 999}),))
    ok, _, err = await audit.verify_chain()
    assert not ok and "seq 3" in err


async def test_audit_detects_deleted_event(stack):
    db, _, audit = stack
    for i in range(4):
        await audit.append(AuditEvent(event_type="t", metadata={"i": i}))
    await db.execute("DROP TRIGGER audit_no_delete")
    await db.execute("DELETE FROM audit_logs WHERE seq = 2")
    ok, _, err = await audit.verify_chain()
    assert not ok and "gap" in err


async def test_audit_concurrent_appends_keep_chain_valid(stack):
    _, _, audit = stack
    await asyncio.gather(*[audit.append(AuditEvent(event_type="t", metadata={"i": i})) for i in range(40)])
    ok, checked, _ = await audit.verify_chain()
    assert ok and checked == 40


async def test_event_bus_fanout_dedup_and_isolation():
    bus = InMemoryEventBus()
    a, b = bus.subscribe(), bus.subscribe()
    ev = FirewallEvent(type="x", event_id="same")
    await bus.publish(ev)
    await bus.publish(ev)  # duplicate delivery is ignored
    assert (await asyncio.wait_for(a.__anext__(), 1)).event_id == "same"
    assert (await asyncio.wait_for(b.__anext__(), 1)).event_id == "same"
    assert a.queue.empty() and b.queue.empty()
    a.close()
    assert bus.subscriber_count() == 1


async def test_event_bus_slow_consumer_gets_resync_not_unbounded_memory():
    bus = InMemoryEventBus(queue_size=3)
    sub = bus.subscribe()
    for i in range(10):
        await bus.publish(FirewallEvent(type="x", event_id=str(i)))
    drained = []
    while not sub.queue.empty():
        drained.append(sub.queue.get_nowait().type)
    assert RESYNC in drained and len(drained) <= 3
