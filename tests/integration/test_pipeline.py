"""Integration tests of the full interception pipeline (application + persistence, fake upstream)."""

from __future__ import annotations

import asyncio

import pytest

from mcp_firewall.application.services.interception_service import IncomingCall
from mcp_firewall.domain.entities.approval import Principal
from mcp_firewall.domain.entities.mcp_request import McpRequest
from mcp_firewall.domain.enums.decision import Role
from mcp_firewall.domain.enums.request_status import RequestStatus as S
from mcp_firewall.domain.exceptions import (
    AlreadyDecidedError,
    ApprovalExpiredError,
    HashMismatchError,
    NotAuthorizedError,
    StrongConfirmationRequired,
    UnknownRequestError,
)
from tests.conftest import ADMIN, APPROVER, make_container


def incoming(tool="create_file", args=None, **kw) -> IncomingCall:
    return IncomingCall(
        operation="tools/call",
        client_id="claude",
        server="demo",
        tool=tool,
        arguments=args if args is not None else {"path": "a.txt"},
        **kw,
    )


async def wait_for_pending(container, count=1, timeout=3.0):
    loop = asyncio.get_running_loop()
    deadline = loop.time() + timeout
    while loop.time() < deadline:
        from mcp_firewall.domain.enums.request_status import RequestStatus

        pending = await container.repo.list_requests(statuses={RequestStatus.PENDING_APPROVAL})
        if len(pending) >= count:
            return pending
        await asyncio.sleep(0.02)
    raise AssertionError("no pending request appeared")


async def audit_types(container, request_id):
    return [e.event_type for e in await container.audit_log.list_events(request_id=request_id)]


# --- the three outcomes the assignment demands ---------------------------------------------------


async def test_approved_request_is_executed_with_exact_arguments(env, approver_factory):
    container, upstream = env
    approver_factory(container, lambda v: "allow")
    out = await container.interception.intercept(incoming(args={"path": "a.txt", "content": "hi"}))
    assert out.status is S.COMPLETED and out.executed
    assert len(upstream.executed) == 1 and upstream.executed[0].arguments == {
        "path": "a.txt",
        "content": "hi",
    }
    types = await audit_types(container, out.request_id)
    assert types == [
        "request.received", "request.validated", "policy.evaluated", "approval.prompted",
        "approval.decided", "execution.started", "execution.finished",
    ]  # fmt: skip


async def test_blocked_request_never_reaches_upstream(env, approver_factory):
    container, upstream = env
    approver_factory(container, lambda v: "block")
    out = await container.interception.intercept(incoming())
    assert out.status is S.REJECTED and not out.executed and "blocked" in out.message
    assert upstream.executed == []
    assert (await container.repo.get(out.request_id)).status is S.REJECTED


async def test_timed_out_request_expires_and_never_executes(tmp_path):
    container, upstream = await make_container(tmp_path, approval_timeout_seconds=1.2)
    try:
        out = await container.interception.intercept(incoming())
        assert out.status is S.EXPIRED and upstream.executed == []
        assert "request.expired" in await audit_types(container, out.request_id)
    finally:
        await container.stop()


# --- policy ---------------------------------------------------------------------------------------


async def test_allow_rule_executes_without_prompt(env, approver_factory):
    container, upstream = env
    approver = approver_factory(container, lambda v: "block")
    out = await container.interception.intercept(incoming("echo", {"text": "x"}))
    assert out.status is S.COMPLETED and approver.seen == [] and len(upstream.executed) == 1
    assert (await container.repo.get(out.request_id)).decided_by == "policy:allow-echo"


async def test_deny_rule_blocks_without_prompt(env, approver_factory):
    container, upstream = env
    approver = approver_factory(container, lambda v: "allow")
    out = await container.interception.intercept(incoming("run_exec", {"cmd": "rm -rf /"}))
    assert out.status is S.DENIED and approver.seen == [] and upstream.executed == []


async def test_policy_reload_changes_decisions(env, tmp_path, approver_factory):
    container, upstream = env
    approver_factory(container, lambda v: "block")
    container.policies_file = tmp_path / "p.yaml"
    container.policies_file.write_text("default_action: allow\nrules: []\n")
    await container.reload_policy("tester")
    out = await container.interception.intercept(incoming("anything"))
    assert out.status is S.COMPLETED
    container.policies_file.write_text("rules: [{id: x, action: bogus}]")
    with pytest.raises(ValueError):
        await container.reload_policy("tester")
    out = await container.interception.intercept(incoming("anything"))  # old policy still active
    assert out.status is S.COMPLETED


# --- decision validation ---------------------------------------------------------------------------


async def test_decision_bound_to_hash_and_request(env):
    container, upstream = env
    task = asyncio.create_task(container.interception.intercept(incoming()))
    (rec,) = await wait_for_pending(container)
    with pytest.raises(HashMismatchError):
        await container.approve(APPROVER, rec.id, "0" * 64)
    with pytest.raises(UnknownRequestError):
        await container.approve(APPROVER, "no-such-id", rec.request.request_hash)
    assert (await container.repo.get(rec.id)).status is S.PENDING_APPROVAL
    await container.approve(APPROVER, rec.id, rec.request.request_hash)
    assert (await task).status is S.COMPLETED


async def test_duplicate_and_conflicting_decisions_do_not_double_execute(env):
    container, upstream = env
    task = asyncio.create_task(container.interception.intercept(incoming()))
    (rec,) = await wait_for_pending(container)
    h = rec.request.request_hash
    results = await asyncio.gather(
        container.approve(APPROVER, rec.id, h),
        container.approve(APPROVER, rec.id, h),
        container.reject(APPROVER, rec.id, h),
        container.approve(ADMIN, rec.id, h),
        return_exceptions=True,
    )
    assert sum(not isinstance(r, Exception) for r in results) == 1
    assert all(isinstance(r, AlreadyDecidedError) for r in results if isinstance(r, Exception))
    out = await task
    assert len(upstream.executed) == (1 if out.status is S.COMPLETED else 0)
    with pytest.raises(AlreadyDecidedError):
        await container.approve(APPROVER, rec.id, h)


async def test_late_decision_after_expiry_rejected(tmp_path):
    container, upstream = await make_container(tmp_path, approval_timeout_seconds=1.2)
    try:
        task = asyncio.create_task(container.interception.intercept(incoming()))
        (rec,) = await wait_for_pending(container)
        assert (await task).status is S.EXPIRED
        with pytest.raises(ApprovalExpiredError):
            await container.approve(APPROVER, rec.id, rec.request.request_hash)
        assert upstream.executed == []
    finally:
        await container.stop()


async def test_expiry_enforced_even_if_waiter_has_not_noticed(tmp_path):
    """A decision arriving after the deadline is refused by the repository, not just the waiter."""
    container, upstream = await make_container(tmp_path, approval_timeout_seconds=1.2)
    try:
        task = asyncio.create_task(container.interception.intercept(incoming()))
        (rec,) = await wait_for_pending(container)
        await asyncio.sleep(1.3)
        with pytest.raises((ApprovalExpiredError, AlreadyDecidedError)):
            await container.approve(APPROVER, rec.id, rec.request.request_hash)
        assert (await task).status is S.EXPIRED and upstream.executed == []
    finally:
        await container.stop()


async def test_viewer_cannot_decide_and_admin_rule_needs_admin(tmp_path):
    policy = {"rules": [{"id": "r", "action": "require_approval", "approver_role": "admin"}]}
    container, upstream = await make_container(tmp_path, policy=policy)
    try:
        task = asyncio.create_task(container.interception.intercept(incoming()))
        (rec,) = await wait_for_pending(container)
        h = rec.request.request_hash
        with pytest.raises(NotAuthorizedError):
            await container.approve(Principal("v", Role.VIEWER), rec.id, h)
        with pytest.raises(NotAuthorizedError):
            await container.approve(APPROVER, rec.id, h)
        await container.approve(ADMIN, rec.id, h)
        assert (await task).status is S.COMPLETED
    finally:
        await container.stop()


async def test_other_tenant_cannot_see_or_decide(env):
    container, _ = env
    task = asyncio.create_task(container.interception.intercept(incoming()))
    (rec,) = await wait_for_pending(container)
    outsider = Principal("eve", Role.APPROVER, tenant_id="other")
    with pytest.raises(UnknownRequestError):
        await container.approve(outsider, rec.id, rec.request.request_hash)
    await container.reject(APPROVER, rec.id, rec.request.request_hash)
    await task


async def test_strong_confirmation_required_for_high_risk(env):
    container, upstream = env
    task = asyncio.create_task(container.interception.intercept(incoming("delete_file", {"path": "x"})))
    (rec,) = await wait_for_pending(container)
    assert rec.strong_confirmation and rec.risk.level.name == "HIGH"
    with pytest.raises(StrongConfirmationRequired):
        await container.approve(APPROVER, rec.id, rec.request.request_hash, confirmed=False)
    assert upstream.executed == []
    await container.approve(APPROVER, rec.id, rec.request.request_hash, confirmed=True)
    assert (await task).status is S.COMPLETED
    # blocking never needs the extra confirmation step


# --- cancellation, failures, edge cases -----------------------------------------------------------------


async def test_client_cancellation_cancels_pending_and_blocks_later_approval(env):
    container, upstream = env
    task = asyncio.create_task(container.interception.intercept(incoming()))
    (rec,) = await wait_for_pending(container)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert (await container.repo.get(rec.id)).status is S.CANCELLED
    with pytest.raises(AlreadyDecidedError):
        await container.approve(APPROVER, rec.id, rec.request.request_hash)
    assert upstream.executed == [] and "request.cancelled" in await audit_types(container, rec.id)
    assert container.approvals.pending_count == 0


@pytest.mark.parametrize(
    "mode,status,executed",
    [
        ("unavailable", S.FAILED, 0),
        ("timeout", S.EXECUTION_UNKNOWN, 1),
        ("lost", S.EXECUTION_UNKNOWN, 1),
        ("error", S.EXECUTION_UNKNOWN, 1),
        ("tool_error", S.COMPLETED, 1),
    ],
)
async def test_upstream_failure_modes(env, approver_factory, mode, status, executed):
    container, upstream = env
    upstream.mode = mode
    approver_factory(container, lambda v: "allow")
    out = await container.interception.intercept(incoming())
    assert out.status is status and len(upstream.executed) == executed
    assert (await container.repo.get(out.request_id)).status is status


async def test_execution_unknown_is_not_retried(env, approver_factory):
    container, upstream = env
    upstream.mode = "lost"
    approver_factory(container, lambda v: "allow")
    await container.interception.intercept(incoming())
    await asyncio.sleep(0.2)
    assert len(upstream.executed) == 1


async def test_execution_timeout_marks_unknown(tmp_path, approver_factory):
    container, upstream = await make_container(tmp_path, execution_timeout_seconds=1.2)
    try:
        upstream.delay = 3
        approver_factory(container, lambda v: "allow")
        out = await container.interception.intercept(incoming())
        assert out.status is S.EXECUTION_UNKNOWN
    finally:
        await container.stop()


async def test_cancel_while_executing_marks_unknown(env, approver_factory):
    container, upstream = env
    upstream.delay = 2
    approver_factory(container, lambda v: "allow")
    task = asyncio.create_task(container.interception.intercept(incoming()))
    await asyncio.sleep(0.4)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    (rec,) = await container.repo.list_requests(limit=5)
    assert rec.status is S.EXECUTION_UNKNOWN


async def test_kill_switch_denies_new_and_stops_approved(env, approver_factory):
    container, upstream = env
    await container.set_kill_switch(True, "root")
    out = await container.interception.intercept(incoming("echo", {"text": "x"}))
    assert out.status is S.DENIED and upstream.executed == []
    await container.set_kill_switch(False, "root")
    assert (await container.interception.intercept(incoming("echo", {"text": "x"}))).status is S.COMPLETED
    # engaged between approval and dispatch
    task = asyncio.create_task(container.interception.intercept(incoming()))
    (rec,) = await wait_for_pending(container)
    await container.approve(APPROVER, rec.id, rec.request.request_hash)
    await container.set_kill_switch(True, "root")
    out = await task
    if out.status is not S.COMPLETED:  # kill switch won the race
        assert out.status is S.FAILED and len(upstream.executed) == 1


@pytest.mark.parametrize(
    "args",
    [{"v": float("nan")}, {"v": object()}, {"blob": "x" * 300_000}],
)
async def test_malformed_or_oversized_rejected_before_upstream(env, args):
    container, upstream = env
    out = await container.interception.intercept(incoming("echo", args))
    assert out.status is S.DENIED and upstream.executed == [] and out.request_id is None


async def test_schema_validation_failure_denied(env, approver_factory):
    container, upstream = env
    approver_factory(container, lambda v: "allow")
    schema = {"type": "object", "properties": {"path": {"type": "string"}}, "required": ["path"]}
    out = await container.interception.intercept(incoming(args={"path": 5}, input_schema=schema))
    assert out.status is S.DENIED and "schema" in out.message and upstream.executed == []
    out = await container.interception.intercept(incoming(args={}, input_schema=schema))
    assert out.status is S.DENIED


async def test_pending_queue_is_bounded(tmp_path):
    container, upstream = await make_container(tmp_path, max_pending_requests=3, approval_timeout_seconds=2)
    try:
        tasks = [
            asyncio.create_task(container.interception.intercept(incoming(args={"i": i}))) for i in range(3)
        ]
        await wait_for_pending(container, 3)
        out = await container.interception.intercept(incoming(args={"i": 99}))
        assert out.status is S.DENIED and "too many" in out.message
        for t in tasks:
            t.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
    finally:
        await container.stop()


async def test_secrets_redacted_for_humans_but_forwarded_intact(env, approver_factory):
    container, upstream = env
    approver = approver_factory(container, lambda v: "allow")
    out = await container.interception.intercept(
        incoming(args={"path": "a", "password": "hunter2", "note": "use sk-abcdefghijklmnopqrstuvwxyz1234"})
    )
    assert out.status is S.COMPLETED
    shown = approver.seen[0]["arguments"]
    assert "hunter2" not in shown and "sk-abcdef" not in shown and "[REDACTED]" in shown
    assert upstream.executed[0].arguments["password"] == "hunter2"
    meta = [e.metadata for e in await container.audit_log.list_events(request_id=out.request_id)]
    assert "hunter2" not in str(meta)


async def test_request_persisted_before_notification(env):
    container, _ = env
    sub = container.bus.subscribe()
    task = asyncio.create_task(container.interception.intercept(incoming()))
    event = None
    async for event in sub:
        if event.type == "approval.requested":
            break
    stored = await container.repo.get(event.request_id)
    assert stored is not None and stored.status is S.PENDING_APPROVAL
    await container.reject(APPROVER, stored.id, stored.request.request_hash)
    await task
    sub.close()


async def test_tool_schema_change_forces_renewed_approval(env, approver_factory):
    container, upstream = env
    approver = approver_factory(container, lambda v: "allow")

    def call(fp):
        return incoming("echo", {"text": "x"}, fingerprint=fp, description="d")

    assert (await container.interception.intercept(call("f1"))).status is S.COMPLETED
    assert approver.seen == []  # allow rule, trusted on first use
    out = await container.interception.intercept(call("f2"))  # definition changed -> must ask
    assert out.status is S.COMPLETED and len(approver.seen) == 1
    assert approver.seen[0]["schema_changed"] and approver.seen[0]["strong_confirmation"]
    assert (await container.interception.intercept(call("f2"))).status is S.COMPLETED
    assert len(approver.seen) == 1  # acknowledged after approval


async def test_schema_change_cannot_override_deny(env):
    container, upstream = env
    await container.interception.intercept(incoming("run_exec", {}, fingerprint="f1"))
    out = await container.interception.intercept(incoming("run_exec", {}, fingerprint="f2"))
    assert out.status is S.DENIED and upstream.executed == []


async def test_gateway_restart_recovery_reaps_abandoned_requests(tmp_path, env):
    container, _ = env
    from mcp_firewall.domain.entities.mcp_request import RequestRecord

    req = McpRequest.create(operation="tools/call", client_id="c", server="demo", tool="t", arguments={})
    import time

    stale = RequestRecord(
        request=req, status=S.PENDING_APPROVAL, created_at=time.time() - 500, expires_at=time.time() - 400
    )
    await container.repo.create(stale)
    assert await container.interception.sweep(30) == 1
    assert (await container.repo.get(stale.id)).status is S.EXPIRED
