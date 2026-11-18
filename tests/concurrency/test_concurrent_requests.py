"""Concurrency tests: many simultaneous requests must never cross-talk or double-execute."""

from __future__ import annotations

import asyncio
import gc
import random
import time
import tracemalloc

from mcp_firewall.domain.enums.request_status import RequestStatus as S
from tests.conftest import APPROVER, FakeUpstream, make_container
from tests.integration.test_pipeline import incoming, wait_for_pending

N = 100


async def test_100_simultaneous_requests_have_independent_outcomes(tmp_path, approver_factory):
    container, upstream = await make_container(
        tmp_path, approval_timeout_seconds=20, max_pending_requests=500
    )
    try:
        rng = random.Random(1234)
        verdict = {i: rng.choice(["allow", "block"]) for i in range(N)}

        async def decide(view):
            i = json_i(view)
            await asyncio.sleep(rng.random() * 0.5)  # decisions arrive out of order
            return verdict[i]

        approver = approver_factory(container, decide)
        started = time.perf_counter()
        outcomes = await asyncio.gather(
            *[container.interception.intercept(incoming("create_file", {"i": i})) for i in range(N)]
        )
        elapsed = time.perf_counter() - started

        for i, out in enumerate(outcomes):
            if verdict[i] == "allow":
                assert out.status is S.COMPLETED, (i, out)
                assert out.result.payload["echo"] == {"i": i}  # response belongs to THIS request
            else:
                assert out.status is S.REJECTED and out.result is None, (i, out)
        executed = sorted(r.arguments["i"] for r in upstream.executed)
        assert executed == sorted(i for i, v in verdict.items() if v == "allow")  # no extra, no missing
        assert len(upstream.executed) == len({r.arguments["i"] for r in upstream.executed})  # no duplicates
        assert not approver.errors
        assert container.approvals.pending_count == 0 and container.approvals._waiters == {}
        ok, _, err = await container.audit_log.verify_chain()
        assert ok, err
        assert elapsed < 30, f"{N} requests took {elapsed:.1f}s"
    finally:
        await container.stop()


def json_i(view) -> int:
    import json

    return json.loads(view["arguments"])["i"]


async def test_decision_for_one_request_never_releases_another(tmp_path):
    container, upstream = await make_container(tmp_path, approval_timeout_seconds=20)
    try:
        tasks = [
            asyncio.create_task(container.interception.intercept(incoming("create_file", {"i": i})))
            for i in range(10)
        ]
        pending = await wait_for_pending(container, 10)
        target = next(p for p in pending if p.request.arguments["i"] == 7)
        await container.approve(APPROVER, target.id, target.request.request_hash)
        await asyncio.sleep(0.5)
        assert [r.arguments["i"] for r in upstream.executed] == [7]
        done = [t for t in tasks if t.done()]
        assert len(done) == 1 and done[0].result().request_id == target.id
        for p in pending:  # clean up the rest
            if p.id != target.id:
                await container.reject(APPROVER, p.id, p.request.request_hash)
        await asyncio.gather(*tasks)
    finally:
        await container.stop()


async def test_decision_storm_executes_at_most_once(tmp_path):
    container, upstream = await make_container(tmp_path, approval_timeout_seconds=20)
    try:
        tasks = [
            asyncio.create_task(container.interception.intercept(incoming("create_file", {"i": i})))
            for i in range(20)
        ]
        pending = await wait_for_pending(container, 20)
        storm = []
        for p in pending:
            for _ in range(10):  # ten racing approvers/blockers per request
                fn = container.approve if random.random() < 0.7 else container.reject
                storm.append(fn(APPROVER, p.id, p.request.request_hash))
        results = await asyncio.gather(*storm, return_exceptions=True)
        assert sum(not isinstance(r, Exception) for r in results) == 20  # exactly one winner per request
        outs = await asyncio.gather(*tasks)
        approved = {o.request_id for o in outs if o.status is S.COMPLETED}
        assert len(upstream.executed) == len(approved)
        assert len({tuple(r.arguments.items()) for r in upstream.executed}) == len(upstream.executed)
    finally:
        await container.stop()


async def test_cancellation_and_timeout_under_load(tmp_path):
    container, upstream = await make_container(
        tmp_path, approval_timeout_seconds=2.5, max_pending_requests=500
    )
    try:
        tasks = {
            i: asyncio.create_task(container.interception.intercept(incoming("create_file", {"i": i})))
            for i in range(60)
        }
        pending = {p.request.arguments["i"]: p for p in await wait_for_pending(container, 60)}
        approved = set(range(0, 60, 3))
        cancelled = set(range(1, 60, 3))  # the rest simply time out
        for i in cancelled:
            tasks[i].cancel()
        await asyncio.sleep(0.1)
        for i in approved:
            await container.approve(APPROVER, pending[i].id, pending[i].request.request_hash)
        results = await asyncio.gather(*tasks.values(), return_exceptions=True)
        for i, res in zip(tasks, results, strict=True):
            if i in cancelled:
                assert isinstance(res, asyncio.CancelledError)
            elif i in approved:
                assert res.status is S.COMPLETED
            else:
                assert res.status is S.EXPIRED
        assert {r.arguments["i"] for r in upstream.executed} == approved
        statuses = {p.id: (await container.repo.get(p.id)).status for p in pending.values()}
        assert all(s.is_terminal for s in statuses.values())
        assert container.approvals.pending_count == 0
        late = [i for i in cancelled | (set(range(60)) - approved - cancelled)]
        for i in late[:5]:
            try:
                await container.approve(APPROVER, pending[i].id, pending[i].request.request_hash)
                raise AssertionError("late approval accepted")
            except AssertionError:
                raise
            except Exception:
                pass
        assert len(upstream.executed) == len(approved)
    finally:
        await container.stop()


async def test_per_server_concurrency_limit_respected(tmp_path, approver_factory):
    container, _ = await make_container(tmp_path, max_concurrent_per_server=4, approval_timeout_seconds=20)
    upstream = FakeUpstream()
    live = {"now": 0, "max": 0}
    original = upstream.execute

    async def tracked(request):
        live["now"] += 1
        live["max"] = max(live["max"], live["now"])
        try:
            await asyncio.sleep(0.1)
            return await original(request)
        finally:
            live["now"] -= 1

    upstream.execute = tracked  # type: ignore[method-assign]
    container.executor._upstream = upstream
    try:
        approver_factory(container, lambda v: "allow")
        outs = await asyncio.gather(
            *[container.interception.intercept(incoming("create_file", {"i": i})) for i in range(24)]
        )
        assert all(o.status is S.COMPLETED for o in outs)
        assert live["max"] <= 4
    finally:
        await container.stop()


async def test_memory_and_tasks_are_released_after_load(tmp_path, approver_factory):
    container, upstream = await make_container(
        tmp_path, approval_timeout_seconds=20, max_pending_requests=500
    )
    try:
        approver_factory(container, lambda v: "allow")
        await asyncio.gather(
            *[container.interception.intercept(incoming("create_file", {"i": i})) for i in range(30)]
        )  # warm up
        gc.collect()
        tracemalloc.start()
        before = tracemalloc.take_snapshot()
        tasks_before = len(asyncio.all_tasks())
        for _ in range(3):
            await asyncio.gather(
                *[container.interception.intercept(incoming("create_file", {"i": i})) for i in range(N)]
            )
        gc.collect()
        grown = sum(
            s.size_diff for s in tracemalloc.take_snapshot().compare_to(before, "filename") if s.size_diff > 0
        )
        tracemalloc.stop()
        assert len(asyncio.all_tasks()) <= tasks_before + 2  # no leaked waiters
        assert container.approvals._waiters == {} and container.approvals.pending_count == 0
        assert grown < 25_000_000, f"memory grew by {grown / 1e6:.1f} MB"  # audit/event buffers are bounded
    finally:
        await container.stop()
