"""Multi-worker coordination through the Redis event bus (fakeredis by default, real Redis if provided)."""

from __future__ import annotations

import asyncio
import os

import pytest
from cryptography.fernet import Fernet

fakeredis = pytest.importorskip("fakeredis")

import redis.asyncio as aioredis  # noqa: E402

from mcp_firewall.application.interfaces.event_publisher import FirewallEvent  # noqa: E402
from mcp_firewall.bootstrap import build_container  # noqa: E402
from mcp_firewall.config import parse_policy  # noqa: E402
from mcp_firewall.domain.enums.request_status import RequestStatus as S  # noqa: E402
from mcp_firewall.infrastructure.persistence.redis import RedisEventBus  # noqa: E402
from mcp_firewall.infrastructure.persistence.sqlite import SqliteDatabase  # noqa: E402
from mcp_firewall.infrastructure.security.secrets_manager import SecretBox  # noqa: E402
from tests.conftest import APPROVER, DEFAULT_POLICY, FakeUpstream, make_settings  # noqa: E402
from tests.integration.test_pipeline import incoming, wait_for_pending  # noqa: E402

REAL_REDIS = os.environ.get("MCPFW_TEST_REDIS_URL")


@pytest.fixture
def redis_url(monkeypatch):
    if REAL_REDIS:
        return REAL_REDIS
    server = fakeredis.FakeServer()
    monkeypatch.setattr(
        aioredis,
        "from_url",
        lambda url, **kw: fakeredis.aioredis.FakeRedis(server=server, decode_responses=True),
    )
    return "redis://fake:6379/0"


async def test_events_cross_workers_and_dedupe(redis_url):
    a, b = RedisEventBus(redis_url, channel="t1"), RedisEventBus(redis_url, channel="t1")
    await a.start()
    await b.start()
    try:
        sub_b = b.subscribe()
        await asyncio.sleep(0.2)
        await a.publish(
            FirewallEvent(type="approval.requested", request_id="r1", payload={"x": 1}, event_id="e1")
        )
        await a.publish(
            FirewallEvent(type="approval.requested", request_id="r1", payload={"x": 1}, event_id="e1")
        )
        got = await asyncio.wait_for(sub_b.__anext__(), 3)
        assert got.request_id == "r1" and got.payload == {"x": 1}
        await asyncio.sleep(0.3)
        assert sub_b.queue.empty()  # duplicate delivery ignored
        assert await a.ping()
    finally:
        await a.stop()
        await b.stop()


async def test_bus_unavailable_fails_fast(monkeypatch):
    class Dead:
        async def ping(self):
            raise ConnectionError("down")

    monkeypatch.setattr(aioredis, "from_url", lambda url, **kw: Dead())
    with pytest.raises(ConnectionError):
        await RedisEventBus("redis://nowhere").start()


async def test_decision_on_worker_b_releases_waiter_on_worker_a(tmp_path, redis_url):
    """Worker A holds the open request; worker B (another process in production) receives the decision."""
    db_path = tmp_path / "shared.db"
    key = Fernet.generate_key()

    def worker(name):
        c = build_container(
            make_settings(tmp_path / name, approval_timeout_seconds=20),
            policy=parse_policy(DEFAULT_POLICY),
            upstream=upstream if name == "a" else FakeUpstream(),  # type: ignore[arg-type]
            db=SqliteDatabase(db_path),
            bus=RedisEventBus(redis_url, channel="coord"),  # type: ignore[arg-type]
            box=SecretBox(key),
        )
        c.approvals._poll_interval = 30  # prove the bus (not polling) wakes the waiter
        return c

    upstream = FakeUpstream()
    a, b = worker("a"), worker("b")
    await a.start()
    await b.start()
    try:
        task = asyncio.create_task(a.interception.intercept(incoming()))
        (rec,) = await wait_for_pending(b)  # B sees A's request through the shared database
        started = asyncio.get_running_loop().time()
        await b.approve(APPROVER, rec.id, rec.request.request_hash)
        out = await asyncio.wait_for(task, 5)
        assert out.status is S.COMPLETED and len(upstream.executed) == 1
        assert asyncio.get_running_loop().time() - started < 3  # well under the 30s poll interval
        # a second decision from either worker is refused: only one winner across workers
        with pytest.raises(Exception, match="already"):
            await a.approve(APPROVER, rec.id, rec.request.request_hash)
    finally:
        await a.stop()
        await b.stop()
