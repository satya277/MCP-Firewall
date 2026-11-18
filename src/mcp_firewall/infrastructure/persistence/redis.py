"""Redis pub/sub event bus for multi-worker deployments (``redis`` extra)."""

from __future__ import annotations

import asyncio
import contextlib
import dataclasses
import json
from uuid import uuid4

import structlog

from mcp_firewall.application.interfaces.event_publisher import FirewallEvent
from mcp_firewall.infrastructure.events.event_bus import InMemoryEventBus, Subscription

log = structlog.get_logger("redis-bus")
CHANNEL = "mcpfw:events"


class RedisEventBus:
    """Publishes to Redis and fans incoming messages (including our own) out to local subscribers."""

    def __init__(self, url: str, channel: str = CHANNEL) -> None:
        self._url = url
        self._channel = channel
        self._local = InMemoryEventBus()
        self._client = None
        self._reader: asyncio.Task[None] | None = None

    async def start(self) -> None:
        import redis.asyncio as aioredis

        self._client = aioredis.from_url(self._url, decode_responses=True, socket_timeout=10)
        await self._client.ping()  # fail fast: an unreachable bus means approvals cannot be coordinated
        self._reader = asyncio.create_task(self._read_loop(), name="redis-bus-reader")

    async def stop(self) -> None:
        if self._reader:
            self._reader.cancel()
            with contextlib.suppress(asyncio.CancelledError, Exception):
                await self._reader
        if self._client:
            await self._client.aclose()
        await self._local.stop()

    async def ping(self) -> bool:
        try:
            return bool(self._client and await self._client.ping())
        except Exception:
            return False

    def subscribe(self) -> Subscription:
        return self._local.subscribe()

    def subscriber_count(self) -> int:
        return self._local.subscriber_count()

    async def publish(self, event: FirewallEvent) -> None:
        if self._client is None:
            raise RuntimeError("redis bus not started")
        if not event.event_id:
            event = dataclasses.replace(event, event_id=str(uuid4()))
        await self._client.publish(self._channel, json.dumps(dataclasses.asdict(event), default=str))

    async def _read_loop(self) -> None:
        backoff = 0.5
        while True:
            try:
                pubsub = self._client.pubsub()
                await pubsub.subscribe(self._channel)
                backoff = 0.5
                async for message in pubsub.listen():
                    if message.get("type") != "message":
                        continue
                    try:
                        self._local.deliver(FirewallEvent(**json.loads(message["data"])))
                    except Exception:
                        log.exception("bad_event_message")
            except asyncio.CancelledError:
                raise
            except Exception:
                log.warning("redis_bus_reconnecting", delay=backoff)
                await asyncio.sleep(backoff)
                backoff = min(backoff * 2, 10)
