"""In-process event bus with bounded per-subscriber queues and duplicate suppression."""

from __future__ import annotations

import asyncio
import dataclasses
from collections import OrderedDict
from uuid import uuid4

import structlog

from mcp_firewall.application.interfaces.event_publisher import FirewallEvent

log = structlog.get_logger("events")
RESYNC = "resync"  # tells a lagging consumer to re-fetch state instead of trusting the stream


class Subscription:
    """Registered immediately on creation, so no event published afterwards can be missed."""

    def __init__(self, bus: InMemoryEventBus, maxsize: int) -> None:
        self._bus = bus
        self.queue: asyncio.Queue[FirewallEvent] = asyncio.Queue(maxsize=maxsize)
        bus._subs.add(self)

    def __aiter__(self) -> Subscription:
        return self

    async def __anext__(self) -> FirewallEvent:
        try:
            return await self.queue.get()
        except asyncio.CancelledError:
            self.close()
            raise

    def close(self) -> None:
        self._bus._subs.discard(self)

    async def aclose(self) -> None:
        self.close()

    def offer(self, event: FirewallEvent) -> None:
        if self.queue.full():
            while not self.queue.empty():
                self.queue.get_nowait()
            log.warning("subscriber_lagging_resync")
            event = FirewallEvent(type=RESYNC, event_id=str(uuid4()))
        self.queue.put_nowait(event)


class InMemoryEventBus:
    def __init__(self, queue_size: int = 1000, dedup_window: int = 2000) -> None:
        self._subs: set[Subscription] = set()
        self._queue_size = queue_size
        self._seen: OrderedDict[str, None] = OrderedDict()
        self._dedup_window = dedup_window

    async def start(self) -> None:
        return None

    async def stop(self) -> None:
        for sub in list(self._subs):
            sub.close()

    def subscribe(self) -> Subscription:
        return Subscription(self, self._queue_size)

    def subscriber_count(self) -> int:
        return len(self._subs)

    async def publish(self, event: FirewallEvent) -> None:
        if not event.event_id:
            event = dataclasses.replace(event, event_id=str(uuid4()))
        self.deliver(event)

    def deliver(self, event: FirewallEvent) -> None:
        if event.event_id in self._seen:  # idempotent: ignore duplicate deliveries
            return
        self._seen[event.event_id] = None
        while len(self._seen) > self._dedup_window:
            self._seen.popitem(last=False)
        for sub in list(self._subs):
            sub.offer(event)
