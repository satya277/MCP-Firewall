"""Event distribution ports (in-memory bus locally, Redis across workers)."""

from __future__ import annotations

import time
from collections.abc import AsyncIterator
from dataclasses import dataclass, field
from typing import Any, Protocol, runtime_checkable


class EventType:
    APPROVAL_REQUESTED = "approval.requested"
    APPROVAL_DECIDED = "approval.decided"
    REQUEST_UPDATED = "request.updated"
    KILL_SWITCH = "killswitch.changed"


@dataclass(frozen=True, slots=True)
class FirewallEvent:
    type: str
    request_id: str | None = None
    tenant_id: str = "default"
    payload: dict[str, Any] = field(default_factory=dict)
    ts: float = field(default_factory=time.time)
    # Unique per event so duplicate deliveries can be ignored by consumers.
    event_id: str = ""


@runtime_checkable
class EventPublisher(Protocol):
    async def publish(self, event: FirewallEvent) -> None: ...


@runtime_checkable
class EventSubscriber(Protocol):
    def subscribe(self) -> AsyncIterator[FirewallEvent]:
        """Async-iterate events until cancelled. Each call gets an independent stream."""
        ...


@runtime_checkable
class EventBus(EventPublisher, EventSubscriber, Protocol):
    async def start(self) -> None: ...

    async def stop(self) -> None: ...

    def subscriber_count(self) -> int: ...
