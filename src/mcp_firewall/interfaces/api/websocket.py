"""WebSocket event stream used by the desktop agent and the web dashboard.

Protocol (JSON text frames):
  client -> {"type": "auth", "token": "..."}                 (first message, within 5 s)
  server -> {"type": "ready", "principal": {...}}
  server -> {"type": "snapshot", "pending": [ <request view>, ... ]}
  server -> {"type": "event", "event": {"type", "request_id", "payload"}}
  server -> {"type": "ping"}      client -> {"type": "pong"} | {"type": "refresh"}
Decisions are submitted over HTTPS/HTTP POST, never over this socket.
"""

from __future__ import annotations

import asyncio
import contextlib
import json

import structlog
from fastapi import APIRouter, WebSocket, WebSocketDisconnect

from mcp_firewall.application.services.views import record_view
from mcp_firewall.domain.entities.approval import Principal
from mcp_firewall.domain.enums.decision import Role
from mcp_firewall.domain.enums.request_status import RequestStatus
from mcp_firewall.infrastructure.events.event_bus import RESYNC
from mcp_firewall.interfaces.api.auth import client_ip, ws_blocked, ws_failure

log = structlog.get_logger("ws")
router = APIRouter()
AUTH_TIMEOUT = 5.0
PING_INTERVAL = 15.0
IDLE_TIMEOUT = 60.0
MAX_MESSAGE = 4096


class ConnectionRegistry:
    """Counts connected approver-capable clients (used to know whether anyone can answer a prompt)."""

    def __init__(self) -> None:
        self._active: set[int] = set()

    def add(self, ws: WebSocket) -> None:
        self._active.add(id(ws))

    def remove(self, ws: WebSocket) -> None:
        self._active.discard(id(ws))

    def count(self) -> int:
        return len(self._active)


def origin_allowed(origin: str | None, host: str | None, allowed: list[str]) -> bool:
    """Browsers always send Origin on websocket handshakes; native clients send none."""
    if not origin:
        return True
    if origin in allowed:
        return True
    return bool(host) and origin in (f"http://{host}", f"https://{host}")


async def _snapshot(container, principal: Principal) -> dict:
    tenant = None if principal.role is Role.ADMIN else principal.tenant_id
    records = await container.repo.list_requests(
        statuses={RequestStatus.PENDING_APPROVAL}, tenant_id=tenant, limit=500
    )
    return {"type": "snapshot", "pending": [record_view(r) for r in reversed(records)]}


@router.websocket("/api/v1/ws")
async def events_ws(ws: WebSocket) -> None:
    container = ws.app.state.container
    registry: ConnectionRegistry = ws.app.state.connections
    ip = client_ip(ws)
    if ws_blocked(ip) or not origin_allowed(
        ws.headers.get("origin"), ws.headers.get("host"), container.settings.allowed_origins
    ):
        await ws.close(code=1008)
        return
    await ws.accept()
    counted = False
    subscription = None
    try:
        try:
            raw = await asyncio.wait_for(ws.receive_text(), AUTH_TIMEOUT)
            message = json.loads(raw) if len(raw) <= MAX_MESSAGE else {}
        except (TimeoutError, ValueError, WebSocketDisconnect):
            ws_failure(ip)
            await ws.close(code=1008)
            return
        token = message.get("token") if isinstance(message, dict) and message.get("type") == "auth" else None
        principal = container.approver_auth.authenticate(token if isinstance(token, str) else None)
        if principal is None:
            ws_failure(ip)
            await ws.send_json({"type": "error", "error": "unauthorized"})
            await ws.close(code=1008)
            return

        subscription = (
            container.bus.subscribe()
        )  # subscribe BEFORE the snapshot: no gap, duplicates are harmless
        if principal.can(Role.APPROVER):
            registry.add(ws)
            counted = True
        await ws.send_json(
            {"type": "ready", "principal": {"id": principal.id, "role": principal.role.name.lower()}}
        )
        await ws.send_json(await _snapshot(container, principal))

        sender = asyncio.create_task(_pump_events(ws, container, principal, subscription))
        receiver = asyncio.create_task(_read_client(ws, container, principal))
        keepalive = asyncio.create_task(_ping_loop(ws))
        done, pending = await asyncio.wait({sender, receiver, keepalive}, return_when=asyncio.FIRST_COMPLETED)
        for task in pending:
            task.cancel()
        for task in done:
            with contextlib.suppress(WebSocketDisconnect, asyncio.CancelledError):
                task.result()
    except WebSocketDisconnect:
        pass
    except Exception:
        log.exception("ws_error")
    finally:
        if subscription is not None:
            subscription.close()
        if counted:
            registry.remove(ws)
        with contextlib.suppress(Exception):
            await ws.close()


async def _pump_events(ws: WebSocket, container, principal: Principal, subscription) -> None:
    async for event in subscription:
        if event.type == RESYNC:
            await ws.send_json(await _snapshot(container, principal))
            continue
        if principal.role is not Role.ADMIN and event.tenant_id != principal.tenant_id:
            continue
        await ws.send_json(
            {
                "type": "event",
                "event": {"type": event.type, "request_id": event.request_id, "payload": event.payload},
            }
        )


async def _read_client(ws: WebSocket, container, principal: Principal) -> None:
    while True:
        try:
            raw = await asyncio.wait_for(ws.receive_text(), IDLE_TIMEOUT)
        except TimeoutError:
            return
        if len(raw) > MAX_MESSAGE:
            return
        with contextlib.suppress(ValueError):
            message = json.loads(raw)
            if isinstance(message, dict) and message.get("type") == "refresh":
                await ws.send_json(await _snapshot(container, principal))


async def _ping_loop(ws: WebSocket) -> None:
    while True:
        await asyncio.sleep(PING_INTERVAL)
        await ws.send_json({"type": "ping"})
