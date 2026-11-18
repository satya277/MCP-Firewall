"""UI-independent core of the desktop agent: endpoint discovery, pending-request state, decisions."""

from __future__ import annotations

import asyncio
import contextlib
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

import structlog
import yaml

from mcp_firewall.infrastructure.discovery import (
    list_gateways,
    pid_alive,
    touch_heartbeat,
)
from mcp_firewall.infrastructure.security.secrets_manager import resolve_refs
from mcp_firewall.interfaces.desktop.client import ApprovalClient

log = structlog.get_logger("agent-core")
LOCAL_PREFIX = "local:"


@dataclass(frozen=True, slots=True)
class RemoteEndpoint:
    name: str
    url: str
    token: str


def load_remotes(path: Path) -> list[RemoteEndpoint]:
    data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    remotes = []
    for item in data.get("remotes", []):
        url = resolve_refs(str(item["url"]))
        if (
            not url.startswith("https://")
            and not url.startswith("http://127.0.0.1")
            and not url.startswith("http://localhost")
        ):
            raise ValueError(f"remote {item['name']!r}: only https:// (or loopback http) URLs are allowed")
        remotes.append(RemoteEndpoint(str(item["name"]), url, resolve_refs(str(item["token"]))))
    return remotes


class AgentCore:
    """Tracks every pending request across all endpoints and routes decisions back to the right one."""

    def __init__(
        self,
        run_dir: Path,
        remotes: list[RemoteEndpoint] | None = None,
        *,
        on_changed: Callable[[], None] | None = None,
        on_new: Callable[[dict], None] | None = None,
        on_resolved: Callable[[str], None] | None = None,
        on_connection: Callable[[int, int], None] | None = None,
        auto_decider: Callable[[dict], str | None] | None = None,
    ) -> None:
        self._run_dir = run_dir
        self._remotes = remotes or []
        self._on_changed = on_changed or (lambda: None)
        self._on_new = on_new or (lambda view: None)
        self._on_resolved = on_resolved or (lambda request_id: None)
        self._on_connection = on_connection or (lambda connected, total: None)
        self._auto = auto_decider
        self._clients: dict[str, ApprovalClient] = {}
        self._pending: dict[str, dict] = {}  # request id -> view (+ "_endpoint")
        self._tasks: list[asyncio.Task[None]] = []
        self._stopping = False

    # -- public state ----------------------------------------------------------------------
    def pending(self) -> list[dict]:
        return sorted(self._pending.values(), key=lambda v: v["created_at"])

    def endpoint_count(self) -> tuple[int, int]:
        return sum(c.connected for c in self._clients.values()), len(self._clients)

    # -- lifecycle -------------------------------------------------------------------------
    async def start(self) -> None:
        for remote in self._remotes:
            self._add_client(f"remote:{remote.name}", remote.url, remote.token)
        self._tasks = [
            asyncio.create_task(self._watch_local(), name="watch-local"),
            asyncio.create_task(self._heartbeat(), name="heartbeat"),
        ]

    async def stop(self) -> None:
        self._stopping = True
        for task in self._tasks:
            task.cancel()
        await asyncio.gather(*self._tasks, return_exceptions=True)
        await asyncio.gather(*(c.stop() for c in self._clients.values()), return_exceptions=True)

    async def _heartbeat(self) -> None:
        while True:
            with contextlib.suppress(OSError):
                touch_heartbeat(self._run_dir)
            await asyncio.sleep(2)

    async def _watch_local(self) -> None:
        while True:
            seen: set[str] = set()
            for path, info in list_gateways(self._run_dir):
                key = f"{LOCAL_PREFIX}{info.pid}"
                seen.add(key)
                if key not in self._clients:
                    log.info("gateway_discovered", pid=info.pid, servers=info.servers)
                    self._add_client(key, info.url, info.token, path=path, pid=info.pid)
            for key in [k for k in self._clients if k.startswith(LOCAL_PREFIX) and k not in seen]:
                await self._drop(key)
            await asyncio.sleep(1)

    def _add_client(
        self, key: str, url: str, token: str, *, path: Path | None = None, pid: int | None = None
    ) -> None:
        def giveup(name: str) -> None:
            if path is not None and pid is not None and not pid_alive(pid):
                with contextlib.suppress(OSError):
                    path.unlink()  # stale file of a dead gateway
            asyncio.get_running_loop().create_task(self._drop(name))

        client = ApprovalClient(
            key,
            url,
            token,
            on_snapshot=self._snapshot,
            on_event=self._event,
            on_state=self._state,
            on_giveup=giveup if key.startswith(LOCAL_PREFIX) else None,
            max_failures=6 if key.startswith(LOCAL_PREFIX) else None,
        )
        self._clients[key] = client
        client.start()
        self._on_connection(*self.endpoint_count())

    async def _drop(self, key: str) -> None:
        client = self._clients.pop(key, None)
        if client is None:
            return
        await client.stop()
        gone = [rid for rid, v in self._pending.items() if v["_endpoint"] == key]
        for rid in gone:
            self._pending.pop(rid, None)
            self._on_resolved(rid)
        self._on_changed()
        self._on_connection(*self.endpoint_count())

    # -- callbacks from clients --------------------------------------------------------------
    def _state(self, endpoint: str, connected: bool) -> None:
        if not connected:
            gone = [rid for rid, v in self._pending.items() if v["_endpoint"] == endpoint]
            for rid in gone:  # we can no longer act on these; the gateway keeps them pending until expiry
                self._pending.pop(rid, None)
                self._on_resolved(rid)
            if gone:
                self._on_changed()
        self._on_connection(*self.endpoint_count())

    def _snapshot(self, endpoint: str, views: list[dict]) -> None:
        current = {v["id"] for v in views}
        for rid in [r for r, v in self._pending.items() if v["_endpoint"] == endpoint and r not in current]:
            self._pending.pop(rid, None)
            self._on_resolved(rid)
        for view in views:
            self._add(endpoint, view)
        self._on_changed()

    def _event(self, endpoint: str, event: dict) -> None:
        kind, payload, rid = event.get("type"), event.get("payload") or {}, event.get("request_id")
        if kind == "approval.requested":
            self._add(endpoint, payload)
        elif kind in ("approval.decided", "request.updated") and rid:
            view = payload.get("request", payload)
            if view.get("status") != "PENDING_APPROVAL" and self._pending.pop(rid, None) is not None:
                self._on_resolved(rid)
        self._on_changed()

    def _add(self, endpoint: str, view: dict) -> None:
        if view["id"] in self._pending:
            return
        view = {**view, "_endpoint": endpoint}
        self._pending[view["id"]] = view
        if self._auto is not None:
            verdict = self._auto(view)
            if verdict:
                asyncio.get_running_loop().create_task(
                    self.decide(view["id"], verdict, confirm=True, reason="auto")
                )
                return
        self._on_new(view)

    # -- decisions --------------------------------------------------------------------------
    async def decide(
        self, request_id: str, decision: str, *, confirm: bool = False, reason: str | None = None
    ) -> tuple[bool, str]:
        view = self._pending.get(request_id)
        if view is None:
            return False, "This request is no longer pending."
        client = self._clients.get(view["_endpoint"])
        if client is None:
            return False, "The gateway is no longer connected."
        ok, message = await client.decide(
            request_id, view["request_hash"], decision, confirm=confirm, reason=reason
        )
        if ok:
            self._pending.pop(request_id, None)
            self._on_resolved(request_id)
            self._on_changed()
        return ok, message
