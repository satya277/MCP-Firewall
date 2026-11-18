"""Qt-free client for the approval API: websocket event stream + HTTP decisions."""

from __future__ import annotations

import asyncio
import contextlib
import json
from collections.abc import Callable

import httpx
import structlog
import websockets

log = structlog.get_logger("approval-client")


class ApprovalClient:
    """Maintains the live set of pending requests of ONE gateway endpoint (local or remote)."""

    def __init__(
        self,
        name: str,
        base_url: str,
        token: str,
        *,
        on_snapshot: Callable[[str, list[dict]], None],
        on_event: Callable[[str, dict], None],
        on_state: Callable[[str, bool], None],
        on_giveup: Callable[[str], None] | None = None,
        max_failures: int | None = None,
    ) -> None:
        self.name = name
        self._base = base_url.rstrip("/")
        self._token = token
        self._ws_url = (
            self._base.replace("https://", "wss://", 1).replace("http://", "ws://", 1) + "/api/v1/ws"
        )
        self._on_snapshot = on_snapshot
        self._on_event = on_event
        self._on_state = on_state
        self._on_giveup = on_giveup
        self._max_failures = max_failures
        self._task: asyncio.Task[None] | None = None
        self._http = httpx.AsyncClient(
            base_url=self._base, timeout=10.0, headers={"Authorization": f"Bearer {token}"}
        )
        self.connected = False

    def start(self) -> None:
        self._task = asyncio.create_task(self._run(), name=f"approval-client-{self.name}")

    async def stop(self) -> None:
        if self._task:
            self._task.cancel()
            with contextlib.suppress(asyncio.CancelledError, Exception):
                await self._task
        await self._http.aclose()

    async def _run(self) -> None:
        backoff, failures = 0.5, 0
        while True:
            try:
                async with websockets.connect(self._ws_url, max_size=2**20, open_timeout=8) as ws:
                    await ws.send(json.dumps({"type": "auth", "token": self._token}))
                    async for raw in ws:
                        message = json.loads(raw)
                        kind = message.get("type")
                        if kind == "ready":
                            self._set_state(True)
                            backoff = 0.5
                            failures = 0
                        elif kind == "snapshot":
                            self._on_snapshot(self.name, message.get("pending", []))
                        elif kind == "event":
                            self._on_event(self.name, message["event"])
                        elif kind == "ping":
                            await ws.send(json.dumps({"type": "pong"}))
                        elif kind == "error":
                            log.warning("endpoint_rejected_token", endpoint=self.name)
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                log.debug("endpoint_connection_error", endpoint=self.name, error=type(exc).__name__)
            self._set_state(False)
            failures += 1
            if self._max_failures and failures >= self._max_failures:
                if self._on_giveup:
                    self._on_giveup(self.name)
                return
            await asyncio.sleep(backoff)
            backoff = min(backoff * 2, 10)

    def _set_state(self, connected: bool) -> None:
        if connected != self.connected:
            self.connected = connected
            self._on_state(self.name, connected)

    async def decide(
        self,
        request_id: str,
        request_hash: str,
        decision: str,
        *,
        confirm: bool = False,
        reason: str | None = None,
    ) -> tuple[bool, str]:
        """Returns (ok, human-readable message). Never raises: a failed decision must not crash the UI."""
        try:
            res = await self._http.post(
                f"/api/v1/requests/{request_id}/decision",
                json={
                    "decision": decision,
                    "request_hash": request_hash,
                    "confirm": confirm,
                    "reason": reason,
                },
            )
        except httpx.HTTPError as exc:
            return False, f"Could not reach the gateway ({type(exc).__name__}). The request stays pending."
        if res.status_code == 200:
            return True, "ok"
        try:
            message = res.json().get("message") or res.json().get("error") or res.text
        except ValueError:
            message = res.text
        return False, f"{res.status_code}: {message}"[:300]
