"""Shared test fixtures: in-memory containers, a controllable fake upstream and a scripted approver."""

from __future__ import annotations

import asyncio
import json
import sys
from collections.abc import Awaitable, Callable
from pathlib import Path
from typing import Any

import pytest
from cryptography.fernet import Fernet

from mcp_firewall.application.interfaces.upstream import ToolInfo, UpstreamResult
from mcp_firewall.bootstrap import Container, build_container
from mcp_firewall.config import Settings, parse_policy
from mcp_firewall.domain.entities.approval import Principal
from mcp_firewall.domain.entities.mcp_request import McpRequest
from mcp_firewall.domain.enums.decision import Role
from mcp_firewall.domain.exceptions import (
    UpstreamCommunicationError,
    UpstreamTimeoutError,
    UpstreamUnavailableError,
)
from mcp_firewall.infrastructure.persistence.sqlite import SqliteDatabase
from mcp_firewall.infrastructure.security.secrets_manager import SecretBox

ROOT = Path(__file__).resolve().parent.parent
PYTHON = sys.executable

APPROVER = Principal("alice", Role.APPROVER)
ADMIN = Principal("root", Role.ADMIN)

DEFAULT_POLICY: dict[str, Any] = {
    "default_action": "require_approval",
    "rules": [
        {"id": "deny-exec", "action": "deny", "priority": 1000, "tools": ["*exec*"]},
        {"id": "allow-echo", "action": "allow", "priority": 100, "tools": ["echo"]},
        {
            "id": "confirm-delete",
            "action": "require_approval",
            "priority": 200,
            "tools": ["delete_*"],
            "risk": "high",
            "strong_confirmation": True,
        },
    ],
}


class FakeUpstream:
    """Records every execution; can simulate latency and failures."""

    def __init__(self) -> None:
        self.executed: list[McpRequest] = []
        self.delay = 0.0
        self.mode = "ok"  # ok | unavailable | timeout | lost | error | tool_error
        self.tools: list[ToolInfo] = []

    def server_names(self) -> list[str]:
        return ["demo"]

    async def list_tools(self) -> list[ToolInfo]:
        return self.tools

    async def start(self) -> None: ...

    async def stop(self) -> None: ...

    def health(self) -> dict:
        return {"demo": {"connected": True, "error": None}}

    async def execute(self, request: McpRequest) -> UpstreamResult:
        if self.mode == "unavailable":
            raise UpstreamUnavailableError("down")
        if self.delay:
            await asyncio.sleep(self.delay)
        self.executed.append(request)  # "reached the upstream"
        if self.mode == "timeout":
            raise UpstreamTimeoutError("slow")
        if self.mode == "lost":
            raise UpstreamCommunicationError("lost")
        if self.mode == "error":
            raise RuntimeError("boom")
        return UpstreamResult(self.mode == "tool_error", {"echo": request.arguments}, "ok")


def make_settings(tmp_path: Path, **overrides: Any) -> Settings:
    base = {
        "home": tmp_path / "home",
        "approval_timeout_seconds": 5.0,
        "execution_timeout_seconds": 5.0,
        "max_pending_requests": 100,
    }
    base.update(overrides)
    return Settings(_env_file=None, **base)


async def make_container(
    tmp_path: Path,
    *,
    policy: dict[str, Any] | None = None,
    upstream: FakeUpstream | None = None,
    **settings: Any,
) -> tuple[Container, FakeUpstream]:
    upstream = upstream or FakeUpstream()
    container = build_container(
        make_settings(tmp_path, **settings),
        policy=parse_policy(policy or DEFAULT_POLICY),
        upstream=upstream,  # type: ignore[arg-type]
        db=SqliteDatabase(":memory:"),
        box=SecretBox(Fernet.generate_key()),
    )
    await container.start()
    return container, upstream


@pytest.fixture
async def env(tmp_path: Path):
    container, upstream = await make_container(tmp_path)
    try:
        yield container, upstream
    finally:
        await container.stop()


class ScriptedApprover:
    """Listens for approval prompts and answers them using ``decide(view) -> 'allow' | 'block' | None``."""

    def __init__(
        self,
        container: Container,
        decide: Callable[[dict], Awaitable[str | None] | str | None],
        principal: Principal = APPROVER,
        confirm: bool = True,
    ) -> None:
        self.container = container
        self._decide = decide
        self.principal = principal
        self.confirm = confirm
        self.seen: list[dict] = []
        self.errors: list[Exception] = []
        self._sub = container.bus.subscribe()
        self._task = asyncio.create_task(self._run())

    async def _run(self) -> None:
        async for event in self._sub:
            if event.type != "approval.requested":
                continue
            view = event.payload
            self.seen.append(view)
            asyncio.create_task(self._answer(view))

    async def _answer(self, view: dict) -> None:
        result = self._decide(view)
        verdict = await result if asyncio.iscoroutine(result) else result
        if verdict is None:
            return
        try:
            if verdict == "allow":
                await self.container.approve(
                    self.principal, view["id"], view["request_hash"], confirmed=self.confirm
                )
            else:
                await self.container.reject(self.principal, view["id"], view["request_hash"], reason="test")
        except Exception as exc:  # recorded for assertions
            self.errors.append(exc)

    async def close(self) -> None:
        self._sub.close()
        self._task.cancel()
        await asyncio.gather(self._task, return_exceptions=True)


@pytest.fixture
async def approver_factory():
    created: list[ScriptedApprover] = []

    def factory(container: Container, decide, **kw) -> ScriptedApprover:
        approver = ScriptedApprover(container, decide, **kw)
        created.append(approver)
        return approver

    yield factory
    for approver in created:
        await approver.close()


def exec_log_entries(path: Path) -> list[dict]:
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
