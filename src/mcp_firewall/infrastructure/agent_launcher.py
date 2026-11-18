"""ApproverNotifier adapter: make sure the desktop approval agent is running."""

from __future__ import annotations

import subprocess
import sys
import time
from pathlib import Path
from typing import Protocol

import structlog

from mcp_firewall.infrastructure.discovery import agent_alive

log = structlog.get_logger("agent-launcher")
_MIN_RESPAWN_SECONDS = 30.0


class _Counter(Protocol):
    def count(self) -> int: ...


class AgentLauncher:
    """Starts ``python -m mcp_firewall agent`` detached if nobody can currently answer prompts."""

    def __init__(self, run_dir: Path, connections: _Counter) -> None:
        self._run_dir = run_dir
        self._connections = connections
        self._last_spawn = 0.0

    async def ensure_approver(self) -> None:
        if self._connections.count() > 0 or agent_alive(self._run_dir):
            return
        if time.monotonic() - self._last_spawn < _MIN_RESPAWN_SECONDS:
            return
        self._last_spawn = time.monotonic()
        self.spawn()

    @staticmethod
    def spawn() -> None:
        kwargs: dict = {
            "stdin": subprocess.DEVNULL,
            "stdout": subprocess.DEVNULL,
            "stderr": subprocess.DEVNULL,
        }
        if sys.platform == "win32":
            kwargs["creationflags"] = (
                subprocess.DETACHED_PROCESS
                | subprocess.CREATE_NEW_PROCESS_GROUP
                | subprocess.CREATE_NO_WINDOW
            )
        else:
            kwargs["start_new_session"] = True
        try:
            subprocess.Popen([sys.executable, "-m", "mcp_firewall", "agent"], **kwargs)  # noqa: S603
            log.info("approval_agent_spawned")
        except OSError:
            log.exception("approval_agent_spawn_failed")
