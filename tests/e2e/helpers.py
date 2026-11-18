"""E2E helpers: launch the real gateway as an MCP STDIO server and answer prompts through the real API."""

from __future__ import annotations

import asyncio
import json
import os
import sys
from collections.abc import Callable
from contextlib import asynccontextmanager
from pathlib import Path

import yaml
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

from mcp_firewall.interfaces.desktop.controller import AgentCore
from tests.conftest import ROOT, exec_log_entries

POLICY = {
    "default_action": "require_approval",
    "rules": [
        {
            "id": "deny-traversal",
            "action": "deny",
            "priority": 900,
            "when": [{"path": "path", "op": "regex", "value": r"(^|[\\/])\.\.([\\/]|$)"}],
        },
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


class E2EEnv:
    def __init__(self, tmp: Path) -> None:
        self.tmp = tmp
        self.home = tmp / "home"
        self.sandbox = tmp / "sandbox"
        self.exec_log = tmp / "exec-log.jsonl"
        self.servers = tmp / "servers.yaml"
        self.policies = tmp / "policies.yaml"
        self.servers.write_text(
            yaml.safe_dump(
                {
                    "servers": [
                        {
                            "name": "demo",
                            "transport": "stdio",
                            "command": sys.executable,
                            "args": [str(ROOT / "demo" / "demo_server.py")],
                            "env": {"DEMO_SANDBOX": str(self.sandbox), "DEMO_EXEC_LOG": str(self.exec_log)},
                        }
                    ],
                    "allowed_executables": [Path(sys.executable).name],
                }
            )
        )
        self.policies.write_text(yaml.safe_dump(POLICY))

    @property
    def run_dir(self) -> Path:
        return self.home / "run"

    def executed(self, tool: str | None = None) -> list[dict]:
        entries = exec_log_entries(self.exec_log)
        return [e for e in entries if tool is None or e["tool"] == tool]

    def settings_env(self, **extra: str) -> dict[str, str]:
        env = {
            "MCPFW_HOME": str(self.home),
            "MCPFW_AUTO_START_AGENT": "false",
            "MCPFW_APPROVAL_TIMEOUT_SECONDS": "4",
            "MCPFW_EXECUTION_TIMEOUT_SECONDS": "20",
            "MCPFW_LOG_LEVEL": "WARNING",
            "MCPFW_ENCRYPTION_KEY": "ZmFrZS1rZXktZm9yLXRlc3RzLW9ubHktMDEyMzQ1Njc4OTA9",
        }
        env.update(extra)
        return env


@asynccontextmanager
async def stdio_gateway(env: E2EEnv, decide: Callable[[dict], str | None]):
    """Yields (session, agent_core). ``decide`` answers prompts like a human would."""
    from cryptography.fernet import Fernet

    key = Fernet.generate_key().decode()
    params = StdioServerParameters(
        command=sys.executable,
        args=["-m", "mcp_firewall", "stdio", "--servers", str(env.servers), "--policies", str(env.policies)],
        env=env.settings_env(MCPFW_ENCRYPTION_KEY=key) | {"SYSTEMROOT": os.environ.get("SYSTEMROOT", "")},
    )
    agent = AgentCore(env.run_dir, auto_decider=decide)
    await agent.start()
    try:
        async with stdio_client(params) as (read, write), ClientSession(read, write) as session:
            await asyncio.wait_for(session.initialize(), 40)
            yield session, agent
    finally:
        await agent.stop()


def text_of(result) -> str:
    return " ".join(c.text for c in result.content if getattr(c, "type", "") == "text")


def args_of(view: dict) -> dict:
    return json.loads(view["arguments"])
