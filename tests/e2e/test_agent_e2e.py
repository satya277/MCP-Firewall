"""E2E: the gateway auto-launches the real desktop agent, which discovers it and receives prompts."""

from __future__ import annotations

import asyncio
import os
import sys

import httpx
import pytest

pytest.importorskip("PySide6")

from cryptography.fernet import Fernet  # noqa: E402
from mcp import ClientSession, StdioServerParameters  # noqa: E402
from mcp.client.stdio import stdio_client  # noqa: E402

from mcp_firewall.infrastructure.discovery import list_gateways, pid_alive, read_agent_pid  # noqa: E402
from tests.e2e.helpers import E2EEnv, text_of  # noqa: E402

pytestmark = pytest.mark.ui


async def _until(predicate, timeout=45.0, interval=0.25):
    loop = asyncio.get_running_loop()
    deadline = loop.time() + timeout
    while loop.time() < deadline:
        value = await predicate()
        if value:
            return value
        await asyncio.sleep(interval)
    raise AssertionError("condition not met in time")


async def test_gateway_spawns_agent_and_prompt_reaches_it(tmp_path):
    env = E2EEnv(tmp_path)
    params = StdioServerParameters(
        command=sys.executable,
        args=["-m", "mcp_firewall", "stdio", "--servers", str(env.servers), "--policies", str(env.policies)],
        env=env.settings_env(
            MCPFW_AUTO_START_AGENT="true",
            MCPFW_APPROVAL_TIMEOUT_SECONDS="60",
            MCPFW_ENCRYPTION_KEY=Fernet.generate_key().decode(),
            QT_QPA_PLATFORM="offscreen",  # real agent process, no visible window
            SYSTEMROOT=os.environ.get("SYSTEMROOT", ""),
        ),
    )
    agent_pid = None
    try:
        async with stdio_client(params) as (read, write), ClientSession(read, write) as session:
            await asyncio.wait_for(session.initialize(), 40)
            call = asyncio.create_task(
                session.call_tool("demo__create_file", {"path": "agent.txt", "content": "via-agent"})
            )

            async def gateway():
                found = list_gateways(env.run_dir)
                return found[0][1] if found else None

            info = await _until(gateway, 30)
            headers = {"Authorization": f"Bearer {info.token}"}
            async with httpx.AsyncClient(base_url=info.url, headers=headers) as api:

                async def agent_connected():
                    try:
                        return (await api.get("/api/v1/status")).json()["approvers_connected"] >= 1
                    except httpx.HTTPError:
                        return False

                await _until(agent_connected, 60)  # the gateway really launched the agent and it connected
                agent_pid = read_agent_pid(env.run_dir)
                assert agent_pid and pid_alive(agent_pid)

                async def pending():
                    items = (await api.get("/api/v1/requests?status=pending")).json()["requests"]
                    return items[0] if items else None

                req = await _until(pending, 15)
                assert req["tool"] == "create_file" and "via-agent" in req["arguments"]
                decision = await api.post(
                    f"/api/v1/requests/{req['id']}/decision",
                    json={"decision": "allow", "request_hash": req["request_hash"]},
                )
                assert decision.status_code == 200
            result = await asyncio.wait_for(call, 30)
            assert not result.isError and "created agent.txt" in text_of(result)
        assert (env.sandbox / "agent.txt").read_text() == "via-agent"
    finally:
        agent_pid = agent_pid or read_agent_pid(env.run_dir)
        if agent_pid and pid_alive(agent_pid):
            os.kill(agent_pid, 15)  # test cleanup of the detached agent (explicit PID, never by name)
