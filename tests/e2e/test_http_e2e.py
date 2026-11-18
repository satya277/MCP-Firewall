"""End-to-end: real MCP client -> remote Streamable-HTTP gateway -> real demo MCP server (Claude Web path)."""

from __future__ import annotations

import asyncio
import contextlib
import socket
from contextlib import asynccontextmanager
from pathlib import Path

import httpx
import pytest
from cryptography.fernet import Fernet
from mcp import ClientSession
from mcp.client.streamable_http import streamablehttp_client

from mcp_firewall.config import Settings
from mcp_firewall.infrastructure.mcp.http_proxy import create_remote_app
from mcp_firewall.infrastructure.mcp.stdio_proxy import EmbeddedServer
from mcp_firewall.infrastructure.security.authentication import hash_token
from mcp_firewall.interfaces.api.auth import reset_auth_throttle
from mcp_firewall.interfaces.desktop.controller import AgentCore, RemoteEndpoint
from tests.e2e.helpers import E2EEnv, args_of, text_of

CLIENT_TOKEN = "claude-web-connector-token-0123456789"
APPROVER_TOKEN = "approver-token-for-remote-0123456789"
PATH_SECRET = "capability-secret-0123456789abcdef"


@asynccontextmanager
async def remote_gateway(env: E2EEnv, **extra):
    import uvicorn

    reset_auth_throttle()
    settings = Settings(
        _env_file=None,
        home=env.home,
        approval_timeout_seconds=4,
        execution_timeout_seconds=20,
        encryption_key=Fernet.generate_key().decode(),
        approver_tokens=f"alice:approver:{hash_token(APPROVER_TOKEN)},root:admin:{hash_token('root-token-0123456789abcdef')}",
        mcp_client_tokens=f"claude-web:{hash_token(CLIENT_TOKEN)}",
        mcp_path_secret=PATH_SECRET,
        allowed_hosts=["127.0.0.1", "localhost"],
        auto_start_agent=False,
        database_url=f"sqlite:///{env.tmp / 'remote.db'}",
        **extra,
    )
    app = create_remote_app(settings, env.servers, env.policies)
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    server = EmbeddedServer(uvicorn.Config(app, log_config=None, access_log=False, lifespan="on"))
    task = asyncio.create_task(server.serve(sockets=[sock]))
    for _ in range(300):
        if server.started or task.done():
            break
        await asyncio.sleep(0.1)
    assert server.started, "remote gateway failed to start"
    try:
        yield f"http://127.0.0.1:{port}"
    finally:
        server.should_exit = True
        await asyncio.wait_for(task, 15)
        reset_auth_throttle()


@asynccontextmanager
async def mcp_session(url: str, token: str | None = CLIENT_TOKEN):
    headers = {"Authorization": f"Bearer {token}"} if token else None
    async with (
        streamablehttp_client(url, headers=headers) as (read, write, _),
        ClientSession(read, write) as session,
    ):
        await asyncio.wait_for(session.initialize(), 20)
        yield session


async def test_remote_gateway_requires_authentication(tmp_path):
    env = E2EEnv(tmp_path)
    async with remote_gateway(env) as base, httpx.AsyncClient() as c:
        body = {"jsonrpc": "2.0", "id": 1, "method": "ping"}
        hdrs = {"Accept": "application/json, text/event-stream", "Content-Type": "application/json"}
        assert (await c.post(f"{base}/mcp", json=body, headers=hdrs)).status_code == 401
        assert (
            await c.post(f"{base}/mcp", json=body, headers={**hdrs, "Authorization": "Bearer nope"})
        ).status_code == 401
        assert (await c.post(f"{base}/mcp/wrong-secret", json=body, headers=hdrs)).status_code == 401
        assert (
            await c.post(
                f"{base}/mcp", json=body, headers={**hdrs, "Authorization": f"Bearer {CLIENT_TOKEN}"}
            )
        ).status_code == 200
        # the approver token is NOT valid for the MCP endpoint and vice versa
        assert (
            await c.post(
                f"{base}/mcp", json=body, headers={**hdrs, "Authorization": f"Bearer {APPROVER_TOKEN}"}
            )
        ).status_code == 401
        assert (
            await c.get(f"{base}/api/v1/me", headers={"Authorization": f"Bearer {CLIENT_TOKEN}"})
        ).status_code == 401
        assert (await c.get(f"{base}/readyz")).status_code == 200


async def test_remote_gateway_approve_block_timeout(tmp_path):
    env = E2EEnv(tmp_path)
    async with remote_gateway(env) as base:

        def decide(view):
            path = args_of(view).get("path", "")
            return "allow" if path.startswith("approve") else "block" if path.startswith("block") else None

        agent = AgentCore(env.run_dir, [RemoteEndpoint("t", base, APPROVER_TOKEN)], auto_decider=decide)
        await agent.start()
        try:
            async with mcp_session(f"{base}/mcp") as session:
                names = {t.name for t in (await session.list_tools()).tools}
                assert "demo__create_file" in names
                ok = await session.call_tool(
                    "demo__create_file", {"path": "approve-r.txt", "content": "remote"}
                )
                assert not ok.isError and (env.sandbox / "approve-r.txt").read_text() == "remote"
                bad = await session.call_tool("demo__create_file", {"path": "block-r.txt", "content": "x"})
                assert (
                    bad.isError and "BLOCKED" in text_of(bad) and not (env.sandbox / "block-r.txt").exists()
                )
                late = await session.call_tool("demo__create_file", {"path": "ignored.txt", "content": "x"})
                assert late.isError and "timed out" in text_of(late)
                assert not (env.sandbox / "ignored.txt").exists()
                results = await asyncio.gather(
                    *[
                        session.call_tool(
                            "demo__create_file",
                            {"path": f"{'approve' if i % 2 else 'block'}-{i}.txt", "content": "c"},
                        )
                        for i in range(8)
                    ]
                )
                for i, r in enumerate(results):
                    assert (not r.isError) if i % 2 else r.isError, (i, text_of(r))
            # capability-URL variant used by connectors that cannot send headers
            async with mcp_session(f"{base}/mcp/{PATH_SECRET}", token=None) as session:
                echoed = await session.call_tool("demo__echo", {"text": "via-secret-path"})
                assert "via-secret-path" in text_of(echoed)
        finally:
            await agent.stop()
    executed = sorted(e["args"].get("path") or e["args"]["text"] for e in env.executed())
    assert executed == sorted(
        ["approve-r.txt", "via-secret-path", *[f"approve-{i}.txt" for i in range(1, 8, 2)]]
    )


async def test_client_disconnect_while_pending_never_executes(tmp_path):
    env = E2EEnv(tmp_path)
    async with remote_gateway(env) as base, httpx.AsyncClient() as http:
        admin = {"Authorization": "Bearer root-token-0123456789abcdef"}
        async with mcp_session(f"{base}/mcp") as session:
            call = asyncio.create_task(
                session.call_tool("demo__create_file", {"path": "gone.txt", "content": "x"})
            )
            pending: list = []
            for _ in range(50):
                pending = (await http.get(f"{base}/api/v1/requests?status=pending", headers=admin)).json()[
                    "requests"
                ]
                if pending:
                    break
                await asyncio.sleep(0.1)
            assert pending, "request never became pending"
            call.cancel()
            with contextlib.suppress(asyncio.CancelledError, Exception):
                await call
        request_id = pending[0]["id"]
        final = None
        for _ in range(80):
            final = (await http.get(f"{base}/api/v1/requests/{request_id}", headers=admin)).json()["status"]
            if final != "PENDING_APPROVAL":
                break
            await asyncio.sleep(0.1)
        assert final == "CANCELLED", final
        # a late approval of the orphaned request must be refused and nothing may run
        late = await http.post(
            f"{base}/api/v1/requests/{request_id}/decision",
            json={"decision": "allow", "request_hash": pending[0]["request_hash"], "confirm": True},
            headers={"Authorization": f"Bearer {APPROVER_TOKEN}"},
        )
        assert late.status_code in (409, 410)
    assert env.executed() == []


def test_remote_refuses_to_start_without_auth(tmp_path):
    env = E2EEnv(tmp_path)
    s = Settings(_env_file=None, home=Path(tmp_path) / "h")
    with pytest.raises(RuntimeError, match="refusing to start"):
        create_remote_app(s, env.servers, env.policies)
    s2 = Settings(_env_file=None, home=Path(tmp_path) / "h", mcp_path_secret="x" * 20)
    with pytest.raises(RuntimeError, match="APPROVER"):
        create_remote_app(s2, env.servers, env.policies)
