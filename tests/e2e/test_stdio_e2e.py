"""End-to-end: real MCP client -> real STDIO gateway process -> real demo MCP server."""

from __future__ import annotations

import asyncio

from tests.e2e.helpers import E2EEnv, args_of, stdio_gateway, text_of


async def test_stdio_gateway_approve_block_timeout_deny(tmp_path):
    env = E2EEnv(tmp_path)

    def decide(view):
        path = args_of(view).get("path", "")
        if path.startswith("approve"):
            return "allow"
        if path.startswith("block"):
            return "block"
        return None  # nobody answers -> the request must expire

    async with stdio_gateway(env, decide) as (session, agent):
        tools = {t.name for t in (await session.list_tools()).tools}
        assert {"demo__read_file", "demo__create_file", "demo__delete_file", "demo__echo"} <= tools

        # 1. APPROVED: runs, and the real result comes back
        ok = await session.call_tool("demo__create_file", {"path": "approve-1.txt", "content": "hello"})
        assert not ok.isError and "created approve-1.txt" in text_of(ok)
        assert (env.sandbox / "approve-1.txt").read_text() == "hello"

        # 2. BLOCKED: denial response, upstream never executed
        blocked = await session.call_tool("demo__create_file", {"path": "block-1.txt", "content": "evil"})
        assert blocked.isError and "BLOCKED" in text_of(blocked)
        assert not (env.sandbox / "block-1.txt").exists()

        # 3. TIMEOUT: nobody answers
        expired = await session.call_tool("demo__create_file", {"path": "ignored.txt", "content": "x"})
        assert expired.isError and "timed out" in text_of(expired)
        assert not (env.sandbox / "ignored.txt").exists()

        # 4. POLICY DENY (path traversal) - no prompt at all
        denied = await session.call_tool("demo__read_file", {"path": "../secrets.txt"})
        assert denied.isError and "DENIED" in text_of(denied)

        # 5. POLICY ALLOW - harmless echo needs no prompt
        echoed = await session.call_tool("demo__echo", {"text": "ping"})
        assert not echoed.isError and "ping" in text_of(echoed)

        # unknown tool
        unknown = await session.call_tool("demo__nope", {})
        assert unknown.isError

    executed = [(e["tool"], e["args"].get("path") or e["args"].get("text")) for e in env.executed()]
    assert executed == [
        ("create_file", "approve-1.txt"),
        ("echo", "ping"),
    ]  # blocked / expired / denied never ran


async def test_stdio_gateway_handles_concurrent_requests(tmp_path):
    env = E2EEnv(tmp_path)

    def decide(view):
        i = int(args_of(view)["path"].split("-")[1].split(".")[0])
        return "allow" if i % 2 == 0 else "block"

    async with stdio_gateway(env, decide) as (session, agent):
        results = await asyncio.gather(
            *[
                session.call_tool("demo__create_file", {"path": f"c-{i}.txt", "content": str(i)})
                for i in range(12)
            ]
        )
    for i, res in enumerate(results):
        if i % 2 == 0:
            assert not res.isError and f"c-{i}.txt" in text_of(res), (i, text_of(res))
        else:
            assert res.isError and "BLOCKED" in text_of(res)
    done = sorted(e["args"]["path"] for e in env.executed("create_file"))
    assert done == sorted(f"c-{i}.txt" for i in range(0, 12, 2))


async def test_high_risk_delete_needs_strong_confirmation_in_agent_flow(tmp_path):
    env = E2EEnv(tmp_path)
    seen = []

    def decide(view):
        seen.append(view)
        return "allow"

    (env.sandbox).mkdir(parents=True)
    (env.sandbox / "victim.txt").write_text("x")
    async with stdio_gateway(env, decide) as (session, agent):
        res = await session.call_tool("demo__delete_file", {"path": "victim.txt"})
    assert not res.isError and not (env.sandbox / "victim.txt").exists()
    assert seen[0]["strong_confirmation"] and seen[0]["risk"]["level"] == "HIGH"
