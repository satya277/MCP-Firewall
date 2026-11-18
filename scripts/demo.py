"""Scripted demo of the three outcomes (approve / block / timeout) against the real STDIO gateway.

Run:  python scripts/demo.py          (opens the real approval popup; click Allow / Block yourself)
      python scripts/demo.py --auto   (answers the prompts automatically, for CI / a dry run)

Everything happens inside ./demo-sandbox; ./demo-output/exec-log.jsonl proves what actually executed.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys
from pathlib import Path

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

ROOT = Path(__file__).resolve().parent.parent


def banner(text: str) -> None:
    print(f"\n=== {text} ===", flush=True)


def text_of(result) -> str:
    return " ".join(c.text for c in result.content if getattr(c, "type", "") == "text")


async def main(auto: bool) -> int:
    out = ROOT / "demo-output"
    out.mkdir(exist_ok=True)
    sandbox = ROOT / "demo-sandbox"
    log = out / "exec-log.jsonl"
    log.unlink(missing_ok=True)
    servers = out / "servers.yaml"
    servers.write_text(
        f"""allowed_executables: [{Path(sys.executable).name}]
servers:
  - name: demo
    transport: stdio
    command: {json.dumps(sys.executable)}
    args: [{json.dumps(str(ROOT / "demo" / "demo_server.py"))}]
    env: {{DEMO_SANDBOX: {json.dumps(str(sandbox))}, DEMO_EXEC_LOG: {json.dumps(str(log))}}}
""",
        encoding="utf-8",
    )
    env = {**os.environ, "MCPFW_APPROVAL_TIMEOUT_SECONDS": "20", "MCPFW_HOME": str(out / "home")}
    params = StdioServerParameters(
        command=sys.executable,
        args=[
            "-m",
            "mcp_firewall",
            "stdio",
            "--servers",
            str(servers),
            "--policies",
            str(ROOT / "config" / "policies.example.yaml"),
        ],
        env=env,
    )
    agent = None
    if auto:
        sys.path.insert(0, str(ROOT / "src"))
        from mcp_firewall.interfaces.desktop.controller import AgentCore

        env["MCPFW_AUTO_START_AGENT"] = "false"

        def decide(view):
            path = json.loads(view["arguments"]).get("path", "")
            return "allow" if path.startswith("approve") else "block" if path.startswith("block") else None

        agent = AgentCore(Path(env["MCPFW_HOME"]) / "run", auto_decider=decide)
        await agent.start()

    async with stdio_client(params) as (r, w), ClientSession(r, w) as session:
        await session.initialize()
        banner("1. Request that you should ALLOW  (create approve-me.txt)")
        print(
            text_of(
                await session.call_tool("demo__create_file", {"path": "approve-me.txt", "content": "hello"})
            )
        )
        banner("2. Request that you should BLOCK  (create block-me.txt)")
        print(
            text_of(await session.call_tool("demo__create_file", {"path": "block-me.txt", "content": "nope"}))
        )
        banner("3. Request nobody answers -> expires after 20 s  (create ignore-me.txt)")
        print(
            text_of(
                await session.call_tool("demo__create_file", {"path": "ignore-me.txt", "content": "late"})
            )
        )
        banner("4. Policy deny, no prompt  (path traversal)")
        print(text_of(await session.call_tool("demo__read_file", {"path": "../secrets.txt"})))
    if agent:
        await agent.stop()

    banner("Execution log of the upstream tool server (what REALLY ran)")
    for line in log.read_text(encoding="utf-8").splitlines() if log.exists() else []:
        entry = json.loads(line)
        print(f"  executed: {entry['tool']} {entry['args']}")
    print("\nFiles in sandbox:", sorted(p.name for p in sandbox.glob("*")))
    return 0


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--auto", action="store_true")
    sys.exit(asyncio.run(main(parser.parse_args().auto)))
