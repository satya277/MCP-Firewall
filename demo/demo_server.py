"""Demo MCP server used for the demonstration video and the end-to-end tests.

Tools:  read_file(path) / create_file(path, content) / delete_file(path) / echo(text)

SAFETY: every file operation is confined to ``DEMO_SANDBOX`` (default ./demo-sandbox). Real user
files are never touched. Each call that actually *executes* is appended to ``DEMO_EXEC_LOG``
(JSON lines) before the operation runs - so "blocked calls never executed" can be verified by
checking that the log contains no entry for them.
"""

from __future__ import annotations

import json
import os
import time
from pathlib import Path

from mcp.server.fastmcp import FastMCP

SANDBOX = Path(os.environ.get("DEMO_SANDBOX", "demo-sandbox")).resolve()
EXEC_LOG = Path(os.environ.get("DEMO_EXEC_LOG", SANDBOX.parent / "demo-exec-log.jsonl")).resolve()
SANDBOX.mkdir(parents=True, exist_ok=True)

mcp = FastMCP("demo-files")


def _record(tool: str, **args: object) -> None:
    EXEC_LOG.parent.mkdir(parents=True, exist_ok=True)
    with EXEC_LOG.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps({"ts": time.time(), "tool": tool, "args": args}) + "\n")


def _safe(path: str) -> Path:
    target = (SANDBOX / path).resolve()
    if SANDBOX != target and SANDBOX not in target.parents:
        raise ValueError("path escapes the demo sandbox")
    return target


@mcp.tool()
def read_file(path: str) -> str:
    """Read a text file from the demo sandbox."""
    target = _safe(path)
    _record("read_file", path=path)
    return target.read_text(encoding="utf-8") if target.exists() else f"(simulated) contents of {path}"


@mcp.tool()
def create_file(path: str, content: str) -> str:
    """Create or overwrite a file inside the demo sandbox."""
    target = _safe(path)
    _record("create_file", path=path, content_length=len(content))
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(content, encoding="utf-8")
    return f"created {path} ({len(content)} bytes)"


@mcp.tool()
def delete_file(path: str) -> str:
    """Delete a file inside the demo sandbox."""
    target = _safe(path)
    _record("delete_file", path=path)
    if not target.exists():
        return f"{path} does not exist"
    target.unlink()
    return f"deleted {path}"


@mcp.tool()
def echo(text: str) -> str:
    """Echo text back (harmless; used for concurrency tests)."""
    _record("echo", text=text)
    return text


if __name__ == "__main__":
    mcp.run("stdio")
