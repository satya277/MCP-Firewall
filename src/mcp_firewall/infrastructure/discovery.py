"""Runtime discovery between local gateway processes and the desktop agent.

Each STDIO gateway publishes ``run/gateway-<pid>.json`` (loopback URL + session token, owner-only
permissions). The agent watches that directory and connects to every live gateway. A heartbeat file
lets gateways know whether an agent is already running.
"""

from __future__ import annotations

import contextlib
import json
import os
import sys
import time
from dataclasses import asdict, dataclass
from pathlib import Path

HEARTBEAT_FILE = "agent.heartbeat"
HEARTBEAT_FRESH_SECONDS = 8.0


@dataclass(frozen=True, slots=True)
class GatewayInfo:
    id: str
    pid: int
    url: str
    token: str
    started: float
    servers: list[str]

    @property
    def ws_url(self) -> str:
        return self.url.replace("http://", "ws://", 1) + "/api/v1/ws"


def _write_private(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        fh.write(text)
    os.replace(tmp, path)


def gateway_file(run_dir: Path, pid: int | None = None) -> Path:
    return run_dir / f"gateway-{pid or os.getpid()}.json"


def publish_gateway(run_dir: Path, info: GatewayInfo) -> Path:
    path = gateway_file(run_dir, info.pid)
    _write_private(path, json.dumps(asdict(info)))
    return path


def remove_gateway(run_dir: Path, pid: int | None = None) -> None:
    with contextlib.suppress(OSError):
        gateway_file(run_dir, pid).unlink()


def list_gateways(run_dir: Path) -> list[tuple[Path, GatewayInfo]]:
    found: list[tuple[Path, GatewayInfo]] = []
    for path in run_dir.glob("gateway-*.json"):
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            found.append((path, GatewayInfo(**data)))
        except (OSError, ValueError, TypeError):
            continue
    return found


def touch_heartbeat(run_dir: Path) -> None:
    run_dir.mkdir(parents=True, exist_ok=True)
    (run_dir / HEARTBEAT_FILE).write_text(
        json.dumps({"pid": os.getpid(), "ts": time.time()}), encoding="utf-8"
    )


def read_agent_pid(run_dir: Path) -> int | None:
    try:
        return int(json.loads((run_dir / HEARTBEAT_FILE).read_text(encoding="utf-8"))["pid"])
    except (OSError, ValueError, KeyError, TypeError):
        return None


def agent_alive(run_dir: Path) -> bool:
    try:
        return time.time() - (run_dir / HEARTBEAT_FILE).stat().st_mtime < HEARTBEAT_FRESH_SECONDS
    except OSError:
        return False


def pid_alive(pid: int) -> bool:
    """Liveness probe. NOTE: ``os.kill(pid, 0)`` must never be used on Windows (it terminates the process)."""
    if sys.platform == "win32":
        import ctypes

        kernel32 = ctypes.windll.kernel32  # type: ignore[attr-defined]
        handle = kernel32.OpenProcess(0x1000, False, pid)  # PROCESS_QUERY_LIMITED_INFORMATION
        if not handle:
            return False
        try:
            code = ctypes.c_ulong()
            return (
                bool(kernel32.GetExitCodeProcess(handle, ctypes.byref(code))) and code.value == 259
            )  # STILL_ACTIVE
        finally:
            kernel32.CloseHandle(handle)
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True
