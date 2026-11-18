"""Desktop approval agent: tray application that shows a topmost popup for every pending request.

Threading model: Qt owns the main thread; all network I/O (AgentCore) runs on one asyncio loop in a
worker thread. They communicate only through Qt signals (thread-safe) and
``run_coroutine_threadsafe``.
"""

from __future__ import annotations

import asyncio
import sys
import threading
from pathlib import Path

import structlog

from mcp_firewall.config import Settings
from mcp_firewall.infrastructure.discovery import agent_alive
from mcp_firewall.interfaces.desktop.controller import AgentCore, load_remotes

log = structlog.get_logger("agent")


def run_agent(settings: Settings, remotes_file: Path | None = None, headless: bool = False) -> int:
    run_dir = settings.run_dir
    run_dir.mkdir(parents=True, exist_ok=True)
    if agent_alive(run_dir):
        print("An MCP Firewall agent is already running.", file=sys.stderr)
        return 0
    remotes = load_remotes(remotes_file) if remotes_file else []
    if headless:
        return _run_headless(run_dir, remotes)
    return _run_qt(run_dir, remotes)


def _run_headless(run_dir: Path, remotes) -> int:
    async def main() -> None:
        core = AgentCore(
            run_dir,
            remotes,
            on_new=lambda v: log.info("approval_requested", server=v["server"], tool=v["tool"], id=v["id"]),
        )
        await core.start()
        try:
            await asyncio.Event().wait()
        finally:
            await core.stop()

    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass
    return 0


def _run_qt(run_dir: Path, remotes) -> int:
    from PySide6.QtCore import QObject, Signal
    from PySide6.QtWidgets import QApplication

    from mcp_firewall.interfaces.desktop.approval_window import ApprovalWindow
    from mcp_firewall.interfaces.desktop.notification_manager import NotificationManager
    from mcp_firewall.interfaces.desktop.tray import TrayController

    class Bridge(QObject):
        pending_changed = Signal(list, int, int)  # views, connected, total
        new_request = Signal(dict)
        decision_failed = Signal(str)

    app = QApplication(sys.argv[:1])
    app.setQuitOnLastWindowClosed(False)  # lives in the tray
    app.setApplicationName("MCP Firewall")

    bridge = Bridge()
    loop = asyncio.new_event_loop()
    state = {"connected": 0, "total": 0}
    core_ref: dict[str, AgentCore] = {}

    def publish() -> None:
        core = core_ref["core"]
        bridge.pending_changed.emit(core.pending(), *core.endpoint_count())

    core = AgentCore(
        run_dir,
        remotes,
        on_changed=publish,
        on_new=lambda view: bridge.new_request.emit(view),
        on_connection=lambda c, t: (
            state.update(connected=c, total=t),
            publish() if "core" in core_ref else None,
        ),
    )
    core_ref["core"] = core

    window = ApprovalWindow()
    tray = TrayController(
        app, on_show=lambda: window.bring_to_front() if window._views else None, on_quit=app.quit
    )
    notifier = NotificationManager(window, tray)

    def on_pending(views: list, connected: int, total: int) -> None:
        window.set_requests(views)
        tray.update(connected, total, len(views))

    bridge.pending_changed.connect(on_pending)
    bridge.new_request.connect(notifier.notify_new)
    bridge.decision_failed.connect(window.show_error)

    def on_decided(request_id: str, decision: str, confirmed: bool) -> None:
        future = asyncio.run_coroutine_threadsafe(core.decide(request_id, decision, confirm=confirmed), loop)

        def done(fut) -> None:
            try:
                ok, message = fut.result()
            except Exception as exc:  # never let a failed decision crash the UI
                ok, message = False, f"Unexpected error: {type(exc).__name__}"
            if not ok:
                bridge.decision_failed.emit(message)

        future.add_done_callback(done)

    window.decided.connect(on_decided)

    thread = threading.Thread(target=loop.run_forever, name="agent-io", daemon=True)
    thread.start()
    asyncio.run_coroutine_threadsafe(core.start(), loop).result(10)
    tray.update(0, 0, 0)
    log.info("agent_started", run_dir=str(run_dir))
    try:
        return app.exec()
    finally:
        try:
            asyncio.run_coroutine_threadsafe(core.stop(), loop).result(10)
        except Exception:
            log.exception("agent_stop_failed")
        loop.call_soon_threadsafe(loop.stop)
        thread.join(5)
