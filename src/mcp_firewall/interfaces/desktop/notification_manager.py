"""Attention management: popup raising, audible/visual alerts and tray-balloon fallback."""

from __future__ import annotations

from PySide6.QtWidgets import QApplication, QSystemTrayIcon


class NotificationManager:
    def __init__(self, window, tray) -> None:
        self._window = window
        self._tray = tray

    def notify_new(self, view: dict) -> None:
        # Primary: a topmost dialog. Fallbacks (the OS may refuse to activate a window): taskbar flash + balloon.
        self._window.bring_to_front()
        QApplication.alert(self._window, 0)
        QApplication.beep()
        if self._tray.available:
            self._tray.tray.showMessage(
                "MCP approval required",
                f"{view['server']} › {view['tool']} ({view['risk']['level']} risk)",
                QSystemTrayIcon.MessageIcon.Warning,
                8000,
            )
