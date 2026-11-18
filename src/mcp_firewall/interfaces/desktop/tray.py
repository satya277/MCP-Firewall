"""System tray icon and menu (persistent pending-request indicator)."""

from __future__ import annotations

from PySide6.QtCore import QPointF, Qt
from PySide6.QtGui import QAction, QBrush, QColor, QFont, QIcon, QPainter, QPen, QPixmap, QPolygonF
from PySide6.QtWidgets import QMenu, QSystemTrayIcon

COLORS = {"offline": "#7b8499", "idle": "#2fb36d", "pending": "#e5484d"}


def make_icon(state: str, count: int = 0) -> QIcon:
    pixmap = QPixmap(64, 64)
    pixmap.fill(Qt.GlobalColor.transparent)
    painter = QPainter(pixmap)
    painter.setRenderHint(QPainter.RenderHint.Antialiasing)
    shield = QPolygonF(
        [QPointF(32, 4), QPointF(58, 14), QPointF(54, 40), QPointF(32, 60), QPointF(10, 40), QPointF(6, 14)]
    )
    painter.setBrush(QBrush(QColor(COLORS[state])))
    painter.setPen(QPen(QColor("#10141f"), 3))
    painter.drawPolygon(shield)
    if count:
        painter.setPen(QColor("white"))
        font = QFont()
        font.setBold(True)
        font.setPixelSize(30 if count < 10 else 24)
        painter.setFont(font)
        painter.drawText(pixmap.rect(), Qt.AlignmentFlag.AlignCenter, str(min(count, 99)))
    painter.end()
    return QIcon(pixmap)


class TrayController:
    def __init__(self, app, on_show, on_quit) -> None:
        self.tray = QSystemTrayIcon(make_icon("offline"), app)
        self.available = QSystemTrayIcon.isSystemTrayAvailable()
        menu = QMenu()
        self._show_action = QAction("Show pending requests", menu)
        self._show_action.triggered.connect(on_show)
        self._status_action = QAction("Starting…", menu)
        self._status_action.setEnabled(False)
        quit_action = QAction("Quit MCP Firewall agent", menu)
        quit_action.triggered.connect(on_quit)
        menu.addAction(self._status_action)
        menu.addSeparator()
        menu.addAction(self._show_action)
        menu.addAction(quit_action)
        self._menu = menu  # keep a reference
        self.tray.setContextMenu(menu)
        self.tray.activated.connect(
            lambda reason: (
                on_show()
                if reason
                in (QSystemTrayIcon.ActivationReason.Trigger, QSystemTrayIcon.ActivationReason.DoubleClick)
                else None
            )
        )
        self.tray.show()

    def update(self, connected: int, total: int, pending: int) -> None:
        state = "pending" if pending else ("idle" if connected else "offline")
        self.tray.setIcon(make_icon(state, pending))
        text = (
            f"{pending} request(s) awaiting approval" if pending else "No requests pending"
        ) + f"  •  {connected}/{total} gateway(s) connected"
        self._status_action.setText(text)
        self._show_action.setEnabled(pending > 0)
        self.tray.setToolTip(f"MCP Firewall - {text}")
