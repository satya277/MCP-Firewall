"""The always-on-top approval dialog.

Safety-driven design:
* Block is the default button and has focus; Enter blocks, never allows.
* Closing the window (X / Esc) does NOT decide anything - the request stays pending until it is
  decided from the tray or expires (fail closed).
* High-risk requests need an explicit confirmation checkbox before Allow is enabled.
* All request content is rendered as plain text (never rich text/HTML).
"""

from __future__ import annotations

import time

from PySide6.QtCore import Qt, QTimer, Signal
from PySide6.QtGui import QFont, QKeySequence, QShortcut
from PySide6.QtWidgets import (
    QCheckBox,
    QDialog,
    QFrame,
    QHBoxLayout,
    QLabel,
    QPlainTextEdit,
    QPushButton,
    QVBoxLayout,
)

RISK_COLORS = {"LOW": "#2fb36d", "MEDIUM": "#f5a524", "HIGH": "#e5484d", "CRITICAL": "#e5484d"}


class ApprovalWindow(QDialog):
    decided = Signal(str, str, bool)  # request_id, "allow" | "block", confirmed

    def __init__(self) -> None:
        super().__init__(None)
        self.setWindowTitle("MCP Firewall - approval required")
        self.setWindowFlags(
            Qt.WindowType.Dialog
            | Qt.WindowType.WindowStaysOnTopHint  # stays above other applications
            | Qt.WindowType.WindowTitleHint
            | Qt.WindowType.WindowCloseButtonHint
            | Qt.WindowType.CustomizeWindowHint
        )
        self.setModal(False)  # never blocks the rest of the desktop (or the agent's own event loop)
        self.setMinimumSize(620, 520)
        self._views: list[dict] = []
        self._index = 0
        self._busy = False
        self._build()
        self._timer = QTimer(self)
        self._timer.setInterval(250)
        self._timer.timeout.connect(self._tick)
        self._timer.start()

    # -- UI -----------------------------------------------------------------------------------
    def _build(self) -> None:
        self.setStyleSheet(
            "QDialog{background:#141a29;color:#e6e9f2;} QLabel{color:#e6e9f2;} "
            "QPlainTextEdit{background:#0c111c;color:#dfe6ff;border:1px solid #2a3350;border-radius:6px;font-family:Consolas,monospace;} "
            "QPushButton{padding:10px 26px;border-radius:8px;font-weight:600;color:white;border:0;} "
            "QCheckBox{color:#f5a524;}"
        )
        root = QVBoxLayout(self)
        root.setSpacing(8)

        top = QHBoxLayout()
        self.title = QLabel()
        self.title.setTextFormat(Qt.TextFormat.PlainText)  # server/tool names are untrusted
        title_font = QFont()
        title_font.setPointSize(13)
        title_font.setBold(True)
        self.title.setFont(title_font)
        self.risk = QLabel()
        self.counter = QLabel()
        top.addWidget(self.title, 1)
        top.addWidget(self.risk)
        root.addLayout(top)

        self.meta = QLabel()
        self.meta.setTextFormat(Qt.TextFormat.PlainText)
        self.meta.setWordWrap(True)
        self.meta.setStyleSheet("color:#9aa5c3;")
        root.addWidget(self.meta)

        self.reasons = QLabel()
        self.reasons.setTextFormat(Qt.TextFormat.PlainText)
        self.reasons.setWordWrap(True)
        root.addWidget(self.reasons)

        self.warning = QLabel()
        self.warning.setTextFormat(Qt.TextFormat.PlainText)
        self.warning.setWordWrap(True)
        self.warning.setStyleSheet(
            "background:#2a2412;border-left:3px solid #f5a524;padding:6px;color:#f5d58a;"
        )
        root.addWidget(self.warning)

        root.addWidget(QLabel("Exact arguments (secrets are redacted):"))
        self.args = QPlainTextEdit()
        self.args.setReadOnly(True)
        root.addWidget(self.args, 1)

        self.desc = QLabel()
        self.desc.setTextFormat(Qt.TextFormat.PlainText)
        self.desc.setWordWrap(True)
        self.desc.setStyleSheet("color:#7f8aa8;")
        root.addWidget(self.desc)

        self.confirm = QCheckBox("I reviewed the exact arguments above and confirm this high-risk action.")
        self.confirm.toggled.connect(self._refresh_buttons)
        root.addWidget(self.confirm)

        line = QFrame()
        line.setFrameShape(QFrame.Shape.HLine)
        line.setStyleSheet("color:#2a3350;")
        root.addWidget(line)

        bottom = QHBoxLayout()
        self.expiry = QLabel()
        self.status = QLabel()
        self.status.setTextFormat(Qt.TextFormat.PlainText)
        self.status.setStyleSheet("color:#e5484d;")
        self.status.setWordWrap(True)
        self.prev_btn = QPushButton("◀")
        self.next_btn = QPushButton("▶")
        for b in (self.prev_btn, self.next_btn):
            b.setStyleSheet("QPushButton{background:#2a3350;padding:6px 12px;}")
        self.prev_btn.clicked.connect(lambda: self._go(-1))
        self.next_btn.clicked.connect(lambda: self._go(1))
        self.block_btn = QPushButton("Block")
        self.block_btn.setStyleSheet(
            "QPushButton{background:#e5484d;} QPushButton:hover{background:#f0646a;}"
        )
        self.allow_btn = QPushButton("Allow")
        self.allow_btn.setStyleSheet(
            "QPushButton{background:#2fb36d;} QPushButton:hover{background:#3cc67c;} QPushButton:disabled{background:#2a3350;color:#667;}"
        )
        self.block_btn.setDefault(True)  # Enter => Block
        self.allow_btn.setAutoDefault(False)
        self.block_btn.clicked.connect(lambda: self._decide("block"))
        self.allow_btn.clicked.connect(lambda: self._decide("allow"))
        bottom.addWidget(self.prev_btn)
        bottom.addWidget(self.counter)
        bottom.addWidget(self.next_btn)
        bottom.addWidget(self.expiry, 1)
        bottom.addWidget(self.block_btn)
        bottom.addWidget(self.allow_btn)
        root.addLayout(bottom)
        root.addWidget(self.status)
        QShortcut(QKeySequence("Ctrl+B"), self, activated=lambda: self._decide("block"))

    # -- data ---------------------------------------------------------------------------------
    def set_requests(self, views: list[dict]) -> None:
        current = self.current_id()
        self._views = views
        ids = [v["id"] for v in views]
        self._index = ids.index(current) if current in ids else min(self._index, max(0, len(ids) - 1))
        self._busy = False
        self._render()

    def current_id(self) -> str | None:
        return self._views[self._index]["id"] if self._views else None

    def show_error(self, message: str) -> None:
        self._busy = False
        self.status.setText(message)
        self._refresh_buttons()

    def _go(self, step: int) -> None:
        if self._views:
            self._index = (self._index + step) % len(self._views)
            self.status.clear()
            self._render()

    def _render(self) -> None:
        if not self._views:
            self.hide()
            return
        view = self._views[self._index]
        self.title.setText(f"{view['server']}  ›  {view['tool']}")
        level = view["risk"]["level"]
        self.risk.setText(f" {level} RISK ")
        self.risk.setStyleSheet(
            f"background:{RISK_COLORS.get(level, '#f5a524')};color:white;border-radius:6px;font-weight:700;padding:2px 8px;"
        )
        self.meta.setText(
            f"Client: {view['client']}   •   Operation: {view['operation']}   •   "
            f"Policy rule: {view['policy']['rule'] or 'default (ask)'}   •   Request {view['id'][:8]}…  hash {view['request_hash'][:12]}…"
        )
        self.reasons.setText("\n".join(f"• {r}" for r in view["risk"]["reasons"]))
        self.warning.setVisible(view["schema_changed"])
        self.warning.setText("⚠ This tool's definition changed since it was last trusted. Review carefully.")
        self.args.setPlainText(view["arguments"])
        description = view.get("description") or ""
        self.desc.setVisible(bool(description))
        self.desc.setText(f"Tool description (untrusted, from the server): {description}")
        self.confirm.setVisible(view["strong_confirmation"])
        self.confirm.setChecked(False)
        self.counter.setText(f"{self._index + 1} of {len(self._views)}")
        multi = len(self._views) > 1
        self.prev_btn.setVisible(multi)
        self.next_btn.setVisible(multi)
        self.counter.setVisible(multi)
        self._refresh_buttons()
        self._tick()

    def _refresh_buttons(self) -> None:
        if not self._views:
            return
        view = self._views[self._index]
        allowed = not self._busy and (self.confirm.isChecked() or not view["strong_confirmation"])
        self.allow_btn.setEnabled(allowed)
        self.block_btn.setEnabled(not self._busy)

    def _tick(self) -> None:
        if not self._views:
            return
        remaining = int(self._views[self._index]["expires_at"] - time.time())
        if remaining <= 0:
            self.expiry.setText("expired - it will be blocked automatically")
            self.allow_btn.setEnabled(False)
        else:
            self.expiry.setText(f"Auto-blocks in {remaining}s if you do nothing")

    def _decide(self, decision: str) -> None:
        if not self._views or self._busy:
            return
        view = self._views[self._index]
        if decision == "allow" and view["strong_confirmation"] and not self.confirm.isChecked():
            return
        self._busy = True
        self.status.clear()
        self._refresh_buttons()
        self.decided.emit(view["id"], decision, self.confirm.isChecked())

    # -- behaviour ----------------------------------------------------------------------------
    def bring_to_front(self) -> None:
        """Best effort: a topmost window stays visible even where OS focus-stealing rules block activation."""
        self.show()
        self.setWindowState(self.windowState() & ~Qt.WindowState.WindowMinimized)
        self.raise_()
        self.activateWindow()
        self.block_btn.setFocus()

    def keyPressEvent(self, event) -> None:  # noqa: N802 - Qt API
        if event.key() == Qt.Key.Key_Escape:
            event.ignore()  # Esc must not silently dismiss a pending security decision
            self.hide()
            return
        super().keyPressEvent(event)

    def closeEvent(self, event) -> None:  # noqa: N802 - Qt API
        event.ignore()  # closing hides only: the request remains pending (tray) and is never auto-allowed
        self.hide()
