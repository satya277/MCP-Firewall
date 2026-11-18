"""UI tests for the approval dialog (Qt offscreen platform - no display needed)."""

from __future__ import annotations

import os
import time

import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
pytest.importorskip("PySide6")

from PySide6.QtCore import QEvent, Qt  # noqa: E402
from PySide6.QtGui import QCloseEvent, QKeyEvent  # noqa: E402
from PySide6.QtWidgets import QApplication  # noqa: E402

from mcp_firewall.interfaces.desktop.approval_window import ApprovalWindow  # noqa: E402
from mcp_firewall.interfaces.desktop.tray import make_icon  # noqa: E402

pytestmark = pytest.mark.ui


@pytest.fixture(scope="module")
def qapp():
    return QApplication.instance() or QApplication([])


def view(i=1, strong=False, args='{"path": "a.txt"}', risk="MEDIUM", expires_in=60, description=""):
    return {
        "id": f"id-{i}" + "0" * 30, "server": "demo", "tool": "create_file", "client": "claude", "operation": "tools/call",
        "arguments": args, "request_hash": "ab" * 32, "risk": {"level": risk, "reasons": ["Tool changes state"]},
        "strong_confirmation": strong, "schema_changed": False, "policy": {"rule": None}, "created_at": time.time(),
        "expires_at": time.time() + expires_in, "description": description,
    }  # fmt: skip


@pytest.fixture
def window(qapp):
    w = ApprovalWindow()
    w.decisions = []
    w.decided.connect(lambda *a: w.decisions.append(a))
    yield w
    w._timer.stop()
    w.deleteLater()


def test_window_is_topmost_nonmodal(window):
    flags = window.windowFlags()
    assert flags & Qt.WindowType.WindowStaysOnTopHint
    assert not window.isModal()


def test_block_is_default_and_allow_emits_with_request_id(window):
    window.set_requests([view(1)])
    assert window.block_btn.isDefault() and not window.allow_btn.autoDefault()
    window.allow_btn.click()
    assert window.decisions == [("id-1" + "0" * 30, "allow", False)]


def test_block_emits_block(window):
    window.set_requests([view(1)])
    window.block_btn.click()
    assert window.decisions[0][1] == "block"


def test_double_click_does_not_send_two_decisions(window):
    window.set_requests([view(1)])
    window.allow_btn.click()
    window.allow_btn.click()
    window.block_btn.click()
    assert len(window.decisions) == 1


def test_high_risk_allow_requires_confirmation_checkbox(window):
    window.set_requests([view(1, strong=True, risk="HIGH")])
    assert not window.allow_btn.isEnabled() and window.block_btn.isEnabled()
    window._decide("allow")  # even programmatically it must not pass
    assert window.decisions == []
    window.confirm.setChecked(True)
    assert window.allow_btn.isEnabled()
    window.allow_btn.click()
    assert window.decisions[0][1:] == ("allow", True)


def test_closing_or_escape_never_decides(window):
    window.set_requests([view(1)])
    window.show()
    window.close()
    window.show()
    window.keyPressEvent(QKeyEvent(QEvent.Type.KeyPress, Qt.Key.Key_Escape, Qt.KeyboardModifier.NoModifier))
    window.closeEvent(QCloseEvent())
    assert window.decisions == []
    assert window._views  # request is still tracked / pending


def test_content_is_rendered_as_plain_text_not_html(window):
    evil = "<img src=x onerror=alert(1)><b>bold</b>"
    window.set_requests([view(1, args=evil, description=evil) | {"server": "<b>srv</b>", "tool": "<i>t</i>"}])
    assert window.args.toPlainText() == evil
    assert window.title.text() == "<b>srv</b>  ›  <i>t</i>"
    for label in (window.desc, window.meta, window.reasons, window.title, window.status, window.warning):
        assert label.textFormat() == Qt.TextFormat.PlainText
    assert window.args.isReadOnly()


def test_multiple_requests_navigation_and_independent_decisions(window):
    window.set_requests([view(1), view(2), view(3)])
    assert window.counter.text() == "1 of 3"
    window.next_btn.click()
    window.block_btn.click()
    assert window.decisions == [("id-2" + "0" * 30, "block", False)]


def test_resolved_request_disappears_and_empty_hides(window):
    window.set_requests([view(1), view(2)])
    window.set_requests([view(2)])
    assert window.current_id().startswith("id-2")
    window.show()
    window.set_requests([])
    assert not window.isVisible()


def test_error_reenables_buttons_for_retry(window):
    window.set_requests([view(1)])
    window.allow_btn.click()
    assert not window.allow_btn.isEnabled()
    window.show_error("403: nope")
    assert window.allow_btn.isEnabled() and "403" in window.status.text()


def test_expired_request_cannot_be_allowed(window):
    window.set_requests([view(1, expires_in=-5)])
    window._tick()
    assert not window.allow_btn.isEnabled() and "expired" in window.expiry.text()


def test_tray_icons_render(qapp):
    for state, n in (("offline", 0), ("idle", 0), ("pending", 3), ("pending", 120)):
        assert not make_icon(state, n).isNull()
