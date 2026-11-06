"""Test SNMP window: ask one host for its SNMP system group with a
community the user types, to check SNMP is on and the community is right
(ping/snmp_test.py)."""

from __future__ import annotations

import ipaddress
from collections.abc import Callable

from PyQt6.QtCore import Qt, QThread, pyqtSignal
from PyQt6.QtWidgets import (
    QComboBox,
    QFormLayout,
    QHBoxLayout,
    QLineEdit,
    QPlainTextEdit,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

from . import fonts
from ..ping import snmp_test
from .threads import retire, track

#: Version choices: label -> version number (None tries v2c, then v1).
VERSIONS = (("Auto (v2c, then v1)", None), ("v2c", snmp_test.VERSION_2C), ("v1", snmp_test.VERSION_1))


class SnmpTestThread(QThread):
    done = pyqtSignal(object)  # snmp_test.SnmpResult

    def __init__(self, ip: str, community: str, version: int | None) -> None:
        super().__init__()
        self._args = (ip, community, version)

    def run(self) -> None:
        self.done.emit(snmp_test.query_system(*self._args))


class SnmpTestWindow(QWidget):
    """A non-modal window: host, community and version, then Test."""

    def __init__(self, ip: str = "", community: str = "public", parent: QWidget | None = None,
                 saved_community: Callable[[], str] | None = None,
                 save_community: Callable[[str], None] | None = None,
                 answered: Callable[[], None] | None = None) -> None:
        """`saved_community` reads the community in Settings and
        `save_community` replaces it; without them there's no Use button.
        `answered` is called whenever the host answers."""
        super().__init__(parent, Qt.WindowType.Window)
        self.setAttribute(Qt.WidgetAttribute.WA_DeleteOnClose)
        self.setWindowTitle(f"Test SNMP — {ip}" if ip else "Test SNMP")
        self.resize(640, 380)
        self._saved_community = saved_community
        self._save_community_to = save_community
        self._answered = answered
        self._thread: SnmpTestThread | None = None

        self.host = QLineEdit(ip)
        self.host.setPlaceholderText("IP address")
        self.community = QLineEdit(community)
        self.community.setToolTip("SNMP read community (v1/v2c)")
        self.version = QComboBox()
        for label, _ in VERSIONS:
            self.version.addItem(label)

        self.button = QPushButton("Test")
        self.button.setDefault(True)
        self.button.clicked.connect(self.start)
        self.save_button = QPushButton("Use This Community")
        self.save_button.setToolTip(
            "Save it as the SNMP community in Settings, for MACs read from routers"
        )
        self.save_button.setVisible(False)
        self.save_button.clicked.connect(self._save_community)
        for field in (self.host, self.community):
            field.returnPressed.connect(self.start)

        form = QFormLayout()
        form.setFormAlignment(Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignTop)
        form.addRow("Host:", self.host)
        form.addRow("Community:", self.community)
        form.addRow("Version:", self.version)

        buttons = QHBoxLayout()
        buttons.addStretch(1)
        buttons.addWidget(self.save_button)
        buttons.addWidget(self.button)

        self.text = QPlainTextEdit()
        self.text.setReadOnly(True)
        self.text.setFont(fonts.mono())
        self.text.setPlaceholderText("Press Test to ask the host for its SNMP name and description.")

        layout = QVBoxLayout(self)
        layout.addLayout(form)
        layout.addLayout(buttons)
        layout.addWidget(self.text, 1)

    def start(self) -> None:
        if self._thread is not None:
            return
        ip = self.host.text().strip()
        try:
            if ipaddress.ip_address(ip).version != 4:
                raise ValueError
        except ValueError:
            self.text.setPlainText(f"✗ \"{ip}\" is not an IPv4 address.")
            return
        community = self.community.text()
        version = VERSIONS[self.version.currentIndex()][1]
        self.setWindowTitle(f"Test SNMP — {ip}")
        self.text.setPlainText(f"Asking {ip} with community \"{community}\"…")
        self.button.setEnabled(False)
        self.save_button.setVisible(False)
        self._thread = track(SnmpTestThread(ip, community, version))
        self._thread.done.connect(self._show)
        self._thread.start()

    def _show(self, result: snmp_test.SnmpResult) -> None:
        self._thread = None
        self.button.setEnabled(True)
        self.text.setPlainText(snmp_test.format_result(result))
        if result.ok and self._answered is not None:
            self._answered()
        self.save_button.setVisible(
            result.ok and self._save_community_to is not None
            and self._saved_community is not None
            and result.community != self._saved_community()
        )

    def _save_community(self) -> None:
        community = self.community.text()
        self._save_community_to(community)
        self.save_button.setVisible(False)
        self.text.appendPlainText(f"\nSaved \"{community}\" as the SNMP community.")

    def closeEvent(self, event) -> None:
        if self._thread is not None:
            self._thread.done.disconnect()
            retire(self._thread)
            self._thread = None
        super().closeEvent(event)
