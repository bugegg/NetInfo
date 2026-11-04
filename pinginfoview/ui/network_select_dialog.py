"""Offered when Start is pressed with no hosts yet: pick a connected network
and scan the whole thing, or switch to typing hosts/IPs in by hand."""

from __future__ import annotations

from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import (
    QDialog,
    QDialogButtonBox,
    QLabel,
    QListWidget,
    QListWidgetItem,
    QVBoxLayout,
)

from ..ping.network_interfaces import NetworkInterface

HELP = (
    "No hosts yet. Pick a network this Mac is connected to and PingInfoView\n"
    "will add every address in it (you can remove any you don't want) —\n"
    "or enter specific hosts or IPs yourself instead."
)


class NetworkSelectDialog(QDialog):
    def __init__(self, interfaces: list[NetworkInterface], parent=None) -> None:
        super().__init__(parent)
        self.setWindowTitle("Scan a Network")
        self.resize(440, 280)
        self._interfaces = interfaces
        #: True once "Enter Hosts Manually..." was clicked, distinguishing
        #: that from a plain Cancel — both reject() the dialog.
        self.manual_entry_requested = False

        self._list = QListWidget()
        for iface in interfaces:
            item = QListWidgetItem(iface.display_label)
            item.setData(Qt.ItemDataRole.UserRole, iface)
            self._list.addItem(item)
        if interfaces:
            self._list.setCurrentRow(0)
        self._list.itemDoubleClicked.connect(self.accept)

        buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel
        )
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        buttons.button(QDialogButtonBox.StandardButton.Ok).setEnabled(bool(interfaces))

        manual_button = buttons.addButton(
            "Enter Hosts Manually...", QDialogButtonBox.ButtonRole.ActionRole
        )
        manual_button.clicked.connect(self._request_manual_entry)

        layout = QVBoxLayout(self)
        layout.addWidget(QLabel(HELP))
        layout.addWidget(self._list, 1)
        layout.addWidget(buttons)

    def _request_manual_entry(self) -> None:
        self.manual_entry_requested = True
        self.reject()

    def selected_interface(self) -> NetworkInterface | None:
        item = self._list.currentItem()
        return item.data(Qt.ItemDataRole.UserRole) if item is not None else None
