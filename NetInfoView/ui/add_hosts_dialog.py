"""The Add Hosts dialog: paste a host list in PingInfoView's own syntax."""

from __future__ import annotations

from PyQt6.QtWidgets import (
    QCheckBox,
    QDialog,
    QDialogButtonBox,
    QLabel,
    QMessageBox,
    QPlainTextEdit,
    QVBoxLayout,
)

from ..fileio.hostfile import HostListError, ParsedHost, has_hosts, parse_host_list

HELP = (
    "One host per line. A description may follow the address.\n"
    "host:port pings over TCP · a leading # disables the entry\n"
    "Ranges: 192.168.0.10-192.168.0.20 · 192.168.0.10-20 · 192.168.0.0/24\n"
    "Group: <name> starts a group."
)


class AddHostsDialog(QDialog):
    def __init__(
        self,
        parent=None,
        initial_text: str = "",
        skip_first: bool = False,
        skip_last: bool = False,
        replace: bool = True,
    ) -> None:
        super().__init__(parent)
        self.setWindowTitle("Add Hosts")
        self.resize(540, 400)

        self._editor = QPlainTextEdit(initial_text)
        self._editor.setPlaceholderText("192.168.0.1 Router\nwww.google.com\n8.8.8.8:53")
        # Pre-filled with the last list entered: selected, so typing replaces
        # it and OK re-adds it as-is.
        self._editor.selectAll()
        self._skip_first = QCheckBox("Skip the first address of every range")
        self._skip_first.setChecked(skip_first)
        self._skip_last = QCheckBox("Skip the last address of every range")
        self._skip_last.setChecked(skip_last)
        self._replace = QCheckBox("Clear the current hosts first")
        self._replace.setToolTip("Unchecked, these hosts are added to the ones already listed")
        self._replace.setChecked(replace)

        buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel
        )
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        # The placeholder looks like real input, so OK on an empty editor
        # used to close the dialog having silently added nothing. This runs on
        # every keystroke, so it must not expand ranges: a half-typed
        # 192.168.1.0/2 (on the way to /24) is a billion addresses.
        self._ok_button = buttons.button(QDialogButtonBox.StandardButton.Ok)
        self._editor.textChanged.connect(self._update_ok_button)
        self._update_ok_button()

        layout = QVBoxLayout(self)
        layout.addWidget(QLabel(HELP))
        layout.addWidget(self._editor, 1)
        layout.addWidget(self._skip_first)
        layout.addWidget(self._skip_last)
        layout.addWidget(self._replace)
        layout.addWidget(buttons)

    def _update_ok_button(self) -> None:
        self._ok_button.setEnabled(has_hosts(self._editor.toPlainText()))

    def accept(self) -> None:
        """Stay open with an explanation rather than accept an unusable list."""
        try:
            self.hosts()
        except HostListError as exc:
            QMessageBox.warning(self, "Add Hosts", str(exc))
            return
        super().accept()

    def text(self) -> str:
        return self._editor.toPlainText()

    def skip_first(self) -> bool:
        return self._skip_first.isChecked()

    def skip_last(self) -> bool:
        return self._skip_last.isChecked()

    def replace(self) -> bool:
        return self._replace.isChecked()

    def hosts(self) -> list[ParsedHost]:
        return parse_host_list(
            self._editor.toPlainText(),
            skip_first=self._skip_first.isChecked(),
            skip_last=self._skip_last.isChecked(),
        )
