"""Details of one hop of a Trace Path MTU: what the trace found, its
reverse-DNS name, and who the address belongs to (ping/whois.py: the
registry's record and the AS announcing it), filled in by a background
lookup since whois takes a second or two."""

from __future__ import annotations

from PyQt6.QtCore import Qt, QThread, pyqtSignal
from PyQt6.QtGui import QGuiApplication
from PyQt6.QtWidgets import (
    QFormLayout,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QPlainTextEdit,
    QPushButton,
    QSizePolicy,
    QVBoxLayout,
    QWidget,
)

from . import fonts
from ..ping import dns_ptr, whois
from ..ping.mtu import format_mtu
from ..ping.tracepath import Hop
from .threads import retire, track


class HopDetailsThread(QThread):
    #: (reverse-DNS name, [(label, value)], raw whois output)
    details_ready = pyqtSignal(str, list, str)

    def __init__(self, address: str) -> None:
        super().__init__()
        self._address = address

    def run(self) -> None:  # noqa: D102 - QThread entry point
        ptr = dns_ptr.lookup(self._address, dns_ptr.system_nameservers())
        rows, raw = whois.details(self._address)
        self.details_ready.emit(ptr or "", rows, raw)


class HopDetailsWindow(QWidget):
    """A non-modal window about one hop; opened from the trace's rows."""

    def __init__(self, hop: Hop, name: str, parent: QWidget | None = None) -> None:
        super().__init__(parent, Qt.WindowType.Window)
        self.setAttribute(Qt.WidgetAttribute.WA_DeleteOnClose)
        self.setWindowTitle(f"Hop {hop.ttl} - {hop.address}")
        self.resize(600, 680)
        self.hop = hop

        trace_box = QGroupBox("Trace")
        self.trace_form = QFormLayout(trace_box)
        self._add(self.trace_form, "Hop", str(hop.ttl))
        self._add(self.trace_form, "Address", hop.address)
        self._add(self.trace_form, "Name", name)
        self.reverse_dns = self._add(self.trace_form, "Reverse DNS", "Looking up...")
        self._add(self.trace_form, "Path MTU", format_mtu(hop.mtu))
        if hop.note:
            self._add(self.trace_form, "Note", hop.note)

        self.owner_box = QGroupBox("Owner (whois)")
        self.owner_form = QFormLayout(self.owner_box)
        self._pending = self._add(self.owner_form, "", "Looking up...")

        self.raw = QPlainTextEdit()
        self.raw.setReadOnly(True)
        self.raw.setFont(fonts.mono())
        self.raw.setPlaceholderText("Raw whois output")

        copy = QPushButton("Copy")
        copy.clicked.connect(self.copy_to_clipboard)
        close = QPushButton("Close")
        close.clicked.connect(self.close)
        buttons = QHBoxLayout()
        buttons.addStretch(1)
        buttons.addWidget(copy)
        buttons.addWidget(close)

        # The details keep the height their wrapped lines need; only the raw
        # output gives way (it scrolls) when the window is short.
        for box in (trace_box, self.owner_box):
            box.setSizePolicy(QSizePolicy.Policy.Preferred, QSizePolicy.Policy.Minimum)
        self.raw.setMinimumHeight(80)

        layout = QVBoxLayout(self)
        layout.addWidget(trace_box)
        layout.addWidget(self.owner_box)
        layout.addWidget(self.raw, 1)
        layout.addLayout(buttons)

        self._thread: HopDetailsThread | None = HopDetailsThread(hop.address)
        self._thread.details_ready.connect(self.show_details)
        self._thread.finished.connect(self._on_finished)
        track(self._thread)
        self._thread.start()

    @staticmethod
    def _add(form: QFormLayout, label: str, value: str) -> QLabel:
        field = QLabel(value)
        field.setWordWrap(True)
        field.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        form.addRow(f"{label}:" if label else "", field)
        return field

    def show_details(self, ptr: str, rows: list, raw: str) -> None:
        self.reverse_dns.setText(ptr or "(none)")
        row, _ = self.owner_form.getWidgetPosition(self._pending)
        self.owner_form.removeRow(row)
        if not rows:
            self._add(self.owner_form, "", "Nothing on record")
        for label, value in rows:
            self._add(self.owner_form, label, value)
        self.raw.setPlainText(raw)
        self.raw.setVisible(bool(raw))

    def text(self) -> str:
        """Everything shown, as plain text for the clipboard."""
        lines = []
        for form in (self.trace_form, self.owner_form):
            for row in range(form.rowCount()):
                label = form.itemAt(row, QFormLayout.ItemRole.LabelRole)
                field = form.itemAt(row, QFormLayout.ItemRole.FieldRole)
                if field is None:
                    continue
                name = label.widget().text() if label is not None else ""
                lines.append(f"{name} {field.widget().text()}".strip())
        return "\n".join(lines)

    def copy_to_clipboard(self) -> None:
        QGuiApplication.clipboard().setText(self.text())

    def _on_finished(self) -> None:
        thread, self._thread = self._thread, None
        if thread is not None:
            thread.wait()

    def closeEvent(self, event) -> None:
        thread, self._thread = self._thread, None
        if thread is not None:
            # Let a lookup still running finish in the background, owned by
            # the app (as TracepathWindow does with its trace).
            thread.details_ready.disconnect()
            thread.finished.disconnect()
            retire(thread)
        super().closeEvent(event)
