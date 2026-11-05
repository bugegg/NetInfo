"""LLDP/CDP Status window: listens on the network interface the user picks
for LLDP and CDP announcements and shows, in a text box, which switch, port
and VLAN it is plugged into (ping/lldp_cdp.py)."""

from __future__ import annotations

from PyQt6.QtCore import Qt, QThread, QTimer, pyqtSignal
from PyQt6.QtWidgets import (
    QComboBox,
    QFormLayout,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QPlainTextEdit,
    QProgressBar,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

from . import fonts
from ..ping import arp
from ..ping.lldp_cdp import DEFAULT_LISTEN_SECONDS, Neighbor, capture_unavailable, listen
from ..ping.network_interfaces import ethernet_interfaces
from .threads import retire, track

#: Dot colours in the status panel.
GOOD, BAD, IDLE = "#2e9d3a", "#d0352b", "#8a8a8a"


def _dot(colour: str, text: str) -> str:
    return f'<span style="color:{colour}">●</span> {text}'


def format_neighbor(neighbor: Neighbor, interface_label: str) -> str:
    """One announcement as a block of "Field: value" lines: the main ones,
    then everything else the switch sent, the full system description
    last. Empty fields are left out."""
    n = neighbor
    if n.address:
        address = f"{n.address} (from {n.address_source})" if n.address_source else n.address
    else:
        address = "not advertised, and not found in the ARP table"
    rows = [
        ("Switch", n.name),
        ("Switch Port", n.port),
        ("Port ID", n.port_id),
        ("Port Description", n.port_description if n.port_description != n.port else ""),
        ("VLAN", n.vlan),
        ("IP Address", address),
    ]
    rows += [("Management", m) for m in n.management if m != f"IPv4 {n.address}"]
    rows += [
        ("Platform", n.platform),
        ("Capabilities", n.capabilities),
        ("Chassis ID", n.chassis_id if n.chassis_id != n.name else ""),
    ]
    rows += n.details
    extra = [line.strip() for line in n.description.splitlines() if line.strip()]
    if extra and extra[0] == n.platform:
        extra = extra[1:]  # already shown as Platform
    rows += [("Description" if index == 0 else "", line) for index, line in enumerate(extra)]
    rows = [(label, value) for label, value in rows if value]
    width = max(len(label) for label, _ in rows) + 2
    lines = [f"{n.protocol} on {interface_label}"]
    lines += [f"  {label + ':' if label else '':<{width}}{value}" for label, value in rows]
    return "\n".join(lines)


class LldpCdpThread(QThread):
    #: Each switch port as soon as it's heard.
    neighbor_found = pyqtSignal(object)
    #: (interface, message) for an interface that couldn't be listened on.
    error = pyqtSignal(str, str)

    def __init__(self, interfaces: list[str], seconds: float) -> None:
        super().__init__()
        self._interfaces = interfaces
        self._seconds = seconds
        self._stop = False

    def stop(self) -> None:
        self._stop = True

    def run(self) -> None:  # noqa: D102 - QThread entry point
        listen(
            self._interfaces,
            self._on_neighbor,
            self._seconds,
            stopped=lambda: self._stop,
            on_error=self.error.emit,
        )

    def _on_neighbor(self, neighbor: Neighbor) -> None:
        # Many switches advertise only a MAC; if the Mac has talked to the
        # switch's IP on this link, the ARP table knows it.
        if not neighbor.address:
            neighbor.address = arp.find_ip(neighbor.macs)
            neighbor.address_source = "ARP" if neighbor.address else ""
        self.neighbor_found.emit(neighbor)


class LldpCdpWindow(QWidget):
    """A non-modal window: pick an interface, then Check listens on it."""

    def __init__(
        self, parent: QWidget | None = None, seconds: float = DEFAULT_LISTEN_SECONDS
    ) -> None:
        super().__init__(parent, Qt.WindowType.Window)
        self.setAttribute(Qt.WidgetAttribute.WA_DeleteOnClose)
        self.setWindowTitle("LLDP/CDP Status")
        self.resize(760, 520)
        self._seconds = seconds
        self._elapsed = 0
        self._found: list[Neighbor] = []
        self._errors: list[str] = []

        self.interface = QComboBox()
        self.interface.setMinimumContentsLength(28)
        self.refresh_button = QPushButton("Refresh")
        self.refresh_button.setToolTip("Look again for active network interfaces")
        self.refresh_button.clicked.connect(self.refresh_interfaces)
        self.button = QPushButton("Check")
        self.button.setDefault(True)
        self.button.clicked.connect(self._on_button)
        top = QHBoxLayout()
        top.addWidget(QLabel("Interface:"))
        top.addWidget(self.interface, 1)
        top.addWidget(self.refresh_button)
        top.addWidget(self.button)

        self.lldp_label = QLabel()
        self.cdp_label = QLabel()
        status_box = QGroupBox("Status")
        form = QFormLayout(status_box)
        # macOS centres form layouts by default; a status panel reads better flush left.
        form.setFormAlignment(Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignTop)
        form.addRow("LLDP:", self.lldp_label)
        form.addRow("CDP:", self.cdp_label)

        self.text = QPlainTextEdit()
        self.text.setReadOnly(True)
        self.text.setFont(fonts.mono())
        self.text.setPlaceholderText("Waiting for LLDP/CDP announcements...")

        self.progress = QProgressBar()
        self.progress.setRange(0, int(seconds))
        self.progress.setTextVisible(False)
        self.progress.setMaximumWidth(200)
        self.status = QLabel()
        bottom = QHBoxLayout()
        bottom.addWidget(self.status, 1)
        bottom.addWidget(self.progress)
        layout = QVBoxLayout(self)
        layout.addLayout(top)
        layout.addWidget(status_box)
        layout.addWidget(self.text)
        layout.addLayout(bottom)

        self._tick = QTimer(self)
        self._tick.setInterval(1000)
        self._tick.timeout.connect(self._on_tick)
        self._label = ""
        self._thread: LldpCdpThread | None = None
        self.lldp_label.setText(_dot(IDLE, "—"))
        self.cdp_label.setText(_dot(IDLE, "—"))
        self.refresh_interfaces()

    @property
    def running(self) -> bool:
        return self._thread is not None

    def refresh_interfaces(self) -> None:
        """Fill the Interface list with the interfaces that have a link up,
        keeping the current choice if it's still there. A fresh list starts
        on a wired one, before Wi-Fi."""
        if self._thread is not None:
            return
        current = self.interface.currentData()
        self.interface.clear()
        for interface in ethernet_interfaces():
            if interface.active:
                self.interface.addItem(interface.label, interface.name)
        index = self.interface.findData(current)
        if index >= 0:
            self.interface.setCurrentIndex(index)
        has_any = self.interface.count() > 0
        self.button.setEnabled(has_any)
        unavailable = "" if has_any else capture_unavailable()
        if unavailable:
            self.status.setText(unavailable)
        elif has_any:
            self.status.setText("Choose an interface and press Check")
        else:
            self.status.setText("No active interface: plug in a cable and press Refresh")

    def start(self) -> None:
        """Listen afresh on the chosen interface; a no-op while listening."""
        if self._thread is not None:
            return
        self.refresh_interfaces()  # the link may have come or gone since
        name = self.interface.currentData()
        if not name:
            return
        self.text.clear()
        self._found.clear()
        self._errors.clear()
        self._elapsed = 0
        self._label = self.interface.currentText()
        thread = LldpCdpThread([name], self._seconds)
        thread.neighbor_found.connect(self.add_neighbor)
        thread.error.connect(self._on_error)
        thread.finished.connect(self._on_finished)
        self._thread = thread
        self.interface.setEnabled(False)
        self.refresh_button.setEnabled(False)
        self.button.setText("Stop")
        self.button.setEnabled(True)
        self._tick.start()
        self._show_progress()
        track(thread)
        thread.start()

    def add_neighbor(self, neighbor: Neighbor) -> None:
        self._found.append(neighbor)
        self.text.setPlainText("\n\n".join(
            format_neighbor(n, self._label) for n in self._found
        ))
        self._show_progress()

    def _on_error(self, interface: str, message: str) -> None:
        # Only the chosen interface is listened on: name it as the list does
        # (on Windows `interface` is a device GUID).
        self._errors.append(f"{self._label or interface}: {message}")
        self._show_progress()

    def _on_tick(self) -> None:
        self._elapsed = min(self._elapsed + 1, int(self._seconds))
        self._show_progress()

    def _protocol_status(self, protocol: str) -> str:
        heard = [n for n in self._found if n.protocol == protocol]
        if heard:
            names = ", ".join(dict.fromkeys(f"{n.name} port {n.port}" for n in heard))
            return _dot(GOOD, f"Received — {names}")
        if self.running:
            return _dot(IDLE, "Listening...")
        return _dot(BAD, f"Nothing heard in {self._elapsed} s")

    def _show_progress(self) -> None:
        self.lldp_label.setText(self._protocol_status("LLDP"))
        self.cdp_label.setText(self._protocol_status("CDP"))
        self.progress.setValue(self._elapsed)
        if self._errors:
            self.status.setText("; ".join(self._errors))
        elif self.running:
            left = int(self._seconds) - self._elapsed
            self.status.setText(
                f"Listening on {self._label}... {left} s left "
                "(switches announce every 30-60 s)"
            )
        elif self._found:
            self.status.setText(f"{len(self._found)} announcement(s) heard")
        else:
            self.status.setText(
                "No LLDP/CDP heard: the switch may have them turned off, or "
                "this is Wi-Fi (switches rarely send them over it)"
            )

    def _on_button(self) -> None:
        if self._thread is not None:
            self._thread.stop()
            self.button.setEnabled(False)
        else:
            self.start()

    def _on_finished(self) -> None:
        thread, self._thread = self._thread, None
        if thread is not None:
            thread.wait()
        self._tick.stop()
        self._show_progress()
        self.interface.setEnabled(True)
        self.refresh_button.setEnabled(True)
        self.button.setText("Check Again")
        self.button.setEnabled(True)

    def closeEvent(self, event) -> None:
        self._tick.stop()
        thread, self._thread = self._thread, None
        if thread is not None:
            thread.stop()  # it notices within a quarter of a second
            thread.neighbor_found.disconnect()
            thread.error.disconnect()
            thread.finished.disconnect()
            # As in TracepathWindow: let the app delete it once it finishes.
            retire(thread)
        super().closeEvent(event)
