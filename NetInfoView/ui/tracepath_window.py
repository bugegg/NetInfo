"""Trace Path MTU window: one row per hop on the way to a host, filled in by
TracepathThread as each hop is probed (ping/tracepath.py)."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor

from PyQt6.QtCore import QCoreApplication, QLocale, Qt, QThread, pyqtSignal
from PyQt6.QtGui import QAction, QBrush, QColor
from PyQt6.QtWidgets import (
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QPushButton,
    QTreeWidget,
    QTreeWidgetItem,
    QVBoxLayout,
    QWidget,
)

from ..ping import hostname, whois
from .hop_details_window import HopDetailsWindow
from ..ping.mtu import format_mtu
from ..ping.tracepath import Hop, trace

COLUMNS = ("Hop", "Address", "Name", "Path MTU", "Country", "Note")
NAME_COLUMN = 2
COUNTRY_COLUMN = 4
#: Hops whose names are looked up at once.
NAME_WORKERS = 8
#: Rows where the path MTU drops are tinted so the culprit stands out.
DROP_TINT = QColor(255, 196, 0, 70)


def country_label(code: str) -> str:
    """"TH" as its flag and name, "🇹🇭 Thailand"; just the code if Qt
    doesn't know it."""
    code = code.upper()
    flag = "".join(chr(0x1F1E6 + ord(letter) - ord("A")) for letter in code)
    territory = QLocale.codeToTerritory(code)
    if territory == QLocale.Country.AnyCountry:
        return f"{flag} {code}"
    return f"{flag} {QLocale.territoryToString(territory)}"


class TracepathThread(QThread):
    #: Each Hop as soon as it has been probed.
    hop_ready = pyqtSignal(object)
    #: (TTL, name) once a hop's address has been resolved.
    name_ready = pyqtSignal(int, str)
    #: (TTL, two-letter country code) once a hop's registration is known.
    country_ready = pyqtSignal(int, str)

    def __init__(self, ip: str) -> None:
        super().__init__()
        self._ip = ip
        self._stop = False

    def stop(self) -> None:
        self._stop = True

    def run(self) -> None:  # noqa: D102 - QThread entry point
        # Names are looked up alongside the trace, not between hops: a
        # private hop's device probes and a whois take seconds each.
        self._names = ThreadPoolExecutor(max_workers=NAME_WORKERS)
        try:
            trace(self._ip, self._on_hop, stopped=lambda: self._stop)
        finally:
            # Wait for the lookups still running, so none emits after the
            # thread is gone; the ones not started yet are dropped on Stop.
            self._names.shutdown(wait=True, cancel_futures=self._stop)

    def _on_hop(self, hop: Hop) -> None:
        self.hop_ready.emit(hop)
        if hop.address and not self._stop:
            self._names.submit(self._resolve, hop.ttl, hop.address)
            self._names.submit(self._find_country, hop.ttl, hop.address)

    def _resolve(self, ttl: int, address: str) -> None:
        if self._stop:
            return
        # No name of its own: say whose network it is in instead, or
        # for a private address that no registry knows, what it's for.
        name = (hostname.resolve(address) or whois.netname(address)
                or whois.reserved_name(address))
        if name:
            self.name_ready.emit(ttl, name)

    def _find_country(self, ttl: int, address: str) -> None:
        if self._stop:
            return
        code = whois.country(address)
        if code:
            self.country_ready.emit(ttl, code)


class TracepathWindow(QWidget):
    """A non-modal window tracing the path MTU to one host."""

    def __init__(self, title: str, ip: str, parent: QWidget | None = None) -> None:
        super().__init__(parent, Qt.WindowType.Window)
        self.setAttribute(Qt.WidgetAttribute.WA_DeleteOnClose)
        self.setWindowTitle(f"Trace Path MTU - {title}")
        self.resize(760, 420)
        self._ip = ip
        self._items: dict[int, QTreeWidgetItem] = {}
        self._hops: dict[int, Hop] = {}
        self._last_mtu: int | None = None
        self._reached = False

        self.tree = QTreeWidget()
        self.tree.setHeaderLabels(COLUMNS)
        self.tree.setRootIsDecorated(False)
        self.tree.setAlternatingRowColors(True)
        header = self.tree.header()
        header.setStretchLastSection(True)
        for column, width in enumerate((40, 130, 220, 70, 150)):
            self.tree.setColumnWidth(column, width)
        header.setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
        # Double-click (or Return) on a hop, or Details... in its menu.
        self.tree.itemActivated.connect(lambda item, _column: self.show_details(item))
        self.tree.setContextMenuPolicy(Qt.ContextMenuPolicy.ActionsContextMenu)
        details = QAction("Details...", self.tree)
        details.triggered.connect(lambda: self.show_details(self.tree.currentItem()))
        self.tree.addAction(details)
        self.tree.setToolTip("Double-click a hop for its details")

        self.status = QLabel()
        self.button = QPushButton()
        self.button.clicked.connect(self._on_button)
        bottom = QHBoxLayout()
        bottom.addWidget(self.status, 1)
        bottom.addWidget(self.button)
        layout = QVBoxLayout(self)
        layout.addWidget(self.tree)
        layout.addLayout(bottom)

        self._thread: TracepathThread | None = None
        self.start()

    def start(self) -> None:
        self.tree.clear()
        self._items.clear()
        self._hops.clear()
        self._last_mtu = None
        self._reached = False
        thread = TracepathThread(self._ip)
        thread.hop_ready.connect(self.add_hop)
        thread.name_ready.connect(self._on_name)
        thread.country_ready.connect(self._on_country)
        thread.finished.connect(self._on_finished)
        self._thread = thread
        self.status.setText(f"Tracing path MTU to {self._ip}...")
        self.button.setText("Stop")
        thread.start()

    def add_hop(self, hop: Hop) -> None:
        mtu = format_mtu(hop.mtu)
        item = QTreeWidgetItem(
            [str(hop.ttl), hop.address or "*", "", mtu, "", hop.note]
        )
        item.setTextAlignment(0, Qt.AlignmentFlag.AlignRight)
        item.setTextAlignment(3, Qt.AlignmentFlag.AlignRight)
        if hop.mtu is not None:
            if self._last_mtu is not None and hop.mtu < self._last_mtu:
                for column in range(len(COLUMNS)):
                    item.setBackground(column, QBrush(DROP_TINT))
            self._last_mtu = hop.mtu
        self._reached = hop.reached
        self._items[hop.ttl] = item
        self._hops[hop.ttl] = hop
        self.tree.addTopLevelItem(item)
        self.tree.scrollToItem(item)

    def show_details(self, item: QTreeWidgetItem | None) -> HopDetailsWindow | None:
        """Open the Details window of the hop on `item`, if it answered."""
        if item is None:
            return None
        hop = self._hops.get(int(item.text(0)))
        if hop is None or not hop.address:
            self.status.setText(f"Hop {item.text(0)} didn't answer: nothing to look up")
            return None
        window = HopDetailsWindow(hop, item.text(NAME_COLUMN), self)
        window.show()
        return window

    def _on_name(self, ttl: int, name: str) -> None:
        item = self._items.get(ttl)
        if item is not None:
            item.setText(NAME_COLUMN, name)

    def _on_country(self, ttl: int, code: str) -> None:
        item = self._items.get(ttl)
        if item is not None:
            item.setText(COUNTRY_COLUMN, country_label(code))
            item.setToolTip(COUNTRY_COLUMN, "Where the address is registered, "
                                            "not necessarily where the device is")

    def _on_button(self) -> None:
        if self._thread is not None:
            self._thread.stop()
            self.button.setEnabled(False)
            self.status.setText("Stopping...")
        else:
            self.start()

    def _on_finished(self) -> None:
        thread, self._thread = self._thread, None
        if thread is not None:
            thread.wait()
        if self._reached:
            self.status.setText(f"Path MTU to {self._ip}: {format_mtu(self._last_mtu)}")
        elif self._last_mtu is None:
            self.status.setText("No hop answered")
        else:
            self.status.setText(
                f"{self._ip} not reached; path MTU as far as it got: {format_mtu(self._last_mtu)}"
            )
        self.button.setText("Trace Again")
        self.button.setEnabled(True)

    def closeEvent(self, event) -> None:
        thread, self._thread = self._thread, None
        if thread is not None:
            # Finishes the hop it's on in the background, not holding up the UI.
            thread.stop()
            thread.hop_ready.disconnect()
            thread.name_ready.disconnect()
            thread.country_ready.disconnect()
            thread.finished.disconnect()
            # Qt mustn't destroy a running QThread along with this window:
            # hand it to the app, which deletes it once it has finished.
            thread.setParent(QCoreApplication.instance())
            thread.finished.connect(thread.deleteLater)
        super().closeEvent(event)
