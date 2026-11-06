"""Port Scan window: which TCP and UDP ports one host has open
(ping/port_scanner.py)."""

from __future__ import annotations

import bisect
import time

from PyQt6.QtCore import Qt, QThread, pyqtSignal
from PyQt6.QtWidgets import (
    QAbstractItemView,
    QComboBox,
    QFormLayout,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QProgressBar,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from . import fonts
from ..osinfo import IS_WINDOWS
from ..ping import port_scanner
from ..ping.port_scanner import PortResult, ScanSummary
from .threads import retire, track

#: Protocol choices: label -> protocols scanned.
PROTOCOLS = (("TCP", (port_scanner.TCP,)), ("UDP", (port_scanner.UDP,)),
             ("TCP + UDP", (port_scanner.TCP, port_scanner.UDP)))

#: How often progress is reported while scanning.
PROGRESS_INTERVAL_S = 0.1


class PortScanThread(QThread):
    #: PortResult of an open port (UDP open|filtered ones are only counted).
    found = pyqtSignal(object)
    progress = pyqtSignal(int, int)  # scanned, total
    #: Recheck round, UDP ports still silent.
    rechecking = pyqtSignal(int, int)
    done = pyqtSignal(object)  # ScanSummary

    def __init__(self, host: str, jobs: list[tuple[str, int]], timeout: float,
                 banners: bool, recheck: bool = True) -> None:
        super().__init__()
        self._host = host
        self._jobs = jobs
        self._timeout = timeout
        self._banners = banners
        self._recheck = recheck
        self._stop = False

    def stop(self) -> None:
        self._stop = True

    def run(self) -> None:
        summary = ScanSummary(host=self._host, total=len(self._jobs))
        started = time.monotonic()
        try:
            summary.ip = port_scanner.resolve(self._host)
        except OSError:
            summary.error = f"\"{self._host}\" doesn't resolve to an address"
            self.done.emit(summary)
            return
        last_progress = 0.0
        silent_jobs: set[tuple[str, int]] = set()  # UDP ports that stayed silent

        def on_result(result: PortResult) -> None:
            nonlocal last_progress
            summary.count(result.state)
            if result.state == port_scanner.OPEN_FILTERED:
                silent_jobs.add((port_scanner.UDP, result.port))
            if result.state == port_scanner.OPEN:
                self.found.emit(result)
            now = time.monotonic()
            if now - last_progress >= PROGRESS_INTERVAL_S:
                last_progress = now
                self.progress.emit(summary.scanned, summary.total)

        completed = port_scanner.scan(
            summary.ip, self._jobs, on_result, lambda: self._stop, timeout=self._timeout,
            banner_timeout=port_scanner.BANNER_TIMEOUT if self._banners else 0,
        )
        silent = sorted(port for _, port in silent_jobs)
        if completed and self._recheck and silent:
            self.progress.emit(summary.scanned, summary.total)

            def settled(result: PortResult) -> None:
                summary.open_filtered -= 1
                summary.scanned -= 1
                summary.count(result.state)
                if result.state == port_scanner.OPEN:
                    self.found.emit(result)

            completed = port_scanner.recheck_udp(
                summary.ip, silent, settled, lambda: self._stop, timeout=self._timeout,
                on_round=self.rechecking.emit,
            )
        summary.stopped = not completed
        summary.elapsed_s = time.monotonic() - started
        self.progress.emit(summary.scanned, summary.total)
        self.done.emit(summary)


class PortScanWindow(QWidget):
    """A non-modal window: host and ports, then Scan."""

    COLUMNS = ("Port", "State", "Service", "Banner / Reply", "Time")

    def __init__(self, host: str = "", parent: QWidget | None = None) -> None:
        super().__init__(parent, Qt.WindowType.Window)
        self.setAttribute(Qt.WidgetAttribute.WA_DeleteOnClose)
        self.setWindowTitle(f"Port Scan — {host}" if host else "Port Scan")
        self.resize(860, 520)
        self._thread: PortScanThread | None = None
        self._results: list[PortResult] = []
        self._summary: ScanSummary | None = None

        self.host = QLineEdit(host)
        self.host.setPlaceholderText("IP address or host name")
        self.preset = QComboBox()
        for label, _ in port_scanner.PRESETS:
            self.preset.addItem(label)
        self.preset.currentIndexChanged.connect(self._preset_changed)
        self.protocol = QComboBox()
        for label, _ in PROTOCOLS:
            self.protocol.addItem(label)
        self.protocol.setToolTip(
            "UDP: well-known services get a real request (DNS, NTP, SNMP, …); a port that "
            "never replies may be open or firewalled (open|filtered)"
        )
        self.protocol.currentIndexChanged.connect(lambda _: self._preset_changed(
            self.preset.currentIndex()))
        self.ports = QLineEdit()
        #: Fixed defaults (no settings in the window): per-probe timeout,
        #: service identification and the slow recheck of silent UDP ports.
        self._timeout = port_scanner.DEFAULT_TIMEOUT
        self._preset_changed(0)

        self.button = QPushButton("Scan")
        self.button.setDefault(True)
        self.button.clicked.connect(self._toggle)
        for field in (self.host, self.ports):
            field.returnPressed.connect(self.start)

        self.progress = QProgressBar()
        self.progress.setTextVisible(True)
        self.progress.setVisible(False)
        ports_row = QHBoxLayout()
        ports_row.addWidget(self.protocol)
        ports_row.addWidget(self.preset)
        self.ports.setMinimumWidth(240)  # keeps its width when the progress bar shows
        ports_row.addWidget(self.ports)
        ports_row.addSpacing(12)
        # The progress bar fills the gap while scanning; Scan sits at the end.
        ports_row.addWidget(self.progress, 1)
        ports_row.addStretch(0)
        ports_row.addWidget(self.button)

        form = QFormLayout()
        form.setFormAlignment(Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignTop)
        # Rows span the window (macOS keeps fields at their size hint by
        # default), so Scan lines up with the table's right edge.
        form.setFieldGrowthPolicy(QFormLayout.FieldGrowthPolicy.AllNonFixedFieldsGrow)
        self.host.setMaximumWidth(260)
        form.addRow("Host:", self.host)
        form.addRow("Ports:", ports_row)

        self.table = QTableWidget(0, len(self.COLUMNS))
        self.table.setHorizontalHeaderLabels(self.COLUMNS)
        self.table.verticalHeader().setVisible(False)
        self.table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        fonts.use_mono(self.table)
        header = self.table.horizontalHeader()
        for column in range(len(self.COLUMNS)):
            header.setSectionResizeMode(column, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(3, QHeaderView.ResizeMode.Stretch)

        self.status = QLabel("Pick the ports and press Scan.")
        self.status.setWordWrap(True)
        self.status.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)

        layout = QVBoxLayout(self)
        layout.addLayout(form)
        layout.addWidget(self.table, 1)
        layout.addWidget(self.status)

    def _preset_changed(self, index: int) -> None:
        spec = port_scanner.PRESETS[index][1]
        custom = not spec
        self.ports.setReadOnly(not custom)
        if custom:
            self.ports.clear()
            self.ports.setPlaceholderText("e.g. 22, 80, 443, 8000-8100")
            self.ports.setFocus()
        elif spec != port_scanner.COMMON:
            self.ports.setText(spec)
        else:
            # The common lists are long: hint at them rather than fill the field.
            jobs = port_scanner.jobs_for(spec, self._protocols())
            self.ports.clear()
            self.ports.setPlaceholderText(
                f"{len(jobs)} ports: " + ", ".join(f"{port}" if len(self._protocols()) == 1
                                                   else f"{port}/{proto}"
                                                   for proto, port in jobs[:10]) + ", …"
            )

    def _protocols(self) -> tuple[str, ...]:
        return PROTOCOLS[self.protocol.currentIndex()][1]

    def _port_spec(self) -> str:
        spec = port_scanner.PRESETS[self.preset.currentIndex()][1]
        return spec or self.ports.text()

    def _toggle(self) -> None:
        if self._thread is None:
            self.start()
        else:
            self.stop()

    def start(self) -> None:
        if self._thread is not None:
            return
        host = self.host.text().strip()
        if not host:
            self.status.setText("✗ Type the host to scan.")
            return
        try:
            jobs = port_scanner.jobs_for(self._port_spec(), self._protocols())
        except ValueError as error:
            self.status.setText(f"✗ {error}.")
            return
        if not jobs:
            self.status.setText("✗ Type the ports to scan, e.g. 22, 80, 8000-8100.")
            return
        self.setWindowTitle(f"Port Scan — {host}")
        self._results.clear()
        self._summary = None
        self.table.setRowCount(0)
        self.progress.setRange(0, len(jobs))
        self.progress.setValue(0)
        self.progress.setVisible(True)
        self.status.setText(f"Scanning {len(jobs):,} {self.protocol.currentText()} ports on {host}…")
        self.button.setText("Stop")
        self._thread = track(PortScanThread(host, jobs, self._timeout, banners=True,
                                            recheck=True))
        self._thread.found.connect(self._add)
        self._thread.progress.connect(self._progress)
        self._thread.rechecking.connect(self._rechecking)
        self._thread.done.connect(self._finished)
        self._thread.start()

    def stop(self) -> None:
        if self._thread is not None:
            self._thread.stop()
            self.button.setEnabled(False)
            self.status.setText("Stopping…")

    def _progress(self, scanned: int, total: int) -> None:
        self.progress.setValue(scanned)
        found = sum(r.state == port_scanner.OPEN for r in self._results)
        self.progress.setFormat(f"{scanned:,} / {total:,}  ·  {found} open")

    def _rechecking(self, round_number: int, silent: int) -> None:
        self.progress.setRange(0, 0)  # busy: how many rounds it takes isn't known
        self.status.setText(
            f"Rechecking {silent:,} silent UDP ports slowly (round {round_number})… "
            "Press Stop to keep what's known."
        )

    def _add(self, result: PortResult) -> None:
        row = bisect.bisect([port_scanner.sort_key(r) for r in self._results],
                            port_scanner.sort_key(result))
        self._results.insert(row, result)
        self.table.insertRow(row)
        port_item = QTableWidgetItem(result.label)
        port_item.setTextAlignment(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)
        time_item = QTableWidgetItem(f"{result.rtt_ms:.0f} ms")
        time_item.setTextAlignment(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)
        banner_item = QTableWidgetItem(result.banner)
        banner_item.setToolTip(result.banner)
        for column, item in enumerate((port_item, QTableWidgetItem(result.state),
                                       QTableWidgetItem(result.service or "?"),
                                       banner_item, time_item)):
            self.table.setItem(row, column, item)

    def _finished(self, summary: ScanSummary) -> None:
        self._thread = None
        self._summary = summary
        self.button.setText("Scan")
        self.button.setEnabled(True)
        self.progress.setVisible(False)
        text = port_scanner.summary_text(summary)
        if not summary.error and summary.ip != summary.host:
            text = f"{summary.host} ({summary.ip}) — {text}"
        # Not on Windows: it retries a connect a closed port refused for ~2 s,
        # longer than the timeout, so closed TCP ports count as filtered there.
        if (not summary.error and summary.scanned and not IS_WINDOWS
                and summary.filtered + summary.open_filtered == summary.scanned):
            text += "\nNothing answered at all: the host may be down, or a firewall drops everything."
        self.status.setText(text)

    def closeEvent(self, event) -> None:
        if self._thread is not None:
            for signal in (self._thread.found, self._thread.progress, self._thread.rechecking,
                           self._thread.done):
                signal.disconnect()
            self._thread.stop()
            retire(self._thread)
            self._thread = None
        super().closeEvent(event)
