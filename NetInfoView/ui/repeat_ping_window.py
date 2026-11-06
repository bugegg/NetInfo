"""Repeat Ping window: a Cisco IOS-style extended ping to one host
(ping/repeat_ping.py)."""

from __future__ import annotations

import time

from PyQt6.QtCore import QEvent, Qt, QThread, pyqtSignal
from PyQt6.QtGui import QTextCursor
from PyQt6.QtWidgets import (
    QApplication,
    QFormLayout,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPlainTextEdit,
    QPushButton,
    QSpinBox,
    QVBoxLayout,
    QWidget,
)

from . import fonts
from ..ping import repeat_ping
from ..ping.port_scanner import resolve
from ..ping.repeat_ping import RepeatOptions, RepeatStats
from .threads import retire, track

#: The window's repeat count to start with (IOS's own default is 5).
WINDOW_COUNT = 1000

#: How often the result characters and the stats are passed to the window.
UPDATE_INTERVAL_S = 0.1


class RepeatPingThread(QThread):
    #: Result characters since the last update, and the stats so far.
    progress = pyqtSignal(str, object)
    #: Address pinged ("" if the host didn't resolve).
    resolved = pyqtSignal(str)
    done = pyqtSignal(object, bool)  # RepeatStats, stopped

    def __init__(self, host: str, options: RepeatOptions) -> None:
        super().__init__()
        self._host = host
        self._options = options
        self._stop = False

    def stop(self) -> None:
        self._stop = True

    def run(self) -> None:
        try:
            ip = resolve(self._host)
        except OSError:
            self.resolved.emit("")
            return
        self.resolved.emit(ip)
        stats = RepeatStats()
        pending: list[str] = []
        last = time.monotonic()

        def on_result(char: str, rtt_ms: float | None, size: int) -> None:
            nonlocal last
            stats.add(char, rtt_ms, size)
            pending.append(char)
            now = time.monotonic()
            if now - last >= UPDATE_INTERVAL_S:
                last = now
                self.progress.emit("".join(pending), _copy(stats))
                pending.clear()

        try:
            completed = repeat_ping.run(ip, self._options, on_result, lambda: self._stop)
        except OSError as error:
            pending.append(f"\n% Could not ping: {error.strerror or error}")
            completed = False
        self.progress.emit("".join(pending), _copy(stats))
        self.done.emit(stats, not completed)


def _copy(stats: RepeatStats) -> RepeatStats:
    return RepeatStats(
        stats.sent, stats.received, stats.min_ms, stats.max_ms, stats.total_ms,
        stats.started, stats.elapsed_s, dict(stats.counts), stats.largest_ok_size,
        stats.smallest_failed_size,
    )


class RepeatPingWindow(QWidget):
    """A non-modal window: target and repeat count, then Ping."""

    def __init__(self, host: str = "", parent: QWidget | None = None) -> None:
        super().__init__(parent, Qt.WindowType.Window)
        self.setAttribute(Qt.WidgetAttribute.WA_DeleteOnClose)
        self.setWindowTitle(f"Repeat Ping — {host}" if host else "Repeat Ping")
        self.resize(720, 520)
        self._thread: RepeatPingThread | None = None
        self._stats: RepeatStats | None = None
        #: The output, kept apart so it can be wrapped again to a new width:
        #: header lines, every result character, then the summary.
        self._head = ""
        self._results: list[str] = []
        self._tail = ""
        #: Result characters per line (fits the box) and on the last line.
        self._width = 0
        self._column: int | None = None

        self.host = QLineEdit(host)
        self.host.setPlaceholderText("IP address or host name")
        self.count = QSpinBox()
        self.count.setRange(1, repeat_ping.MAX_COUNT)
        self.count.setValue(WINDOW_COUNT)
        self.count.setGroupSeparatorShown(True)
        self.count.setToolTip(
            "Repeat count. Everything else is Cisco's default: 100-byte datagrams, "
            "2 s timeout, data pattern 0xABCD"
        )
        self.host.returnPressed.connect(self.start)

        self.button = QPushButton("Ping")
        self.button.setDefault(True)
        self.button.clicked.connect(self._toggle)
        self.copy_button = QPushButton("Copy")
        self.copy_button.setEnabled(False)
        self.copy_button.clicked.connect(self.copy)

        target_row = QHBoxLayout()
        target_row.addWidget(self.host, 1)
        target_row.addSpacing(12)
        target_row.addWidget(QLabel("Repeat:"))
        target_row.addWidget(self.count)

        form = QFormLayout()
        form.setFormAlignment(Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignTop)
        form.addRow("Target:", target_row)

        self.stats_label = QLabel(" ")
        self.stats_label.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        buttons = QHBoxLayout()
        buttons.addWidget(self.stats_label, 1)
        buttons.addWidget(self.copy_button)
        buttons.addWidget(self.button)

        self.text = QPlainTextEdit()
        self.text.setReadOnly(True)
        fonts.use_mono(self.text)
        self.text.viewport().installEventFilter(self)
        self.text.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        self.text.setLineWrapMode(QPlainTextEdit.LineWrapMode.NoWrap)

        legend = QLabel("   ".join(f"<b>{char}</b> {meaning}"
                                   for char, meaning in repeat_ping.LEGEND))
        legend.setTextFormat(Qt.TextFormat.RichText)

        layout = QVBoxLayout(self)
        layout.addLayout(form)
        layout.addLayout(buttons)
        layout.addWidget(self.text, 1)
        layout.addWidget(legend)

    def options(self) -> RepeatOptions:
        """Cisco IOS defaults (100-byte datagrams, 2 s timeout, pattern
        0xABCD, no DF); only the repeat count is set here."""
        return RepeatOptions(count=self.count.value())

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
            self.stats_label.setText("✗ Type the target.")
            return
        options = self.options()
        self.setWindowTitle(f"Repeat Ping — {host}")
        self._options = options
        self._host_text = host
        self._stats = None
        self._head, self._results, self._tail = "", [], ""
        self.text.clear()
        self.copy_button.setEnabled(False)
        self.stats_label.setText("Resolving…")
        self.button.setText("Stop")
        self._thread = track(RepeatPingThread(host, options))
        self._thread.resolved.connect(self._resolved)
        self._thread.progress.connect(self._progress)
        self._thread.done.connect(self._finished)
        self._thread.finished.connect(self._thread_ended)
        self._thread.start()

    def stop(self) -> None:
        if self._thread is not None:
            self._thread.stop()
            self.button.setEnabled(False)

    def _line_width(self) -> int:
        """How many result characters fit across the box."""
        margin = 2 * self.text.document().documentMargin()
        advance = self.text.fontMetrics().horizontalAdvance("!") or 1
        # Two characters spare, so the last one doesn't touch the edge.
        return max(10, int((self.text.viewport().width() - margin) // advance) - 2)

    def _render(self) -> None:
        """Lay the whole output out again at the box's current width."""
        self._width = self._line_width()
        results = "".join(self._results)
        lines = [results[i:i + self._width] for i in range(0, len(results), self._width)]
        # None: the results haven't started, so the first one opens a line.
        self._column = len(lines[-1]) if lines else None
        body = "\n".join(lines)
        parts = [part for part in (self._head, body) if part]
        self.text.setPlainText("\n".join(parts) + self._tail)
        scroll = self.text.verticalScrollBar()
        scroll.setValue(scroll.maximum())

    def eventFilter(self, watched, event) -> bool:
        if (watched is self.text.viewport() and event.type() == QEvent.Type.Resize
                and (self._head or self._results) and self._line_width() != self._width):
            self._render()
        return super().eventFilter(watched, event)

    def _append(self, text: str) -> None:
        cursor = self.text.textCursor()
        cursor.movePosition(QTextCursor.MoveOperation.End)
        cursor.insertText(text)
        scroll = self.text.verticalScrollBar()
        scroll.setValue(scroll.maximum())

    def _resolved(self, ip: str) -> None:
        if not ip:
            self._head = f"% Unrecognized host or address: \"{self._host_text}\" doesn't resolve."
            self._render()
            self.stats_label.setText(" ")
            return
        self._head = repeat_ping.header_text(self._host_text, ip, self._options)
        self._render()

    def _progress(self, chars: str, stats: RepeatStats) -> None:
        self._stats = stats
        chars, _, note = chars.partition("\n")  # a send error comes after a newline
        if note:
            self._tail += "\n" + note
        if chars:
            self._results.append(chars)
            if self._line_width() != self._width:
                self._render()
            else:
                wrapped = []
                for char in chars:
                    if self._column is None or self._column == self._width:
                        if self._column is not None or self._head:
                            wrapped.append("\n")
                        self._column = 0
                    wrapped.append(char)
                    self._column += 1
                self._append("".join(wrapped))
        elif note:
            self._render()
        self.stats_label.setText(self._stats_text(stats))

    def _stats_text(self, stats: RepeatStats) -> str:
        total = self._options.total
        loss = stats.lost * 100 / stats.sent if stats.sent else 0.0
        text = (f"Sent {stats.sent:,}/{total:,}  ·  Received {stats.received:,}  ·  "
                f"Loss {stats.lost:,} ({loss:.2f}%)")
        if stats.received:
            text += (f"  ·  {stats.min_ms:.1f}/{stats.avg_ms:.1f}/{stats.max_ms:.1f} ms")
        return text + f"  ·  {stats.rate:,.0f}/s"

    def _finished(self, stats: RepeatStats, stopped: bool) -> None:
        self._stats = stats
        self._tail += "\n" + repeat_ping.summary_text(stats, stopped)
        self._render()
        self.stats_label.setText(self._stats_text(stats) + f"  ·  {stats.elapsed_s:.1f} s")
        self.copy_button.setEnabled(True)

    def _thread_ended(self) -> None:
        self._thread = None
        self.button.setText("Ping")
        self.button.setEnabled(True)

    def copy(self) -> None:
        QApplication.clipboard().setText(self.text.toPlainText())

    def closeEvent(self, event) -> None:
        if self._thread is not None:
            for signal in (self._thread.resolved, self._thread.progress, self._thread.done):
                signal.disconnect()
            # Only this window's slot: threads.track listens on finished too.
            self._thread.finished.disconnect(self._thread_ended)
            self._thread.stop()
            retire(self._thread)
            self._thread = None
        super().closeEvent(event)
