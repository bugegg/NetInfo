"""Route Monitor window: every hop on the way to a host, pinged each interval
(ping/route_monitor.py), with each hop's latency and loss over the focus
time in the table and the selected hop's history on a timeline below. Every
sample is logged to a SQLite file as it comes (model/route_log.py)."""

from __future__ import annotations

import ipaddress
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from pathlib import Path

from PyQt6.QtCore import QPointF, QRectF, QSize, Qt, QThread, QTimer, pyqtSignal
from PyQt6.QtGui import QColor, QFont, QFontMetrics, QPainter, QPainterPath, QPen
from PyQt6.QtWidgets import (
    QComboBox, QDialog, QDialogButtonBox, QDoubleSpinBox, QFileDialog, QFormLayout, QHBoxLayout, QHeaderView, QLabel, QLineEdit, QPushButton, QSplitter,
    QStyle, QStyledItemDelegate, QTreeWidget, QTreeWidgetItem, QVBoxLayout, QWidget,
)

from ..model.route_log import (
    KEEP_DAYS, HopStats, RouteLog, RouteLogFile, export_csv, log_path, prune_logs, rate_limited,
)
from ..model.samples import nice_ceiling
from ..ping import hostname, netpath, whois
from ..settings import Settings
from ..ping.route_monitor import RoundProbe, RouteChange, RouteTracker, default_round_probe, resolve
from .netpath_window import AMBER, GREEN, LEVEL_FILLS, LEVEL_TEXT, RED
from .ping_graph import LOSS_COLOR, PingGraphWidget, local_time
from .threads import retire, track

#: (label, seconds) choices for how often every hop is pinged.
INTERVALS = (("1 s", 1.0), ("2.5 s", 2.5), ("5 s", 5.0), ("10 s", 10.0), ("30 s", 30.0), ("60 s", 60.0))
DEFAULT_INTERVAL = 1.0
#: (label, seconds; 0 for everything kept) choices for the focus time.
FOCUS = (("1 minute", 60), ("5 minutes", 300), ("10 minutes", 600), ("30 minutes", 1800),
         ("1 hour", 3600), ("6 hours", 21600), ("All", 0))
DEFAULT_FOCUS = 600
#: Names looked up at once: every hop of a long route, since a private
#: address's reverse lookup can take seconds to come back empty.
NAME_WORKERS = 32

COLUMNS = ("Hop", "PL%", "IP", "Name", "Avg", "Min", "Max", "Jitter", "Cur", "Latency")
HOP, PL, IP, NAME, AVG, MIN, MAX, JITTER, CUR, LATENCY = range(len(COLUMNS))
NUMBER_COLUMNS = (PL, AVG, MIN, MAX, JITTER, CUR)

TTL_ROLE = Qt.ItemDataRole.UserRole
#: The hop bubble's colour, or "" for a hop that never answered.
BUBBLE_ROLE = Qt.ItemDataRole.UserRole + 1
#: What the latency column draws: see RouteMonitorWindow.refresh.
LATENCY_ROLE = Qt.ItemDataRole.UserRole + 2
#: Set on the Name of the hop the graph shows.
GRAPHED_ROLE = Qt.ItemDataRole.UserRole + 3

#: Net Path's level colours: the hop bubble, and lighter, the bands behind
#: the latency column and the graph.
BUBBLE_GOOD = GREEN
BUBBLE_WARN = AMBER
BUBBLE_BAD = RED
BAND_GOOD = QColor(LEVEL_FILLS[netpath.OK])
BAND_WARN = QColor(LEVEL_FILLS[netpath.WARN])
BAND_BAD = QColor(LEVEL_FILLS[netpath.CRIT])
#: The timeline's colours, from the design mockup.
GRAPH_BANDS = (QColor("#d6e6cf"), QColor("#f6e3c3"), QColor("#f4c9c6"))
GRAPH_LINE = QColor("#1d2330")
GRAPH_LOSS = QColor(224, 53, 43, 217)  # #e0352b at 85%
GRAPH_LOSS_LINE = QColor("#e0352b")
GRAPH_GRID = QColor("#e3e5e9")
CURRENT_COLOR = QColor("#0b5bd3")
ROUTE_CHANGE_COLOR = QColor("#0b5bd3")
GRAPHED_COLOR = QColor("#0b5bd3")
GRAPHED_TEXT = "● graphed"
LOGGING_COLOR = GREEN

#: The packet-loss bar in the latency column, and its label.
LOSS_BAR = QColor(229, 56, 59, 105)
LOSS_TEXT = QColor("#16191f")

#: Fitting the columns: room beside the text, the Name column's cap, and
#: the width of its "● graphed" tag.
COLUMN_PADDING = 10
NAME_MAX_WIDTH = 300
GRAPHED_TAG_WIDTH = 100

LIMITED_TIP = ("This router answers only so many probes; the hops after it lose less, "
               "so this isn't loss on the path.")


@dataclass(frozen=True)
class Thresholds:
    """Where a hop turns Warning (amber) and Critical (red): Net Path's
    thresholds, SolarWinds' defaults, by the hop's average latency or its
    loss (0 leaves loss out; loss a router only limits its replies with
    never counts)."""

    warn_ms: float = netpath.WARN_MS
    crit_ms: float = netpath.CRIT_MS
    warn_loss: float = netpath.WARN_LOSS * 100
    crit_loss: float = netpath.CRIT_LOSS * 100

    @classmethod
    def from_settings(cls, settings: Settings) -> Thresholds:
        return cls(settings.route_latency_warn_ms, settings.route_latency_crit_ms,
                   settings.route_loss_warn_percent, settings.route_loss_crit_percent)

    def store(self, settings: Settings) -> None:
        settings.route_latency_warn_ms = self.warn_ms
        settings.route_latency_crit_ms = self.crit_ms
        settings.route_loss_warn_percent = self.warn_loss
        settings.route_loss_crit_percent = self.crit_loss


def bubble_color(stats: HopStats, limited: bool, limits: Thresholds = Thresholds()) -> str:
    if stats.avg_ms is None:
        return ""
    loss = 0.0 if limited else stats.loss_percent
    if stats.avg_ms >= limits.crit_ms or (limits.crit_loss and loss >= limits.crit_loss):
        return BUBBLE_BAD
    if stats.avg_ms >= limits.warn_ms or (limits.warn_loss and loss >= limits.warn_loss):
        return BUBBLE_WARN
    return BUBBLE_GOOD


def legend_html(limits: Thresholds) -> str:
    def dot(color: str) -> str:
        return f"<span style='color:{color}; font-size:14px'>●</span>"

    def loss(word: str, percent: float) -> str:
        return f" {word} {percent:g}%+ loss" if percent else ""

    gap = "&nbsp;&nbsp;&nbsp;"
    return (f"{dot(BUBBLE_GOOD)} {LEVEL_TEXT[netpath.OK]}: under {limits.warn_ms:g} ms"
            f"{loss('and under', limits.warn_loss).replace('%+', '%')}{gap}"
            f"{dot(BUBBLE_WARN)} {LEVEL_TEXT[netpath.WARN]}: {limits.warn_ms:g} ms+"
            f"{loss('or', limits.warn_loss)}{gap}"
            f"{dot(BUBBLE_BAD)} {LEVEL_TEXT[netpath.CRIT]}: {limits.crit_ms:g} ms+"
            f"{loss('or', limits.crit_loss)}")


class ThresholdsDialog(QDialog):
    """Set the latency and loss at which hops turn Warning and Critical."""

    def __init__(self, limits: Thresholds, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setWindowTitle("Ping Monitor Colors")

        def box(value: float, suffix: str, top: float, off: bool = False) -> QDoubleSpinBox:
            spin = QDoubleSpinBox()
            spin.setRange(0, top)
            spin.setDecimals(1)
            spin.setSuffix(suffix)
            if off:
                spin.setSpecialValueText("Off")
            spin.setValue(value)
            return spin

        self.warn_ms = box(limits.warn_ms, " ms", 10000)
        self.crit_ms = box(limits.crit_ms, " ms", 10000)
        self.warn_loss = box(limits.warn_loss, " %", 100, off=True)
        self.crit_loss = box(limits.crit_loss, " %", 100, off=True)
        form = QFormLayout()
        default = Thresholds()
        note = QLabel(
            "A hop turns Warning or Critical when its average latency <b>or</b> its packet "
            "loss reaches these values. The defaults are Net Path's: "
            f"{default.warn_ms:g} / {default.crit_ms:g} ms and "
            f"{default.warn_loss:g} / {default.crit_loss:g}% loss. "
            "The bands behind the latency column and the graph follow the latency values. "
            "Off leaves loss out.")
        note.setWordWrap(True)
        form.addRow(note)
        form.addRow(f"<span style='color:{BUBBLE_WARN}'>●</span> Warning from latency", self.warn_ms)
        form.addRow(f"<span style='color:{BUBBLE_BAD}'>●</span> Critical from latency", self.crit_ms)
        form.addRow(f"<span style='color:{BUBBLE_WARN}'>●</span> Warning from loss", self.warn_loss)
        form.addRow(f"<span style='color:{BUBBLE_BAD}'>●</span> Critical from loss", self.crit_loss)
        self.error = QLabel("")
        self.error.setStyleSheet(f"color: {BUBBLE_BAD}")
        form.addRow(self.error)
        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok
                                   | QDialogButtonBox.StandardButton.Cancel
                                   | QDialogButtonBox.StandardButton.RestoreDefaults)
        buttons.accepted.connect(self._accept)
        buttons.rejected.connect(self.reject)
        buttons.button(QDialogButtonBox.StandardButton.RestoreDefaults).clicked.connect(self._defaults)
        form.addRow(buttons)
        self.setLayout(form)
        self.setMinimumWidth(380)

    def thresholds(self) -> Thresholds:
        return Thresholds(self.warn_ms.value(), self.crit_ms.value(),
                          self.warn_loss.value(), self.crit_loss.value())

    def _defaults(self) -> None:
        default = Thresholds()
        self.warn_ms.setValue(default.warn_ms)
        self.crit_ms.setValue(default.crit_ms)
        self.warn_loss.setValue(default.warn_loss)
        self.crit_loss.setValue(default.crit_loss)

    def _accept(self) -> None:
        limits = self.thresholds()
        if limits.warn_ms < 1 or limits.crit_ms <= limits.warn_ms:
            self.error.setText("Critical latency must be higher than Warning latency.")
            return
        if limits.crit_loss and limits.crit_loss < limits.warn_loss:
            self.error.setText("Critical loss can't be lower than Warning loss.")
            return
        self.accept()


def loss_text(loss: float, limited: bool = False) -> str:
    """The packet-loss bar's label: "8.61% packet loss"."""
    text = "100% packet loss (no reply)" if loss >= 100 else f"{loss:.2f}% packet loss"
    # "*" as in the PL% column, whose tooltip says what it means.
    return text + " *" if limited else text


def latency_scale(stats) -> float:
    """The latency column's scale, as the graph's is worked out: the highest
    latency any hop had in the focus time, plus a tenth, rounded up to a tidy
    value, so every hop's whisker fits (PingPlotter's scale follows its
    slowest sample too). The bands show once latency gets that far."""
    highest = max((s.max_ms for s in stats if s.max_ms is not None), default=0.0)
    return nice_ceiling(highest * 1.1)


def format_ms(value: float | None) -> str:
    if value is None:
        return ""
    return f"{value:.1f}" if value < 10 else f"{value:.0f}"


def is_address(text: str) -> bool:
    try:
        ipaddress.ip_address(text.strip())
    except ValueError:
        return False
    return True


class RouteMonitorThread(QThread):
    """Pings every hop of the route to one host each `interval` seconds,
    logs each round, and looks up the names of the hops."""

    #: The host's IPv4 address, once resolved.
    resolved = pyqtSignal(str)
    #: Each round's RoundResult.
    round_ready = pyqtSignal(object)
    name_ready = pyqtSignal(str, str)
    #: Why monitoring can't go on; the thread has stopped.
    failed = pyqtSignal(str)
    #: Why the log file can't be written; monitoring goes on without it.
    log_failed = pyqtSignal(str)

    def __init__(self, target: str, interval: float, log_file: Path | None,
                 probe: RoundProbe | None = None) -> None:
        super().__init__()
        self.target = target
        self.interval = interval
        self._log_file = log_file
        self._probe = probe or default_round_probe()
        self._stop = False
        self._looked_up: set[str] = set()

    def stop(self) -> None:
        self._stop = True

    def run(self) -> None:  # noqa: D102 - QThread entry point
        try:
            ip = resolve(self.target)
        except (OSError, UnicodeError) as error:
            self.failed.emit(f"Can't find {self.target}: {error}")
            return
        self.resolved.emit(ip)
        log = None
        if self._log_file is not None:
            try:
                log = RouteLogFile(self._log_file, self.target, ip, self.interval)
            except Exception as error:  # noqa: BLE001 - monitoring goes on without a log
                self.log_failed.emit(f"Not logging to {self._log_file}: {error}")
        lookups = ThreadPoolExecutor(max_workers=NAME_WORKERS)
        tracker = RouteTracker()
        try:
            while not self._stop:
                began = time.monotonic()
                started = time.time()
                answers = self._probe(ip, tracker.ttls(), tracker.round)
                if self._stop:
                    break
                result = tracker.record(started, answers)
                if log is not None:
                    try:
                        log.write(result)
                    except Exception as error:  # noqa: BLE001 - e.g. the disk is full
                        log.close()
                        log = None
                        self.log_failed.emit(f"Logging stopped: {error}")
                self.round_ready.emit(result)
                for sample in result.samples:
                    if sample.address and sample.address not in self._looked_up:
                        self._looked_up.add(sample.address)
                        lookups.submit(self._name, sample.address)
                until = began + self.interval
                while not self._stop and time.monotonic() < until:
                    self.msleep(50)
        finally:
            lookups.shutdown(wait=False, cancel_futures=True)
            # A lookup still out (a reverse lookup can take seconds) finishes
            # on its own; stopping needn't wait for it.
            if log is not None:
                log.close()

    def _name(self, address: str) -> None:
        if self._stop:
            return
        name = (hostname.resolve(address) or whois.netname(address)
                or whois.reserved_name(address))
        self.name_ready.emit(address, name or "")


def _selected_ink(widget) -> QColor:
    """The text colour of a selected row in the app's theme. Not the
    palette's HighlightedText: Windows' style keeps that white while the
    app stylesheet paints the selection light, which made the tag vanish."""
    from .dashboard import theme_colors
    main = widget.window().parentWidget() if widget is not None else None
    settings = getattr(main, "settings", None)
    return QColor(theme_colors(bool(getattr(settings, "dark_background", False)))["selected_ink"])


class HopDelegate(QStyledItemDelegate):
    """Paints the hop number as a coloured bubble, and the latency column:
    the packet-loss bar and the min-max whisker (RouteLineOverlay adds the
    route line and the ○ / × marks),
    on Net Path's green / amber / red bands."""

    def sizeHint(self, option, index) -> QSize:
        size = super().sizeHint(option, index)
        return QSize(size.width(), max(size.height(), 24))

    def paint(self, painter: QPainter, option, index) -> None:
        if index.column() == HOP:
            self._paint_hop(painter, option, index)
        elif index.column() == LATENCY:
            self._paint_latency(painter, option, index)
        elif index.column() == NAME and index.data(GRAPHED_ROLE):
            self._paint_graphed_name(painter, option, index)
        else:
            super().paint(painter, option, index)

    def _paint_graphed_name(self, painter: QPainter, option, index) -> None:
        """The name, with a "● graphed" tag at the right end of the cell."""
        # The row's own size, semibold, so the tag reads as easily as the name.
        tag_font = QFont(option.font)
        tag_font.setWeight(QFont.Weight.DemiBold)
        tag_width = QFontMetrics(tag_font).horizontalAdvance(GRAPHED_TEXT) + 12
        name_option = type(option)(option)
        name_option.rect = option.rect.adjusted(0, 0, -tag_width, 0)
        style = option.widget.style() if option.widget else None
        if style is not None:
            # Selection background across the whole cell, the name in its share.
            full = type(option)(option)
            self.initStyleOption(full, index)
            full.text = ""
            style.drawControl(QStyle.ControlElement.CE_ItemViewItem, full, painter, option.widget)
        super().paint(painter, name_option, index)
        painter.save()
        painter.setFont(tag_font)
        selected = bool(option.state & QStyle.StateFlag.State_Selected)
        painter.setPen(_selected_ink(option.widget) if selected else GRAPHED_COLOR)
        painter.drawText(QRectF(option.rect).adjusted(0, 0, -6, 0),
                         Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter, GRAPHED_TEXT)
        painter.restore()

    def _paint_hop(self, painter: QPainter, option, index) -> None:
        self.initStyleOption(option, index)
        text, option.text = option.text, ""
        style = option.widget.style() if option.widget else None
        if style is not None:
            style.drawControl(QStyle.ControlElement.CE_ItemViewItem, option, painter, option.widget)
        color = index.data(BUBBLE_ROLE) or ""
        painter.save()
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        rect = option.rect
        width = max(22, painter.fontMetrics().horizontalAdvance(text) + 12)
        pill = QRectF(rect.left() + 6, rect.center().y() - 9, width, 18)
        if color:
            painter.setPen(Qt.PenStyle.NoPen)
            painter.setBrush(QColor(color))
            painter.drawRoundedRect(pill, 9, 9)
            painter.setPen(QColor("#ffffff"))
        else:
            painter.setPen(option.palette.color(option.palette.ColorRole.PlaceholderText))
        bold = QFont(option.font)
        bold.setBold(True)
        painter.setFont(bold)
        painter.drawText(pill, Qt.AlignmentFlag.AlignCenter, text)
        painter.restore()

    def _paint_latency(self, painter: QPainter, option, index) -> None:
        data = index.data(LATENCY_ROLE)
        rect = QRectF(option.rect)
        painter.save()
        if not data:
            painter.restore()
            return
        top, warn, crit = data["top"], data["warn"], data["crit"]

        def x(ms: float) -> float:
            return band_x(rect, ms, top)

        painter.fillRect(rect, BAND_GOOD)
        if top > warn:
            # To the edge when the scale stops short of Critical.
            right = x(crit) if top > crit else rect.right() + 1
            painter.fillRect(QRectF(x(warn), rect.top(), right - x(warn),
                                    rect.height()), BAND_WARN)
        if top > crit:
            painter.fillRect(QRectF(x(crit), rect.top(), rect.right() - x(crit),
                                    rect.height()), BAND_BAD)
        # Packet loss as in PingPlotter: a bar from the left edge as long as
        # the loss (the whole width is 100%), labelled, under the latency marks.
        loss = 100.0 if data["silent"] else data["loss"]
        if loss > 0:
            bar = QRectF(rect.left(), rect.top() + 3, rect.width() * min(loss, 100.0) / 100,
                         rect.height() - 6)
            # Always red; "*" in the label marks a router limiting its replies.
            painter.fillRect(bar, LOSS_BAR)
            painter.setPen(LOSS_TEXT)
            painter.drawText(rect.adjusted(6, 0, -6, 0), Qt.AlignmentFlag.AlignVCenter,
                             loss_text(loss, data["limited"]))
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        if data["avg"] is None:
            painter.restore()
            return
        cy = rect.center().y()
        painter.setPen(QPen(QColor("#6b7280"), 1.2))
        low, high = x(data["min"]), x(data["max"])
        painter.drawLine(QPointF(low, cy), QPointF(high, cy))
        painter.drawLine(QPointF(low, cy - 3), QPointF(low, cy + 3))
        painter.drawLine(QPointF(high, cy - 3), QPointF(high, cy + 3))
        # The route line and the ○ / × marks are RouteLineOverlay's, drawn
        # over the whole column at once.
        painter.restore()


class RouteLineOverlay(QWidget):
    """The route line over the latency column, as PingPlotter draws it: one
    line through every hop's average, straight past the hops that don't
    answer, then each hop's ○ average and × latest on top. The rows (bands,
    loss bars, whiskers) are the delegate's; this lies over the tree's
    viewport and lets the mouse through."""

    def __init__(self, tree: QTreeWidget) -> None:
        super().__init__(tree.viewport())
        self.tree = tree
        self.setAttribute(Qt.WidgetAttribute.WA_TransparentForMouseEvents)
        self.setAttribute(Qt.WidgetAttribute.WA_NoSystemBackground)
        tree.viewport().installEventFilter(self)
        tree.header().sectionResized.connect(self.update)
        tree.header().geometriesChanged.connect(self.update)
        tree.verticalScrollBar().valueChanged.connect(self._follow)
        tree.horizontalScrollBar().valueChanged.connect(self._follow)
        self.resize(tree.viewport().size())
        self.raise_()

    def _follow(self) -> None:
        # Scrolling a viewport moves its child widgets along with the
        # content; this one stays put and redraws instead.
        self.move(0, 0)
        self.update()

    def eventFilter(self, watched, event) -> bool:
        if event.type() == event.Type.Resize:
            self.resize(watched.size())
        return False

    def points(self) -> list[tuple[QPointF, float | None]]:
        """(the hop's average, where its latest lands or None) for each hop
        that answered, top to bottom, in viewport coordinates."""
        header = self.tree.header()
        left = header.sectionViewportPosition(LATENCY)
        width = header.sectionSize(LATENCY)
        out = []
        for row in range(self.tree.topLevelItemCount()):
            item = self.tree.topLevelItem(row)
            data = item.data(LATENCY, LATENCY_ROLE)
            if not data or data["avg"] is None:
                continue
            rect = self.tree.visualItemRect(item)
            column = QRectF(left, rect.top(), width, rect.height())
            y = column.center().y()
            cur = None if data["cur"] is None else band_x(column, data["cur"], data["top"])
            out.append((QPointF(band_x(column, data["avg"], data["top"]), y), cur))
        return out

    def paintEvent(self, event) -> None:
        if self.pos().x() or self.pos().y():
            self.move(0, 0)  # scrolled along; repainted from the right place
            return
        points = self.points()
        if not points:
            return
        header = self.tree.header()
        painter = QPainter(self)
        painter.setClipRect(QRectF(header.sectionViewportPosition(LATENCY), 0,
                                   header.sectionSize(LATENCY), self.height()))
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        painter.setPen(QPen(LOSS_COLOR, 1.6))
        for (a, _), (b, _) in zip(points, points[1:]):
            painter.drawLine(a, b)
        for average, cur in points:
            painter.setPen(QPen(LOSS_COLOR, 1.6))
            painter.setBrush(QColor("#ffffff"))
            painter.drawEllipse(average, 3.6, 3.6)
            if cur is not None:
                y = average.y()
                painter.setPen(QPen(CURRENT_COLOR, 1.8))
                painter.drawLine(QPointF(cur - 3.5, y - 3.5), QPointF(cur + 3.5, y + 3.5))
                painter.drawLine(QPointF(cur + 3.5, y - 3.5), QPointF(cur - 3.5, y + 3.5))
        painter.end()


def band_x(rect: QRectF, ms: float, top: float) -> float:
    """Where `ms` falls across the latency column (rows and header alike)."""
    return rect.left() + 6 + min(ms, top) / top * (rect.width() - 12)


class LatencyHeader(QHeaderView):
    """The table's header, with the latency column's drawn as PingPlotter
    does: the colour bands at the rows' scale, "0 ms" at the left, the
    scale's top at the right, and "Latency" on a tab in the middle."""

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(Qt.Orientation.Horizontal, parent)
        # As QTreeWidget's own header: titles to the left.
        self.setDefaultAlignment(Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter)
        #: (top of the scale, warning, critical) in ms; None until measured.
        self.scale: tuple[float, float, float] | None = None

    def set_scale(self, top: float, warn: float, crit: float) -> None:
        if self.scale != (top, warn, crit):
            self.scale = (top, warn, crit)
            self.viewport().update()

    def paintSection(self, painter: QPainter, rect, logical_index: int) -> None:
        super().paintSection(painter, rect, logical_index)
        if logical_index != LATENCY or not rect.isValid():
            return
        painter.save()
        area = QRectF(rect).adjusted(0, 0, 0, -1)
        if self.scale is not None:
            top, warn, crit = self.scale
            painter.fillRect(area, BAND_GOOD)
            if top > warn:
                right = band_x(area, crit, top) if top > crit else area.right() + 1
                painter.fillRect(QRectF(band_x(area, warn, top), area.top(),
                                        right - band_x(area, warn, top), area.height()), BAND_WARN)
            if top > crit:
                x = band_x(area, crit, top)
                painter.fillRect(QRectF(x, area.top(), area.right() + 1 - x, area.height()), BAND_BAD)
        else:
            painter.fillRect(area, self.palette().color(self.palette().ColorRole.Button))
        ink = QColor("#16191f")
        metrics = painter.fontMetrics()
        # The tab: a trapezoid in the header's own colour under "Latency".
        title = "Latency"
        tab_width = metrics.horizontalAdvance(title) + 60
        center = area.center().x()
        slant = area.height() * 0.6
        tab = QPainterPath()
        tab.moveTo(center - tab_width / 2 - slant, area.top())
        tab.lineTo(center + tab_width / 2 + slant, area.top())
        tab.lineTo(center + tab_width / 2, area.bottom() + 1)
        tab.lineTo(center - tab_width / 2, area.bottom() + 1)
        tab.closeSubpath()
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        painter.fillPath(tab, self.palette().color(self.palette().ColorRole.Base))
        painter.setPen(self.palette().color(self.palette().ColorRole.Text))
        painter.drawText(area, Qt.AlignmentFlag.AlignCenter, title)
        if self.scale is not None:
            painter.setPen(ink)
            sides = area.adjusted(8, 0, -8, 0)
            painter.drawText(sides, Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter, "0 ms")
            painter.drawText(sides, Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter,
                             f"{format_scale(self.scale[0])} ms")
        painter.restore()


def format_scale(ms: float) -> str:
    return f"{ms:g}" if ms < 10000 else f"{ms:,.0f}"


class RouteGraph(PingGraphWidget):
    """The ping graph, plus a dashed line where the route changed."""

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.changes: list[RouteChange] = []
        self.band_colors = GRAPH_BANDS
        self.line_color = GRAPH_LINE
        self.line_width = 1.2
        self.loss_color = GRAPH_LOSS
        self.loss_line_color = GRAPH_LOSS_LINE
        self.grid_color = GRAPH_GRID
        self.frame_color = GRAPH_GRID
        # The bands run the whole width, as in the mockup.
        self.no_data_color = None
        #: Shown across an empty graph: why there's nothing to draw yet.
        self.empty_text = ""

    def paintEvent(self, event) -> None:
        super().paintEvent(event)
        if self.empty_text and not self._samples:
            painter = QPainter(self)
            painter.setPen(QColor("#5f6673"))
            painter.drawText(self._plot_rect(), Qt.AlignmentFlag.AlignCenter, self.empty_text)
            painter.end()
        if not self.changes:
            return
        painter = QPainter(self)
        plot = self._plot_rect()
        painter.setFont(self._small_font())
        for change in self.changes:
            x = self._x_for(change.timestamp, plot)
            if not plot.left() <= x <= plot.right():
                continue
            painter.setPen(QPen(ROUTE_CHANGE_COLOR, 1.5, Qt.PenStyle.DashLine))
            painter.drawLine(QPointF(x, plot.top()), QPointF(x, plot.bottom()))
            painter.setPen(ROUTE_CHANGE_COLOR)
            text = f"Route changed at hop {change.ttl}"
            width = painter.fontMetrics().horizontalAdvance(text) + 8
            # Beside the line, on whichever side has room.
            left = x + 4 if x + width <= plot.right() else x - width
            painter.drawText(QRectF(left, plot.top() + 2, width, 16), Qt.AlignmentFlag.AlignLeft,
                             text)
        painter.end()


class RouteMonitorWindow(QWidget):
    """A non-modal window watching the route to one host."""

    def __init__(self, target: str = "", title: str = "", parent: QWidget | None = None,
                 probe: RoundProbe | None = None, start: bool = True,
                 log_folder: Path | None = None) -> None:
        super().__init__(parent, Qt.WindowType.Window)
        self.setAttribute(Qt.WidgetAttribute.WA_DeleteOnClose)
        self.resize(1120, 760)
        self._probe = probe
        self._log_folder = log_folder
        self.log = RouteLog()
        self.names: dict[str, str] = {}
        self.ip = ""
        #: The target this session's log belongs to.
        self.session_target = ""
        self.log_file: Path | None = None
        self.selected_ttl: int | None = None
        self._thread: RouteMonitorThread | None = None
        self._title = title
        #: (rows, the names) when the columns were last fitted to them.
        self._fitted_shape: tuple[int, int] | None = None
        #: Rounds in a row in which no hop at all answered.
        self._silent_rounds = 0
        #: Whether this run's samples are reaching the log file.
        self._logging_ok = False
        #: The main window's settings, where the colour thresholds are kept.
        self._settings: Settings | None = getattr(parent, "settings", None)
        self.limits = (Thresholds.from_settings(self._settings) if self._settings is not None
                       else Thresholds())
        #: A problem worth keeping on the status line (e.g. not logging).
        self._warning = ""

        self.button = QPushButton("Start")
        self.button.setDefault(True)
        self.button.clicked.connect(self.toggle)
        self.target = QLineEdit(target)
        self.target.setPlaceholderText("Host name or IP address")
        self.target.setMinimumWidth(200)
        self.target.returnPressed.connect(self.start)
        self.ip_label = QLabel("")
        self.ip_label.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        self.interval = QComboBox()
        for label, seconds in INTERVALS:
            self.interval.addItem(label, seconds)
        self.interval.setCurrentIndex(next(i for i, (_, s) in enumerate(INTERVALS)
                                           if s == DEFAULT_INTERVAL))
        self.interval.setToolTip("How often every hop is pinged")
        self.interval.currentIndexChanged.connect(self._on_interval)
        self.focus = QComboBox()
        for label, seconds in FOCUS:
            self.focus.addItem(label, seconds)
        self.focus.setCurrentIndex(next(i for i, (_, s) in enumerate(FOCUS) if s == DEFAULT_FOCUS))
        self.focus.setToolTip("The stretch of time the table's numbers and the graph cover")
        self.focus.currentIndexChanged.connect(self.refresh)
        self.meta = QLabel("")
        self.meta.setObjectName("muted")
        self.logging_label = QLabel("")
        self.logging_label.setTextFormat(Qt.TextFormat.RichText)
        self.export_button = QPushButton("Export CSV…")
        self.export_button.setToolTip("Save every sample of this session's log as CSV")
        self.export_button.setEnabled(False)
        self.export_button.clicked.connect(self.export)
        self.colors_button = QPushButton("Colors…")
        self.colors_button.setToolTip("Set the latency (and loss) at which hops turn yellow and red")
        self.colors_button.clicked.connect(self.edit_colors)

        toolbar = QHBoxLayout()
        toolbar.addWidget(self.button)
        toolbar.addSpacing(8)
        toolbar.addWidget(QLabel("Target"))
        toolbar.addWidget(self.target)
        toolbar.addWidget(self.ip_label)
        toolbar.addSpacing(12)
        toolbar.addWidget(QLabel("Interval"))
        toolbar.addWidget(self.interval)
        toolbar.addSpacing(12)
        toolbar.addWidget(QLabel("Focus"))
        toolbar.addWidget(self.focus)
        toolbar.addStretch(1)
        toolbar.addWidget(self.meta)
        toolbar.addSpacing(8)
        toolbar.addWidget(self.logging_label)
        toolbar.addSpacing(8)
        toolbar.addWidget(self.colors_button)
        toolbar.addWidget(self.export_button)

        self.tree = QTreeWidget()
        self.latency_header = LatencyHeader(self.tree)
        self.tree.setHeader(self.latency_header)
        self.tree.setColumnCount(len(COLUMNS))
        self.tree.setHeaderLabels(COLUMNS)
        self.tree.setRootIsDecorated(False)
        self.tree.setUniformRowHeights(True)
        self.tree.setAllColumnsShowFocus(True)
        self.tree.setItemDelegate(HopDelegate(self.tree))
        header = self.tree.header()
        header.setStretchLastSection(True)
        header.setSectionResizeMode(NAME, QHeaderView.ResizeMode.Interactive)
        for column, width in ((HOP, 52), (PL, 52), (IP, 120), (NAME, 220)):
            self.tree.setColumnWidth(column, width)
        for column in (AVG, MIN, MAX, JITTER, CUR):
            self.tree.setColumnWidth(column, 56)
        for column in NUMBER_COLUMNS:
            self.tree.headerItem().setTextAlignment(
                column, Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)
        self.tree.currentItemChanged.connect(self._on_current)
        self.route_line = RouteLineOverlay(self.tree)

        self.legend = QLabel("")
        self.legend.setTextFormat(Qt.TextFormat.RichText)
        self.legend.setToolTip("Change these with Colors…")
        self.round_trip = QLabel("")
        self.round_trip.setAlignment(Qt.AlignmentFlag.AlignRight)
        bold = QFont(self.round_trip.font())
        bold.setBold(True)
        self.round_trip.setFont(bold)

        self.graph_title = QLabel("")
        self.graph_title.setFont(bold)
        self.graph = RouteGraph()
        self.graph.setMinimumHeight(170)
        lower = QWidget()
        lower_layout = QVBoxLayout(lower)
        lower_layout.setContentsMargins(0, 4, 0, 0)
        lower_layout.setSpacing(2)
        self.graph_time = QLabel("")
        self.graph_legend = QLabel(graph_legend_html())
        self.graph_legend.setTextFormat(Qt.TextFormat.RichText)
        graph_header = QHBoxLayout()
        graph_header.addWidget(self.graph_title)
        graph_header.addSpacing(12)
        graph_header.addWidget(self.graph_time)
        graph_header.addStretch(1)
        graph_header.addWidget(self.graph_legend)
        lower_layout.addLayout(graph_header)
        lower_layout.addWidget(self.graph, 1)
        upper = QWidget()
        upper_layout = QVBoxLayout(upper)
        upper_layout.setContentsMargins(0, 0, 0, 0)
        upper_layout.setSpacing(2)
        upper_layout.addWidget(self.tree, 1)
        footer = QHBoxLayout()
        footer.addWidget(self.legend)
        footer.addStretch(1)
        footer.addWidget(self.round_trip)
        upper_layout.addLayout(footer)
        splitter = QSplitter(Qt.Orientation.Vertical)
        splitter.addWidget(upper)
        splitter.addWidget(lower)
        splitter.setStretchFactor(0, 3)
        splitter.setStretchFactor(1, 2)

        self.status = QLabel("Type a host name or IP address and press Start.")
        self.status.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        self.status.setWordWrap(True)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(10, 8, 10, 8)
        layout.addLayout(toolbar)
        layout.addWidget(splitter, 1)
        layout.addWidget(self.status)

        # The graph moves on with the clock between rounds.
        self._tick = QTimer(self)
        self._tick.setInterval(1000)
        self._tick.timeout.connect(self._refresh_graph)
        self._update_title()
        self._apply_limits()
        self._show_logging()

        try:
            days = self._settings.route_log_keep_days if self._settings is not None else KEEP_DAYS
            prune_logs(log_folder, days)
        except OSError:
            pass
        if start and target.strip():
            QTimer.singleShot(0, self.start)
        else:
            self.target.setFocus()

    # -- running -----------------------------------------------------------

    @property
    def running(self) -> bool:
        return self._thread is not None

    def toggle(self) -> None:
        if self.running:
            self.stop()
        else:
            self.start()

    def start(self) -> None:
        target = self.target.text().strip()
        if not target:
            self.status.setText("Type a host name or IP address to monitor.")
            self.target.setFocus()
            return
        self._detach_thread()
        self._warning = ""
        if target != self.session_target:
            # A new host is a new session, logged to a new file.
            self.session_target = target
            self.log.clear()
            self.names = {}
            self.ip = ""
            self.ip_label.setText("")
            self.selected_ttl = None
            self._silent_rounds = 0
            self.tree.clear()
            self.log_file = log_path(target, time.time(), self._log_folder)
        thread = RouteMonitorThread(target, self.interval.currentData(), self.log_file, self._probe)
        thread.resolved.connect(self._on_resolved)
        thread.round_ready.connect(self._on_round)
        thread.name_ready.connect(self._on_name)
        thread.failed.connect(self._on_failed)
        thread.log_failed.connect(self._on_log_failed)
        thread.finished.connect(self._on_finished)
        self._thread = thread
        self.button.setText("Stop")
        self.status.setText(f"Finding {target}…")
        self._update_title()
        self._logging_ok = self.log_file is not None
        track(thread)
        thread.start()
        self._tick.start()
        self._show_logging()

    def stop(self) -> None:
        self._detach_thread()
        self._tick.stop()
        self.button.setText("Start")
        self._show_logging()
        self._show_status()
        self.refresh()

    def _detach_thread(self) -> None:
        """Let the running round finish on its own, its results unheard."""
        thread, self._thread = self._thread, None
        if thread is None:
            return
        thread.stop()
        for signal in (thread.resolved, thread.round_ready, thread.name_ready, thread.failed,
                       thread.log_failed, thread.finished):
            signal.disconnect()
        # Qt mustn't destroy a running QThread along with this window.
        retire(thread)

    def _on_interval(self) -> None:
        if self._thread is not None:
            self._thread.interval = self.interval.currentData()

    def _on_resolved(self, ip: str) -> None:
        self.ip = ip
        self.ip_label.setText(ip if ip != self.session_target else "")
        self._show_status()

    def _on_round(self, result) -> None:
        answered = any(sample.address for sample in result.samples)
        self._silent_rounds = 0 if answered else self._silent_rounds + 1
        # A name to show at once for each new hop that has one without
        # asking anyone ("Private (10.0.0.0/8)"); lookups may better it.
        for sample in result.samples:
            if sample.address and sample.address not in self.names:
                self.names[sample.address] = whois.reserved_name(sample.address)
        self.log.add(result)
        self.export_button.setEnabled(self.log_file is not None)
        self._show_status()
        self.refresh()

    def _on_name(self, address: str, name: str) -> None:
        if name or not self.names.get(address):
            self.names[address] = name
        self.refresh()

    def _on_failed(self, message: str) -> None:
        self._warning = message
        self.status.setText(message)

    def _on_log_failed(self, message: str) -> None:
        self._logging_ok = False
        self._on_failed(message)
        self._show_logging()

    def _show_logging(self) -> None:
        """● Logging while samples go to the log file, else why not."""
        if not self.running:
            color, text = "#8a919c", "Stopped"
        elif self._logging_ok:
            color, text = LOGGING_COLOR, "Logging"
        else:
            color, text = BUBBLE_WARN, "Not logging"
        self.logging_label.setText(f"<span style='color:{color}'>●</span> {text}")
        self.logging_label.setToolTip(str(self.log_file) if self.log_file and self._logging_ok else "")

    def _on_finished(self) -> None:
        # Stopped on its own: the host couldn't be found.
        self._thread = None
        self._tick.stop()
        self.button.setText("Start")
        self._show_logging()

    def _show_status(self) -> None:
        if not self.session_target:
            return
        parts = [self._warning] if self._warning else []
        if self.log.last is None:
            parts.append(f"Tracing the route to {self.session_target}…" if self.running
                         else "Stopped.")
        elif not self.log.addresses:
            parts.append(no_answer_text(self._silent_rounds))
        elif self.log.hop_count is None:
            parts.append(f"{self.session_target} hasn't answered yet; showing the hops that did.")
        if self.log.started is not None:
            started = time.strftime("%d %b %Y %H:%M:%S", local_time(self.log.started))
            parts.append(f"Session {self.session_target} · started {started}")
        if self.log_file is not None:
            parts.append(f"Log: {self.log_file}")
        changes = len(self.log.changes)
        parts.append(f"Route changes: {changes}")
        self.status.setText("   ·   ".join(parts))

    def _update_title(self) -> None:
        name = self.session_target or self._title
        # The sidebar calls it Ping monitor; the window goes by the same name.
        self.setWindowTitle(f"Ping Monitor - {name}" if name else "Ping Monitor")

    # -- showing -----------------------------------------------------------

    def _focus_since(self, end: float) -> float | None:
        seconds = self.focus.currentData()
        return end - seconds if seconds else None

    def _hop_name(self, ttl: int, address: str) -> str:
        if ttl == self.log.hop_count and not is_address(self.session_target):
            return self.session_target
        if not address:
            return "No reply"
        return self.names.get(address, "")

    def refresh(self) -> None:
        end = self.log.last
        if end is None:
            self._refresh_graph()
            return
        since = self._focus_since(end)
        stats = self.log.stats(since)
        limited = rate_limited(stats)
        ttls = self.log.ttls()
        top = latency_scale(stats.values())
        self.latency_header.set_scale(top, self.limits.warn_ms, self.limits.crit_ms)

        while self.tree.topLevelItemCount() > len(ttls):
            self.tree.takeTopLevelItem(self.tree.topLevelItemCount() - 1)
        for row, ttl in enumerate(ttls):
            item = self.tree.topLevelItem(row)
            if item is None:
                item = QTreeWidgetItem()
                for column in NUMBER_COLUMNS:
                    item.setTextAlignment(column, Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)
                self.tree.addTopLevelItem(item)
            hop = stats[ttl]
            address = self.log.addresses.get(ttl, "")
            is_limited = ttl in limited
            item.setData(HOP, TTL_ROLE, ttl)
            item.setText(HOP, str(ttl))
            item.setData(HOP, BUBBLE_ROLE, bubble_color(hop, is_limited, self.limits))
            if hop.silent:
                pl = "100"
            elif hop.lost:
                pl = f"{hop.loss_percent:.1f}" + ("*" if is_limited else "")
            else:
                pl = ""
            item.setText(PL, pl)
            item.setForeground(PL, LOSS_COLOR if hop.lost
                               else self.palette().color(self.palette().ColorRole.PlaceholderText))
            item.setToolTip(PL, LIMITED_TIP if is_limited else "")
            item.setText(IP, address or "*")
            name = self._hop_name(ttl, address)
            item.setText(NAME, name)
            item.setToolTip(NAME, name)
            for column, value in ((AVG, hop.avg_ms), (MIN, hop.min_ms), (MAX, hop.max_ms),
                                  (JITTER, hop.jitter_ms), (CUR, hop.last_ms)):
                item.setText(column, format_ms(value))
            item.setData(LATENCY, LATENCY_ROLE, dict(
                top=top, avg=hop.avg_ms, min=hop.min_ms, max=hop.max_ms, cur=hop.last_ms,
                silent=hop.silent,
                loss=hop.loss_percent, limited=is_limited,
                warn=self.limits.warn_ms, crit=self.limits.crit_ms,
            ))
        if self.selected_ttl not in ttls and ttls:
            self.selected_ttl = ttls[-1]
        current = self.tree.currentItem()
        if ttls and (current is None or current.data(HOP, TTL_ROLE) != self.selected_ttl):
            self.tree.blockSignals(True)
            self.tree.setCurrentItem(self.tree.topLevelItem(ttls.index(self.selected_ttl)))
            self.tree.blockSignals(False)
        self._mark_graphed()
        self._fit_columns()
        self.tree.viewport().update()
        self.route_line.update()

        target = stats.get(self.log.hop_count) if self.log.hop_count else None
        if target is not None:
            self.round_trip.setText(f"Round trip (ms)   avg {format_ms(target.avg_ms) or '-'}"
                                    f"   cur {format_ms(target.last_ms) or 'lost'}"
                                    f"   loss {target.loss_percent:.1f}%")
            count = target.sent
        else:
            self.round_trip.setText("")
            count = max((s.sent for s in stats.values()), default=0)
        first = max(self.log.first or end, since or 0)
        self.meta.setText(f"{count} samples, {_clock(first)} – {_clock(end)}")
        self._refresh_graph()

    def _fit_columns(self) -> None:
        """Size the columns before Latency to what they hold, once each time
        a hop or a name comes in, so the latency graph gets the rest."""
        shape = (self.tree.topLevelItemCount(), hash(frozenset(self.names.items())))
        if shape == self._fitted_shape:
            return
        self._fitted_shape = shape
        for column in range(LATENCY):
            self.tree.resizeColumnToContents(column)
            width = self.tree.columnWidth(column) + COLUMN_PADDING
            if column == NAME:
                # Room for the "● graphed" tag; very long names are elided.
                width = min(NAME_MAX_WIDTH, width + GRAPHED_TAG_WIDTH)
            self.tree.setColumnWidth(column, width)

    def _refresh_graph(self) -> None:
        ttl = self.selected_ttl
        end = time.time() if self.running else (self.log.last or time.time())
        seconds = self.focus.currentData() or max(60, int(end - (self.log.first or end)) + 1)
        self.graph.span_seconds = seconds
        self.graph.first_seen = self.log.first
        self.graph_time.setText(f"Graph time {span_text(seconds)}")
        if ttl is None:
            self.graph_title.setText("")
            if self.log.last is not None and not self.log.addresses:
                self.graph.empty_text = no_answer_text(self._silent_rounds)
            elif self.running:
                self.graph.empty_text = "Waiting for the first answer…"
            else:
                self.graph.empty_text = ""
            self.graph.changes = []
            self.graph.set_samples([], end)
            return
        address = self.log.addresses.get(ttl, "")
        name = self._hop_name(ttl, address)
        label = f"{name} ({address})" if name and address and name != address else (address or name)
        self.graph_title.setText(f"Hop {ttl}: {label}")
        # A change at or before this hop moves this hop's route.
        self.graph.changes = [c for c in self.log.changes if c.ttl <= ttl]
        self.graph.set_samples(self.log.samples(ttl, end - seconds - 60), end)

    def _on_current(self, item: QTreeWidgetItem | None, _previous) -> None:
        if item is not None:
            self.selected_ttl = item.data(HOP, TTL_ROLE)
            self._mark_graphed()
            self._refresh_graph()

    def _mark_graphed(self) -> None:
        for row in range(self.tree.topLevelItemCount()):
            item = self.tree.topLevelItem(row)
            item.setData(NAME, GRAPHED_ROLE, item.data(HOP, TTL_ROLE) == self.selected_ttl)

    # -- colours -----------------------------------------------------------

    def edit_colors(self) -> None:
        dialog = ThresholdsDialog(self.limits, self)
        if dialog.exec() == QDialog.DialogCode.Accepted:
            self.set_limits(dialog.thresholds())

    def set_limits(self, limits: Thresholds) -> None:
        self.limits = limits
        if self._settings is not None:
            limits.store(self._settings)
            self._settings.sanitised()
            self._settings.save()
        self._apply_limits()
        self.refresh()

    def _apply_limits(self) -> None:
        self.legend.setText(legend_html(self.limits))
        self.graph.warn_ms = self.limits.warn_ms
        self.graph.bad_ms = self.limits.crit_ms
        self.graph.update()

    # -- export ------------------------------------------------------------

    def export(self) -> None:
        if self.log_file is None or not self.log_file.exists():
            self.status.setText("Nothing logged yet to export.")
            return
        suggested = str(Path.home() / f"{self.log_file.stem}.csv")
        path, _ = QFileDialog.getSaveFileName(self, "Export Route Log", suggested, "CSV (*.csv)")
        if not path:
            return
        try:
            count = export_csv(self.log_file, Path(path), self.names)
        except Exception as error:  # noqa: BLE001 - shown to the user
            self.status.setText(f"Couldn't export: {error}")
            return
        self.status.setText(f"Exported {count} samples to {path}")

    def closeEvent(self, event) -> None:
        self._detach_thread()
        self._tick.stop()
        super().closeEvent(event)


def no_answer_text(rounds: int) -> str:
    """What to say when not even the first router answers."""
    return (f"No hop has answered in {rounds} round{'s' if rounds != 1 else ''}: check the "
            "network connection, or whether a VPN or firewall is blocking ping (ICMP).")


def span_text(seconds: float) -> str:
    """600 -> "10 minutes", 3600 -> "1 hour"."""
    seconds = int(seconds)
    if seconds % 3600 == 0:
        hours = seconds // 3600
        return f"{hours} hour{'s' if hours != 1 else ''}"
    if seconds >= 3600:
        return f"{seconds / 3600:.1f} hours"
    if seconds % 60 == 0:
        minutes = seconds // 60
        return f"{minutes} minute{'s' if minutes != 1 else ''}"
    return f"{seconds} seconds"


def graph_legend_html() -> str:
    """What the marks on the graph mean."""
    gap = "&nbsp;&nbsp;&nbsp;"
    return (f"<b>━</b> Latency{gap}"
            f"<span style='color:{GRAPH_LOSS_LINE.name()}'>▮</span> Lost ping{gap}"
            f"<span style='color:{GRAPH_LOSS_LINE.name()}'>━</span> Loss % (right axis){gap}"
            f"<span style='color:{ROUTE_CHANGE_COLOR.name()}'>┆</span> Route changed")


def _clock(stamp: float) -> str:
    return time.strftime("%H:%M:%S", local_time(stamp))
