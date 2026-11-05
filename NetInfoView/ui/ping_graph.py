"""A PingPlotter-style latency graph, opened by double-clicking a host.

Every host graphed while the window is open gets its own panel, stacked one
under another on the same clock, so their latency can be compared over the
same stretch of time. Each panel has a jitter strip above the latency graph,
whose right-hand axis carries the packet-loss percentage. A scroll bar along
the bottom moves every panel back through the kept history together.
"""

from __future__ import annotations

import statistics
import time
from collections.abc import Callable

from PyQt6.QtCore import QEvent, QObject, QPointF, QRectF, Qt, QTimer
from PyQt6.QtGui import QColor, QFont, QPainter, QPainterPath, QPen
from PyQt6.QtWidgets import (
    QComboBox,
    QFrame,
    QHBoxLayout,
    QLabel,
    QScrollArea,
    QScrollBar,
    QToolButton,
    QToolTip,
    QVBoxLayout,
    QWidget,
)

from ..model.samples import Sample, SampleStore, nice_ceiling, summarize

#: (label, seconds) choices for the visible time span.
TIME_RANGES = (
    ("1 minute", 60),
    ("5 minutes", 300),
    ("10 minutes", 600),
    ("30 minutes", 1800),
    ("60 minutes", 3600),
)
DEFAULT_TIME_RANGE = 600

#: Background bands, as in PingPlotter: green while latency is fine, amber
#: once it gets sluggish, red when it's bad.
WARN_MS = 100.0
BAD_MS = 200.0
GOOD_COLOR = QColor("#d6e6cf")
WARN_COLOR = QColor("#f6e3c3")
BAD_COLOR = QColor("#f2cccc")
#: Time before the first ping of the visible span: nothing to show yet.
NO_DATA_COLOR = QColor("#c5cbc0")
GRID_COLOR = QColor(0, 0, 0, 30)
LINE_COLOR = QColor("#111111")
LOSS_COLOR = QColor("#e8231d")
JITTER_COLOR = QColor("#8b1a1a")
JITTER_SCALE_COLOR = QColor("#e07020")

#: Top of the packet-loss axis, in percent, and how many recent pings each
#: point of the loss line is averaged over.
PL_MAX = 30
PL_WINDOW = 10
#: How many recent pings each point of the jitter line is averaged over.
JITTER_WINDOW = 10

REFRESH_MS = 1000
#: How far before the span to look for the ping that carries the line in.
LEAD_IN_SECONDS = 60

#: Plot margins: the latency axis on the left, packet loss on the right,
#: time labels below.
MARGIN_LEFT = 52
MARGIN_RIGHT = 34
MARGIN_TOP = 6
MARGIN_BOTTOM = 22

#: A panel's height while there's room; with many hosts they shrink so that
#: all of them fit the window, down to PANEL_MIN_HEIGHT before it scrolls.
PANEL_HEIGHT = 250
PANEL_MIN_HEIGHT = 44
#: Below this a panel drops its jitter strip to leave room for latency.
COMPACT_BELOW = 190
#: Below this panels leave time labels to one strip under them all, and the
#: ms axis shows just 0 and the top.
TINY_BELOW = 110


def rolling_loss_percent(samples: list[Sample], window: int = PL_WINDOW) -> list[float]:
    """Loss % over the last `window` pings, at each sample."""
    out = []
    lost = 0
    for i, sample in enumerate(samples):
        lost += sample.rtt_ms is None
        if i >= window:
            lost -= samples[i - window].rtt_ms is None
        # Always over the full window, so the first ping or two lost can't
        # read as 50-100% loss.
        out.append(lost / window * 100.0)
    return out


def rolling_jitter(samples: list[Sample], window: int = JITTER_WINDOW) -> list[tuple[float, float]]:
    """(timestamp, jitter ms) per reply: the mean change in latency between
    consecutive replies over the last `window` of them."""
    out = []
    diffs: list[float] = []
    previous: float | None = None
    for sample in samples:
        if sample.rtt_ms is None:
            continue
        if previous is not None:
            diffs.append(abs(sample.rtt_ms - previous))
            recent = diffs[-window:]
            out.append((sample.timestamp, sum(recent) / len(recent)))
        previous = sample.rtt_ms
    return out


class _TimeAxisWidget(QWidget):
    """Shared time-to-x mapping for the strips of one host panel."""

    margin_bottom = MARGIN_BOTTOM

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.margin_bottom = type(self).margin_bottom
        self.span_seconds = DEFAULT_TIME_RANGE
        self._samples: list[Sample] = []
        self._end = time.time()
        #: When this host was first pinged (as far as the kept history goes):
        #: only the time before it is greyed out as having no data.
        self.first_seen: float | None = None

    def set_samples(self, samples: list[Sample], end: float) -> None:
        self._samples = samples
        self._end = end
        self.update()

    def _plot_rect(self) -> QRectF:
        return QRectF(
            MARGIN_LEFT,
            MARGIN_TOP,
            max(1, self.width() - MARGIN_LEFT - MARGIN_RIGHT),
            max(1, self.height() - MARGIN_TOP - self.margin_bottom),
        )

    def _start(self) -> float:
        return self._end - self.span_seconds

    def _x_for(self, timestamp: float, plot: QRectF) -> float:
        return plot.left() + (timestamp - self._start()) / self.span_seconds * plot.width()

    def _small_font(self) -> QFont:
        small = QFont(self.font())
        small.setPointSizeF(max(7.0, small.pointSizeF() - 2))
        return small

    def _paint_time_axis(self, painter: QPainter, plot: QRectF) -> None:
        # A label roughly every 120 px, snapped to a whole-minute/second step.
        wanted = max(2, int(plot.width() // 120))
        raw = self.span_seconds / wanted
        step = next(
            (s for s in (5, 10, 15, 30, 60, 120, 300, 600, 900, 1800) if s >= raw), 3600
        )
        fmt = "%H:%M:%S" if step < 60 else "%H:%M"
        first = (int(self._start()) // step + 1) * step
        for stamp in range(first, int(self._end) + 1, step):
            x = self._x_for(stamp, plot)
            painter.setPen(QPen(GRID_COLOR, 1))
            painter.drawLine(QPointF(x, plot.bottom() - 4), QPointF(x, plot.bottom() + 3))
            if self.margin_bottom < MARGIN_BOTTOM:
                continue  # time labels hidden: ticks only
            painter.setPen(self.palette().color(self.foregroundRole()))
            painter.drawText(
                QRectF(x - 40, plot.bottom() + 3, 80, MARGIN_BOTTOM - 3),
                Qt.AlignmentFlag.AlignHCenter | Qt.AlignmentFlag.AlignTop,
                time.strftime(fmt, time.localtime(stamp)),
            )

    def _draw_rotated(self, painter: QPainter, center: QPointF, text: str) -> None:
        painter.save()
        painter.translate(center)
        painter.rotate(90 if center.x() > self.width() / 2 else -90)
        painter.drawText(QRectF(-40, -8, 80, 16), Qt.AlignmentFlag.AlignCenter, text)
        painter.restore()


class TimeAxisStrip(_TimeAxisWidget):
    """Time labels alone, shared below a crowded window's panels so each panel
    doesn't spend its own height on them."""

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setFixedHeight(MARGIN_BOTTOM)

    def paintEvent(self, event) -> None:
        painter = QPainter(self)
        painter.setFont(self._small_font())
        plot = QRectF(MARGIN_LEFT, 0, max(1, self.width() - MARGIN_LEFT - MARGIN_RIGHT), 0)
        self._paint_time_axis(painter, plot)
        painter.end()


class JitterWidget(_TimeAxisWidget):
    """A thin strip above the latency graph tracing jitter over time."""

    margin_bottom = 4

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setFixedHeight(46)

    def paintEvent(self, event) -> None:
        painter = QPainter(self)
        plot = self._plot_rect()
        painter.fillRect(plot, QColor("#ffffff"))
        points = [(t, j) for t, j in rolling_jitter(self._samples) if t >= self._start()]
        scale = nice_ceiling(max((j for _, j in points), default=0.0))
        # The scale line sits about a third down, leaving headroom for spikes.
        top = scale * 1.5

        def y_for(ms: float) -> float:
            return plot.bottom() - min(ms, top) / top * plot.height()

        painter.setFont(self._small_font())
        y_scale = y_for(scale)
        painter.setPen(QPen(QColor(0, 0, 0, 140), 1, Qt.PenStyle.DashLine))
        painter.drawLine(QPointF(plot.left(), y_scale), QPointF(plot.right(), y_scale))
        painter.setPen(JITTER_SCALE_COLOR)
        painter.drawText(
            QRectF(0, y_scale - 8, MARGIN_LEFT - 6, 16),
            Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter,
            f"{scale:g}",
        )
        painter.setPen(JITTER_COLOR)
        painter.drawText(
            QRectF(plot.left(), y_scale - 8, plot.width(), 16),
            Qt.AlignmentFlag.AlignCenter,
            "Jitter (ms)",
        )

        if points:
            path = QPainterPath()
            for i, (stamp, jitter) in enumerate(points):
                point = QPointF(self._x_for(stamp, plot), y_for(jitter))
                path.moveTo(point) if i == 0 else path.lineTo(point)
            painter.setRenderHint(QPainter.RenderHint.Antialiasing)
            painter.setPen(QPen(JITTER_COLOR, 1.2))
            painter.setClipRect(plot)
            painter.drawPath(path)
            painter.setClipping(False)

        painter.setPen(QPen(QColor("#888888"), 1))
        painter.setBrush(Qt.BrushStyle.NoBrush)
        painter.drawRect(plot)
        painter.end()


class PingGraphWidget(_TimeAxisWidget):
    """Draws latency as a step line with lost pings as red vertical bars,
    and the recent packet-loss percentage as a red line on the right axis."""

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setMinimumSize(420, 16)
        self.setMouseTracking(True)
        self._hover_x: float | None = None
        #: Where the amber and red bands start, in ms.
        self.warn_ms = WARN_MS
        self.bad_ms = BAD_MS
        #: (fine, warning, bad) band colours.
        self.band_colors = (GOOD_COLOR, WARN_COLOR, BAD_COLOR)
        #: The other colours, so a window can restyle its graph.
        self.line_color = LINE_COLOR
        self.line_width = 1.4
        self.loss_color = LOSS_COLOR
        self.loss_line_color = LOSS_COLOR.darker(130)
        self.grid_color = GRID_COLOR
        self.frame_color = QColor("#888888")
        #: Greys out the time before the first ping; None leaves the bands.
        self.no_data_color: QColor | None = NO_DATA_COLOR

    # -- geometry ------------------------------------------------------------

    def _y_for(self, ms: float, top_ms: float, plot: QRectF) -> float:
        return plot.bottom() - min(ms, top_ms) / top_ms * plot.height()

    def _top_ms(self) -> float:
        rtts = [s.rtt_ms for s in self._samples if s.rtt_ms is not None]
        return nice_ceiling(max(rtts) * 1.1) if rtts else 10.0

    def _expected_gap(self) -> float:
        """The usual spacing between pings, so a pause in pinging shows as a
        break in the line rather than one long flat step."""
        stamps = [s.timestamp for s in self._samples]
        if len(stamps) < 2:
            return 1.0
        return statistics.median(b - a for a, b in zip(stamps, stamps[1:]))

    # -- painting --------------------------------------------------------------

    def paintEvent(self, event) -> None:
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing, False)
        plot = self._plot_rect()
        top_ms = self._top_ms()

        self._paint_bands(painter, plot, top_ms)
        self._paint_grid(painter, plot, top_ms)
        self._paint_time_axis(painter, plot)
        self._paint_losses(painter, plot)
        self._paint_line(painter, plot, top_ms)
        self._paint_loss_percent(painter, plot)
        self._paint_hover(painter, plot, top_ms)

        painter.setPen(QPen(self.frame_color, 1))
        painter.setBrush(Qt.BrushStyle.NoBrush)
        painter.drawRect(plot)
        painter.end()

    def _paint_bands(self, painter: QPainter, plot: QRectF, top_ms: float) -> None:
        good, warn, bad = self.band_colors
        painter.fillRect(plot, good)
        for low, high, color in ((self.warn_ms, self.bad_ms, warn),
                                 (self.bad_ms, top_ms, bad)):
            if top_ms <= low:
                continue
            y_low = self._y_for(low, top_ms, plot)
            y_high = self._y_for(min(high, top_ms), top_ms, plot)
            painter.fillRect(QRectF(plot.left(), y_high, plot.width(), y_low - y_high), color)
        # Grey out the part of the span before this host's first ping.
        if self.no_data_color is None:
            return
        first = self.first_seen if self.first_seen is not None else self._end
        x_first = min(plot.right(), self._x_for(first, plot))
        if x_first > plot.left():
            painter.fillRect(
                QRectF(plot.left(), plot.top(), x_first - plot.left(), plot.height()),
                self.no_data_color,
            )

    def _paint_grid(self, painter: QPainter, plot: QRectF, top_ms: float) -> None:
        painter.setFont(self._small_font())
        # Whole-number ticks where the top allows (250 -> 50s, not 62.5s).
        if plot.height() < 50:
            steps = 1  # too short for more than 0 and the top
        else:
            steps = next((n for n in (4, 5, 3, 2) if (top_ms / n).is_integer()), 4)
        for i in range(steps + 1):
            ms = top_ms * i / steps
            y = self._y_for(ms, top_ms, plot)
            if 0 < i < steps:
                painter.setPen(QPen(self.grid_color, 1, Qt.PenStyle.DashLine))
                painter.drawLine(QPointF(plot.left(), y), QPointF(plot.right(), y))
            painter.setPen(self.palette().color(self.foregroundRole()))
            painter.drawText(
                QRectF(14, y - 8, MARGIN_LEFT - 20, 16),
                Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter,
                f"{ms:g}",
            )
        self._draw_rotated(painter, QPointF(8, plot.center().y()), "ms")
        painter.setPen(self.loss_color)
        painter.drawText(
            QRectF(plot.right() + 3, plot.top() - 2, MARGIN_RIGHT - 3, 16),
            Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignTop,
            f"{PL_MAX}",
        )
        if plot.height() >= 50:
            self._draw_rotated(painter, QPointF(plot.right() + 14, plot.center().y()), "PL%")

    def _sample_width(self, plot: QRectF) -> float:
        return plot.width() * self._expected_gap() / self.span_seconds

    def _paint_losses(self, painter: QPainter, plot: QRectF) -> None:
        width = max(3.0, min(6.0, self._sample_width(plot)))
        for sample in self._samples:
            if sample.rtt_ms is not None:
                continue
            x = self._x_for(sample.timestamp, plot)
            if plot.left() <= x <= plot.right():
                painter.fillRect(
                    QRectF(x - width / 2, plot.top(), width, plot.height()), self.loss_color
                )

    def _paint_line(self, painter: QPainter, plot: QRectF, top_ms: float) -> None:
        gap_limit = self._expected_gap() * 3
        step = self._sample_width(plot)
        path = QPainterPath()
        pen_down = False
        previous: Sample | None = None
        for sample in self._samples:
            if sample.rtt_ms is None:
                pen_down = False
                previous = None
                continue
            x = max(plot.left(), self._x_for(sample.timestamp, plot))
            y = self._y_for(sample.rtt_ms, top_ms, plot)
            broken = previous is not None and sample.timestamp - previous.timestamp > gap_limit
            if not pen_down or broken:
                path.moveTo(x, y)
            else:
                path.lineTo(x, path.currentPosition().y())
                path.lineTo(x, y)
            # Hold the level until the next ping lands.
            path.lineTo(min(plot.right(), x + step), y)
            pen_down = True
            previous = sample
        painter.setPen(QPen(self.line_color, self.line_width))
        painter.setBrush(Qt.BrushStyle.NoBrush)
        painter.setClipRect(plot)
        painter.drawPath(path)
        painter.setClipping(False)

    def _paint_loss_percent(self, painter: QPainter, plot: QRectF) -> None:
        losses = rolling_loss_percent(self._samples)
        if not any(losses):
            return
        path = QPainterPath()
        for i, (sample, percent) in enumerate(zip(self._samples, losses)):
            x = self._x_for(sample.timestamp, plot)
            y = self._y_for(percent, PL_MAX, plot)
            if i == 0:
                path.moveTo(x, y)
            else:
                # Steps, like the latency line: the level changes at a ping.
                path.lineTo(x, path.currentPosition().y())
                path.lineTo(x, y)
        painter.setPen(QPen(self.loss_line_color, 1.2))
        painter.setBrush(Qt.BrushStyle.NoBrush)
        painter.setClipRect(plot)
        painter.drawPath(path)
        painter.setClipping(False)

    def _nearest_sample(self, x: float, plot: QRectF) -> Sample | None:
        if not self._samples:
            return None
        nearest = min(self._samples, key=lambda s: abs(self._x_for(s.timestamp, plot) - x))
        if abs(self._x_for(nearest.timestamp, plot) - x) > max(8.0, self._sample_width(plot)):
            return None
        return nearest

    def _paint_hover(self, painter: QPainter, plot: QRectF, top_ms: float) -> None:
        if self._hover_x is None:
            return
        sample = self._nearest_sample(self._hover_x, plot)
        if sample is None:
            return
        x = self._x_for(sample.timestamp, plot)
        painter.setPen(QPen(QColor(0, 0, 0, 120), 1, Qt.PenStyle.DashLine))
        painter.drawLine(QPointF(x, plot.top()), QPointF(x, plot.bottom()))
        if sample.rtt_ms is not None:
            y = self._y_for(sample.rtt_ms, top_ms, plot)
            painter.setBrush(self.line_color)
            painter.drawEllipse(QPointF(x, y), 3, 3)

    # -- hover -------------------------------------------------------------------

    def mouseMoveEvent(self, event) -> None:
        plot = self._plot_rect()
        pos = event.position()
        self._hover_x = pos.x() if plot.contains(pos) else None
        sample = None if self._hover_x is None else self._nearest_sample(pos.x(), plot)
        if sample is None:
            QToolTip.hideText()
        else:
            when = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(sample.timestamp))
            value = "Lost" if sample.rtt_ms is None else f"{sample.rtt_ms:.1f} ms"
            QToolTip.showText(event.globalPosition().toPoint(), f"{when}\n{value}", self)
        self.update()

    def leaveEvent(self, event) -> None:
        self._hover_x = None
        QToolTip.hideText()
        self.update()


class HostGraphPanel(QFrame):
    """One host's strip in the graph window: header, jitter, latency."""

    def __init__(
        self, key: int, on_remove: Callable[[HostGraphPanel], None], parent=None
    ) -> None:
        super().__init__(parent)
        self.key = key
        self.setFrameShape(QFrame.Shape.NoFrame)

        self._title = QLabel()
        bold = QFont(self._title.font())
        bold.setBold(True)
        self._title.setFont(bold)
        self._stats = QLabel()
        self._stats.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self._remove = remove = QToolButton()
        remove.setText("✕")
        remove.setToolTip("Remove this host from the graph")
        remove.setAutoRaise(True)
        remove.clicked.connect(lambda: on_remove(self))

        header = QHBoxLayout()
        header.setContentsMargins(4, 0, 4, 0)
        header.addWidget(self._title)
        header.addStretch(1)
        header.addWidget(self._stats)
        header.addStretch(1)
        header.addWidget(remove)

        self.jitter = JitterWidget()
        self.graph = PingGraphWidget()
        self._layout = layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 4, 0, 4)
        layout.setSpacing(2)
        layout.addLayout(header)
        layout.addWidget(self.jitter)
        layout.addWidget(self.graph, 1)

    def fit(self, height: int) -> None:
        """Size the panel, trimming what a short one has no room for. Every
        panel is trimmed alike so their graphs stay the same size."""
        self.setFixedHeight(height)
        tiny = height < TINY_BELOW
        self.jitter.setVisible(height >= COMPACT_BELOW)
        self._remove.setFixedHeight(18 if tiny else self._remove.sizeHint().height())
        self.graph.margin_bottom = 4 if tiny else MARGIN_BOTTOM
        margin = 1 if tiny else 4
        self._layout.setContentsMargins(0, margin, 0, margin)
        self._layout.setSpacing(0 if tiny else 2)
        self.graph.update()

    def refresh(
        self,
        label: str,
        samples_since: Callable[[float], list[Sample]],
        end: float,
        span: int,
        first_seen: float | None = None,
    ) -> None:
        """Show the `span` seconds up to `end` (now, or a moment scrolled
        back to)."""
        self._title.setText(label)
        # A ping still in flight when Stop was pressed may land a moment
        # later; leave it out so the frozen graph and its stats agree.
        start = end - span
        recent = [s for s in samples_since(start - LEAD_IN_SECONDS) if s.timestamp <= end]
        samples = [s for s in recent if s.timestamp >= start]
        stats = summarize(samples)
        if stats.sent:
            self._stats.setText(
                f"Min {_ms(stats.min_ms)} · Avg {_ms(stats.avg_ms)} · Max {_ms(stats.max_ms)} ms"
                f"   |   Lost {stats.lost}/{stats.sent} ({stats.loss_percent:.1f}%)"
            )
        else:
            self._stats.setText("No pings yet")
        # The last ping before the span carries the line in from the left
        # edge rather than leaving a gap until the first ping inside it.
        before = [s for s in recent if s.timestamp < start]
        drawn = before[-1:] + samples
        for strip in (self.jitter, self.graph):
            strip.span_seconds = span
            strip.first_seen = first_seen
            strip.set_samples(drawn, end)


class PingGraphWindow(QWidget):
    """A live, non-modal window stacking a HostGraphPanel per host."""

    def __init__(
        self,
        keys: int | list[int],
        store: SampleStore,
        describe: Callable[[int], tuple[str, str] | None],
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent, Qt.WindowType.Window)
        self.setAttribute(Qt.WidgetAttribute.WA_DeleteOnClose)
        self._store = store
        #: key -> (display name, IP), or None once the host has been removed.
        self._describe = describe
        self.panels: list[HostGraphPanel] = []

        self._column = QVBoxLayout()
        self._column.setContentsMargins(0, 0, 0, 0)
        self._column.setSpacing(0)
        self._column.addStretch(1)
        self._body = QWidget()
        self._body.setLayout(self._column)
        # Panel heights are set by hand in _fit_panels, never squeezed by the
        # layout, so a crowded window scrolls instead of overlapping them.
        self._scroll = scroll = QScrollArea()
        scroll.setWidgetResizable(False)
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        scroll.setFrameShape(QFrame.Shape.NoFrame)
        scroll.setWidget(self._body)
        #: Moves every panel back in time together: its value is where the
        #: graphs end, in seconds after the earliest moment it can show, so
        #: the right-hand end is now and dragging left goes back. (Inverted
        #: appearance would be simpler but the macOS style ignores it.)
        self.history_bar = QScrollBar(Qt.Orientation.Horizontal)
        self.history_bar.setToolTip("Scroll back through the ping history")
        self.history_bar.valueChanged.connect(self._on_history_scrolled)
        #: Where the graphs end while scrolled back (None: following now).
        self._view_end: float | None = None
        #: The end time the history bar's value 0 stands for.
        self._earliest_end = 0.0

        #: One time span for every panel, picked once at the top.
        self._span_label = QLabel()
        self.range_combo = QComboBox()
        for label, seconds in TIME_RANGES:
            self.range_combo.addItem(label, seconds)
        self.range_combo.setCurrentIndex(
            next(i for i, (_, s) in enumerate(TIME_RANGES) if s == DEFAULT_TIME_RANGE)
        )
        self.range_combo.currentIndexChanged.connect(self.refresh)
        header = QHBoxLayout()
        header.addStretch(1)
        header.addWidget(self._span_label)
        header.addWidget(self.range_combo)
        #: Time labels under all the panels once they're too short for their own.
        self.time_axis = TimeAxisStrip()
        self.time_axis.hide()

        layout = QVBoxLayout(self)
        layout.setContentsMargins(8, 4, 8, 4)
        layout.setSpacing(2)
        layout.addLayout(header)
        layout.addWidget(scroll)
        layout.addWidget(self.time_axis, 0, Qt.AlignmentFlag.AlignLeft)
        layout.addWidget(self.history_bar)
        self.resize(1000, PANEL_HEIGHT + 80)

        #: Set while pinging is stopped: the graph holds still at that moment
        #: instead of scrolling on into empty time.
        self._frozen_at: float | None = None
        self._timer = QTimer(self)
        self._timer.timeout.connect(self.refresh)
        self._timer.start(REFRESH_MS)
        self.add_hosts([keys] if isinstance(keys, int) else keys)

    @property
    def keys(self) -> list[int]:
        return [panel.key for panel in self.panels]

    @property
    def graph(self) -> PingGraphWidget:
        """The first host's latency graph."""
        return self.panels[0].graph

    def add_hosts(self, keys: list[int]) -> None:
        """Stack a panel for each host not already shown, below the others."""
        for key in keys:
            if key in self.keys:
                continue
            panel = HostGraphPanel(key, self._remove_panel)
            for strip in (panel.jitter, panel.graph):
                strip.installEventFilter(self)
            self._column.insertWidget(len(self.panels), panel)
            self.panels.append(panel)
        wanted = min(900, len(self.panels) * PANEL_HEIGHT + 80)
        if self.height() < wanted:
            self.resize(self.width(), wanted)
        self._fit_panels()
        self.refresh()

    def _fit_panels(self) -> None:
        """Share the window's height between the panels: full size while they
        fit, ever smaller as hosts are added so they all stay on one page."""
        count = max(1, len(self.panels))
        # The shared time axis takes its room before the panels share the rest.
        tiny = self._scroll.height() + (
            self.time_axis.height() if self.time_axis.isVisible() else 0
        ) < TINY_BELOW * count
        if self.time_axis.isHidden() == tiny:
            self.time_axis.setVisible(tiny)
            self.layout().activate()
        viewport = self._scroll.viewport()
        height = max(PANEL_MIN_HEIGHT, min(PANEL_HEIGHT, viewport.height() // count))
        for panel in self.panels:
            panel.fit(height)
        width = viewport.width()
        if height * count > viewport.height():
            width -= self._scroll.verticalScrollBar().sizeHint().width()
        self._body.resize(width, max(viewport.height(), height * count))
        # Line the shared labels up with the graphs above (scroll bar aside).
        self.time_axis.setFixedWidth(width)

    def resizeEvent(self, event) -> None:
        super().resizeEvent(event)
        self._fit_panels()

    def showEvent(self, event) -> None:
        super().showEvent(event)
        self._fit_panels()

    def _remove_panel(self, panel: HostGraphPanel) -> None:
        self.panels.remove(panel)
        panel.deleteLater()
        if self.panels:
            self._fit_panels()
            self.refresh()
        else:
            self.close()

    def _span(self) -> int:
        return self.range_combo.currentData() or DEFAULT_TIME_RANGE

    def _now(self) -> float:
        return self._frozen_at if self._frozen_at is not None else time.time()

    def _on_history_scrolled(self, value: int) -> None:
        live = value >= self.history_bar.maximum()
        self._view_end = None if live else self._earliest_end + value
        self.refresh()

    def eventFilter(self, watched: QObject, event: QEvent) -> bool:
        """A sideways swipe, or Shift+wheel, over a graph scrolls the history."""
        if event.type() == QEvent.Type.Wheel:
            delta = event.angleDelta()
            steps = delta.x() or (
                delta.y() if event.modifiers() & Qt.KeyboardModifier.ShiftModifier else 0
            )
            if steps:
                bar = self.history_bar
                # Wheel/swipe right moves towards now, left goes back.
                bar.setValue(bar.value() + round(steps / 120 * bar.singleStep()))
                return True
        return super().eventFilter(watched, event)

    def _update_history_bar(self, now: float, end: float) -> None:
        oldest = min(
            (t for t in (self._store.oldest(k) for k in self.keys) if t is not None),
            default=now,
        )
        span = self._span()
        self._earliest_end = oldest + span
        bar = self.history_bar
        bar.blockSignals(True)
        bar.setRange(0, max(0, int(now - self._earliest_end)))
        bar.setPageStep(span)
        bar.setSingleStep(max(1, span // 10))
        bar.setValue(bar.maximum() - int(now - end))
        bar.blockSignals(False)

    def freeze(self, at: float | None) -> None:
        """Hold the graph still at `at`, or let it scroll live again with None."""
        self._frozen_at = at
        if at is None:
            self._timer.start(REFRESH_MS)
        else:
            self._timer.stop()
        self.refresh()

    @property
    def frozen(self) -> bool:
        return self._frozen_at is not None

    def refresh(self) -> None:
        # Removed hosts drop out; the window goes with the last of them.
        gone = [p for p in self.panels if self._describe(p.key) is None]
        for panel in gone:
            self.panels.remove(panel)
            panel.deleteLater()
        if not self.panels:
            self.close()
            return
        if gone:
            self._fit_panels()

        # One clock for every panel, so they line up for comparison. Scrolled
        # back, the view stays put on that moment while pinging carries on.
        now = self._now()
        end = now if self._view_end is None else min(self._view_end, now)
        self._update_history_bar(now, end)
        span = self._span()
        self._span_label.setText(f"({_clock(end - span)} - {_clock(end)})")
        self.time_axis.span_seconds = span
        self.time_axis.set_samples([], end)
        labels = []
        for panel in self.panels:
            name, ip = self._describe(panel.key)
            label = f"{name} ({ip})" if ip and ip != name else name
            labels.append(label)
            panel.refresh(
                label,
                lambda since, k=panel.key: self._store.samples(k, since=since),
                end,
                span,
                self._store.oldest(panel.key),
            )
        shown = ", ".join(labels) if len(labels) <= 3 else f"{len(labels)} hosts"
        self.setWindowTitle(f"Ping Graph - {shown}")


def _ms(value: float | None) -> str:
    return "-" if value is None else f"{value:.0f}"


def _clock(stamp: float) -> str:
    return time.strftime("%H:%M:%S", time.localtime(stamp))
