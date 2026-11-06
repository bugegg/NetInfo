"""The main window's layout: a sidebar, the network overview (summary,
search and filters, device grid) and an inspector for the selected device.

It only arranges and restyles what MainWindow already owns (its actions,
models, table and history view), so every feature keeps working as before.
"""
from __future__ import annotations

import html
import socket
import time
from datetime import datetime

from PyQt6.QtCore import QEvent, QPointF, QRectF, QSize, QSysInfo, Qt, QTimer
from PyQt6.QtGui import (
    QAction, QColor, QFont, QFontInfo, QPainter, QPainterPath, QPen,
)
from PyQt6.QtWidgets import (
    QComboBox, QFrame, QGridLayout, QHBoxLayout, QLabel, QLineEdit, QMenu, QPushButton,
    QScrollArea, QSizePolicy, QSplitter, QStyle, QStyledItemDelegate, QStyleOptionViewItem, QTabWidget,
    QToolButton, QVBoxLayout, QWidget,
)

from .. import __version__
from ..model.columns import COLUMNS
from ..model.samples import nice_ceiling
from ..ping.port_scan import STATIC_PORTS, STATIC_UDP_PORTS
from ..settings import DisplayMode
from . import fonts, glyphs

BLUE = "#087dff"
GREEN = "#16a34a"
RED = "#e5383b"

#: The device grid's default columns, in order, with shorter headers and
#: starting widths. Hostname (width None) takes whatever room is left; in a
#: window too narrow for them all, the grid scrolls sideways.
GRID_COLUMNS = {
    "last_status": ("Status", 96),
    "ip_address": ("IP address", 128),
    "hostname": ("Hostname", None),
    "dns_name": ("DNS Name", 170),
    "mac_address": ("MAC address", 158),
    "vendor": ("Vendor", 180),
    "mtu": ("MTU", 56),
    "total_sent": ("Total", 64),
    "succeed_count": ("Succeed", 76),
    "failed_count": ("Failed", 64),
    "last_rtt": ("Latency", 76),
    "last_failed_on": ("Last Failed On", 150),
}
STRETCH_COLUMN = "hostname"
#: Columns the grid never shows nor offers in its Columns menu. "Host Name"
#: (what the user typed when adding the host) read as a duplicate of
#: "Hostname" (the name found by DNS/NetBIOS/mDNS) and of "IP address".
EXCLUDED_COLUMNS = {"host_name"}
#: Shorter titles for optional columns, in the grid and its Columns menu.
RENAMED_COLUMNS = {"succeed_count": "Succeed", "failed_count": "Failed"}
#: Hostname never gets narrower than this when it fills the spare width.
STRETCH_MIN_WIDTH = 180
#: History view columns: time, host, IP, status, latency, TTL.
HISTORY_TITLES = {0: "Time", 1: "Host", 2: "IP address", 3: "Status", 4: "Latency", 5: "TTL"}


def column_index(key: str) -> int:
    return next(i for i, c in enumerate(COLUMNS) if c.key == key)


def grid_title(column) -> str:
    """What the grid and its Columns menu call `column`."""
    if column.key in GRID_COLUMNS:
        return GRID_COLUMNS[column.key][0]
    return RENAMED_COLUMNS.get(column.key, column.title)


def service_name(port: int | str) -> str:
    """What usually listens on an open port as the grid lists it (443, or
    "161/udp"): the scanner's own label, else the OS services database,
    else ""."""
    number, _, proto = str(port).partition("/")
    proto = proto or "tcp"
    try:
        number = int(number)
    except ValueError:
        return ""
    known = (STATIC_UDP_PORTS if proto == "udp" else STATIC_PORTS).get(number)
    if known:
        return known
    try:
        return socket.getservbyport(number, proto).upper()
    except (OSError, OverflowError):
        return ""


def open_ports_html(ports) -> str:
    """Open ports one per line, each after its service name, in two aligned
    columns."""
    rows = "".join(
        f"<tr><td style='padding-right:14px'>{html.escape(service_name(p) or '—')}</td>"
        f"<td>{html.escape(str(p))}</td></tr>"
        for p in ports
    )
    return f"<table cellspacing='0' cellpadding='0'>{rows}</table>"


def label(text: str = "", name: str = "") -> QLabel:
    widget = QLabel(text)
    widget.setObjectName(name)
    widget.setTextFormat(Qt.TextFormat.PlainText)
    return widget


def theme_colors(dark: bool) -> dict[str, str]:
    if dark:
        return dict(bg="#121821", surface="#1a222e", sidebar="#161d27", ink="#e8edf5",
                    muted="#98a5b8", border="#2c3747", hover="#243042", select="#1f3b63",
                    selected_ink="#e8edf5", nav="#1f3b63", nav_ink="#9cc7ff", fill="#0d2a4d")
    return dict(bg="#f7f6f4", surface="#ffffff", sidebar="#f1f0ee", ink="#16191f",
                muted="#5f6673", border="#e3e5e9", hover="#eef0f3", select="#d6e7ff",
                selected_ink="#16191f", nav="#dfeaff", nav_ink="#0b5bd3", fill="#e3efff")


def status_badge(entry) -> tuple[str, str, str]:
    """(text, background, foreground) for a host's status pill."""
    if not entry.enabled:
        return "Disabled", "#eceef2", "#5f6673"
    if entry.last_status is None:
        return "Pending", "#fff1d1", "#8a5a00"
    if entry.last_status.succeeded:
        return "Online", "#dcf6e4", "#15803d"
    return "Offline", "#fde2e2", "#c62828"


def draw_badge(painter: QPainter, rect: QRectF, text: str, bg: str, fg: str) -> None:
    painter.save()
    painter.setRenderHint(QPainter.RenderHint.Antialiasing)
    font = QFont(painter.font())
    font.setWeight(QFont.Weight.DemiBold)
    painter.setFont(font)
    width = painter.fontMetrics().horizontalAdvance(text) + 28
    pill = QRectF(rect.left(), rect.center().y() - 9, width, 18)
    painter.setPen(Qt.PenStyle.NoPen)
    painter.setBrush(QColor(bg))
    painter.drawRoundedRect(pill, 9, 9)
    painter.setBrush(QColor(fg))
    painter.drawEllipse(QPointF(pill.left() + 10, pill.center().y()), 3, 3)
    painter.setPen(QColor(fg))
    painter.drawText(pill.adjusted(18, 0, 0, 0), Qt.AlignmentFlag.AlignVCenter, text)
    painter.restore()


def computer_name() -> str:
    """This computer's name as people know it: "OFFICE-PC", not
    "office-pc.corp.example" or "MacBook-Pro.local"."""
    return QSysInfo.machineHostName().split(".")[0]


class ElidedLabel(QLabel):
    """A one-line label that ends in "…" when it doesn't fit, with the
    full text as its tooltip (a long Mac name in the narrow sidebar)."""

    def __init__(self, text: str = "") -> None:
        super().__init__(text)
        self.setToolTip(text)
        self.setMinimumWidth(1)
        self.setSizePolicy(QSizePolicy.Policy.Ignored, QSizePolicy.Policy.Preferred)

    def paintEvent(self, event):
        painter = QPainter(self)
        text = self.fontMetrics().elidedText(self.text(), Qt.TextElideMode.ElideRight, self.width())
        painter.setPen(self.palette().color(self.foregroundRole()))
        painter.drawText(self.rect(), int(self.alignment()), text)


class StatusDelegate(QStyledItemDelegate):
    """Online/Offline pills in the grid; the model keeps the exact status
    text (Timeout, Host unreachable, ...) for sorting, export and tooltips."""

    def paint(self, painter, option, index):
        opt = QStyleOptionViewItem(option)
        self.initStyleOption(opt, index)
        opt.text = ""
        opt.widget.style().drawControl(QStyle.ControlElement.CE_ItemViewItem, opt, painter, opt.widget)
        proxy = index.model()
        entry = proxy.sourceModel().entry_at(proxy.mapToSource(index).row())
        if entry is not None:
            draw_badge(painter, QRectF(option.rect).adjusted(12, 0, 0, 0), *status_badge(entry))


class HistoryStatusDelegate(QStyledItemDelegate):
    def paint(self, painter, option, index):
        opt = QStyleOptionViewItem(option)
        self.initStyleOption(opt, index)
        text = opt.text
        opt.text = ""
        opt.widget.style().drawControl(QStyle.ControlElement.CE_ItemViewItem, opt, painter, opt.widget)
        ok = text == "Succeeded"
        draw_badge(painter, QRectF(option.rect).adjusted(12, 0, 0, 0), text,
                   "#dcf6e4" if ok else "#fde2e2", "#15803d" if ok else "#c62828")


class TextDelegate(QStyledItemDelegate):
    """Shows an em dash for an empty cell, adds a unit, and can use a
    monospaced font (addresses line up)."""

    def __init__(self, parent=None, suffix: str = "", mono: bool = False):
        super().__init__(parent)
        self.suffix = suffix
        self.mono = mono
        #: The mono font for each cell font seen (they're all the same
        #: unless the theme changes), so painting a cell doesn't build one.
        self._mono_fonts: dict[str, QFont] = {}

    def initStyleOption(self, option, index):
        super().initStyleOption(option, index)
        option.displayAlignment = Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter
        if option.text:
            option.text += self.suffix
        else:
            option.text = "—"
        if self.mono:
            key = option.font.key()
            font = self._mono_fonts.get(key)
            if font is None:
                size = QFont(option.font)
                size.setPixelSize(QFontInfo(option.font).pixelSize())
                font = self._mono_fonts[key] = fonts.mono(size)
            option.font = font


class TimeDelegate(TextDelegate):
    """The history's time column: "12:24:16" for today's pings, the full
    date only for older ones, so the column stays narrow."""

    def initStyleOption(self, option, index):
        super().initStyleOption(option, index)
        today = datetime.now().strftime("%Y-%m-%d ")
        if option.text.startswith(today):
            option.text = option.text[len(today):]


class MenuButton(QToolButton):
    """A drop-down button with a small chevron in place of Qt's arrow."""

    chevron_color = "#5f6673"

    def paintEvent(self, event):
        super().paintEvent(event)
        if self.objectName() == "navButton":
            return
        painter = QPainter(self)
        chevron = glyphs.pixmap("chevron", self.chevron_color, 12)
        painter.drawPixmap(self.width() - 22, (self.height() - 12) // 2, chevron)
        painter.end()


def y_steps(ceiling: float) -> int:
    """How many gridlines divide the latency axis into whole numbers
    (250 -> 5 steps of 50, not 4 of 62.5)."""
    for steps in (5, 4, 3, 2):
        if float(ceiling / steps).is_integer():
            return steps
    return 4


def x_intervals(width: float, label_width: float) -> int:
    """How many equal slices of the chart's time span fit their time labels
    side by side: 6 when wide, down to 2."""
    for intervals in (6, 4, 3, 2):
        if width / intervals >= label_width:
            return intervals
    return 1


#: The spans the latency chart can show, picked from its corner.
CHART_RANGES = (
    ("1 min", 60),
    ("5 min", 300),
    ("10 min", 600),
    ("30 min", 1800),
    ("60 min", 3600),
)


class RangeCombo(QComboBox):
    """A combo box styled as a small grey pill, with the up/down chevron that
    a style sheet takes away drawn back in at its right end."""

    def paintEvent(self, event):
        super().paintEvent(event)
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        painter.setPen(QPen(self.palette().color(self.foregroundRole()), 1.4,
                            Qt.PenStyle.SolidLine, Qt.PenCapStyle.RoundCap, Qt.PenJoinStyle.RoundJoin))
        x, y = self.width() - 11.0, self.height() / 2
        painter.drawPolyline([QPointF(x - 3, y - 2), QPointF(x, y - 5), QPointF(x + 3, y - 2)])
        painter.drawPolyline([QPointF(x - 3, y + 2), QPointF(x, y + 5), QPointF(x + 3, y + 2)])


class LatencyChart(QWidget):
    """The selected device's latency over a chosen span (a minute at first)."""

    def __init__(self, window):
        super().__init__()
        self.window = window
        self.setMinimumSize(220, 120)
        self.range_combo = RangeCombo(self)
        self.range_combo.setToolTip("How far back the chart goes")
        # A small box hugging its text and arrow (styled in apply_theme).
        self.range_combo.setObjectName("chartRange")
        self.range_combo.setCursor(Qt.CursorShape.PointingHandCursor)
        for text, seconds in CHART_RANGES:
            self.range_combo.addItem(text, seconds)
        # The list is as narrow as the box; leave room for the tick and text.
        metrics = self.range_combo.fontMetrics()
        widest = max(metrics.horizontalAdvance(text) for text, _ in CHART_RANGES)
        self.range_combo.view().setMinimumWidth(widest + 48)
        self.range_combo.currentIndexChanged.connect(self.update)
        #: How many seconds before now the chart ends: 0 follows now; drag
        #: or swipe sideways to look back, double-click to come back.
        self.offset = 0.0
        self._drag: tuple[float, float] | None = None  # (mouse x, offset)
        self._key = None  # the host shown, to start a new one at now
        self.setCursor(Qt.CursorShape.OpenHandCursor)
        self.setToolTip("Drag or swipe sideways to scroll back; double-click for now")

    @property
    def window_seconds(self) -> int:
        return self.range_combo.currentData()

    def _plot(self) -> QRectF:
        return QRectF(44, 34, max(1, self.width() - 80), max(1, self.height() - 58))

    def _latest_end(self) -> float:
        return self.window._stopped_at or time.time()

    def _max_offset(self) -> float:
        """How far back there's history to show for the selected host."""
        selected = self.window._selected_entries()
        history = self.window._samples.samples(selected[0].key) if len(selected) == 1 else []
        if not history:
            return 0.0
        return max(0.0, self._latest_end() - history[0].timestamp - self.window_seconds)

    def scroll_by(self, seconds: float) -> None:
        """Move the chart back (positive) or forward in time."""
        self.offset = min(self._max_offset(), max(0.0, self.offset + seconds))
        self.update()

    def mousePressEvent(self, event):
        if event.button() == Qt.MouseButton.LeftButton:
            self._drag = (event.position().x(), self.offset)
            self.setCursor(Qt.CursorShape.ClosedHandCursor)

    def mouseMoveEvent(self, event):
        if self._drag is None:
            return
        x, offset = self._drag
        moved = (event.position().x() - x) / self._plot().width() * self.window_seconds
        self.offset = offset
        self.scroll_by(moved)  # dragging right shows earlier pings

    def mouseReleaseEvent(self, event):
        self._drag = None
        self.setCursor(Qt.CursorShape.OpenHandCursor)

    def mouseDoubleClickEvent(self, event):
        self.offset = 0.0
        self.update()

    def wheelEvent(self, event):
        delta = event.pixelDelta()
        dx = delta.x() if not delta.isNull() else event.angleDelta().x() / 8
        if not dx:
            event.ignore()
            return
        self.scroll_by(dx / self._plot().width() * self.window_seconds)

    def resizeEvent(self, event):
        super().resizeEvent(event)
        hint = self.range_combo.sizeHint()
        self.range_combo.setGeometry(self.width() - hint.width() - 8, 4, hint.width(), hint.height())

    def paintEvent(self, event):
        colors = theme_colors(self.window.settings.dark_background)
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        ink, muted, grid = QColor(colors["ink"]), QColor(colors["muted"]), QColor(colors["border"])
        title = QFont(self.font())
        title.setWeight(QFont.Weight.DemiBold)
        painter.setFont(title)
        painter.setPen(ink)
        painter.drawText(QRectF(12, 6, 200, 20), Qt.AlignmentFlag.AlignVCenter, "Latency (ms)")
        painter.setFont(self.font())
        span = self.window_seconds

        selected = self.window._selected_entries()
        key = selected[0].key if len(selected) == 1 else None
        if key != self._key:
            self._key, self.offset = key, 0.0
        self.offset = min(self.offset, self._max_offset())
        end = self._latest_end() - self.offset
        start = end - span
        samples = ([s for s in self.window._samples.samples(key, start) if s.timestamp <= end]
                   if key is not None else [])
        plot = self._plot()
        ceiling = nice_ceiling(max((s.rtt_ms or 0 for s in samples), default=10) * 1.15)
        steps = y_steps(ceiling)
        for i in range(steps + 1):
            y = plot.bottom() - plot.height() * i / steps
            painter.setPen(QPen(grid, 1))
            painter.drawLine(QPointF(plot.left(), y), QPointF(plot.right(), y))
            painter.setPen(muted)
            painter.drawText(QRectF(0, y - 9, plot.left() - 10, 18),
                             Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter,
                             f"{ceiling * i / steps:g}")
        intervals = x_intervals(plot.width(), painter.fontMetrics().horizontalAdvance("00:00:00") + 16)
        for i in range(intervals + 1):
            x = plot.left() + plot.width() * i / intervals
            painter.setPen(QPen(grid, 1))
            painter.drawLine(QPointF(x, plot.top()), QPointF(x, plot.bottom()))
            painter.setPen(muted)
            stamp = datetime.fromtimestamp(start + span * i / intervals).strftime("%H:%M:%S")
            painter.drawText(QRectF(x - 40, plot.bottom() + 6, 80, 18), Qt.AlignmentFlag.AlignCenter, stamp)
        if not samples:
            painter.setPen(muted)
            painter.drawText(plot, Qt.AlignmentFlag.AlignCenter,
                             "Select one device to see its latency" if len(selected) != 1
                             else "Waiting for ping replies")
            return

        def point(sample):
            x = plot.left() + (sample.timestamp - start) / span * plot.width()
            return QPointF(x, plot.bottom() - min(sample.rtt_ms, ceiling) / ceiling * plot.height())

        runs, run = [], []
        for sample in samples:
            if sample.rtt_ms is None:
                if run:
                    runs.append(run)
                run = []
                x = plot.left() + (sample.timestamp - start) / span * plot.width()
                painter.setPen(QPen(QColor(RED), 2))
                painter.drawLine(QPointF(x, plot.bottom() - 8), QPointF(x, plot.bottom()))
            else:
                run.append(point(sample))
        if run:
            runs.append(run)
        fill = QColor(colors["fill"])
        fill.setAlpha(170)
        for points in runs:
            area = QPainterPath(QPointF(points[0].x(), plot.bottom()))
            line = QPainterPath(points[0])
            for p in points:
                area.lineTo(p)
            for p in points[1:]:
                line.lineTo(p)
            area.lineTo(QPointF(points[-1].x(), plot.bottom()))
            painter.fillPath(area, fill)
            painter.setPen(QPen(QColor(BLUE), 2))
            painter.drawPath(line)
            # Dots only while they're spread out enough to tell apart.
            if plot.width() / max(1, len(samples)) >= 6:
                painter.setBrush(QColor(BLUE))
                painter.setPen(Qt.PenStyle.NoPen)
                for p in points:
                    painter.drawEllipse(p, 2.6, 2.6)
            painter.setBrush(Qt.BrushStyle.NoBrush)


def follow_action(button: QToolButton, action: QAction) -> None:
    """Trigger `action` from `button` and mirror its enabled state and
    tooltip, keeping the button's own label and icon."""
    def sync():
        button.setEnabled(action.isEnabled())
        button.setToolTip(action.toolTip())

    button.clicked.connect(action.trigger)
    action.changed.connect(sync)
    sync()


class Dashboard(QWidget):
    def __init__(self, window, interfaces=()):
        super().__init__()
        self.window = window
        self.interfaces = list(interfaces)
        self._icon_targets: list[tuple[object, str, bool]] = []
        root = QHBoxLayout(self)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(0)
        root.addWidget(self._build_sidebar())
        body = QWidget()
        body.setObjectName("body")
        layout = QVBoxLayout(body)
        layout.setContentsMargins(16, 12, 16, 8)
        layout.setSpacing(10)
        layout.addLayout(self._build_heading())
        layout.addWidget(self._build_summary())
        layout.addLayout(self._build_filters())
        self._setup_grid()
        self._build_inspector()
        # The table and the inspector share MainWindow's splitter, so the
        # Show Lower Pane setting still hides the whole lower half.
        splitter = window._splitter
        while splitter.count() > 1:
            splitter.widget(1).setParent(None)
        splitter.addWidget(self.inspector)
        splitter.setChildrenCollapsible(False)
        splitter.setStretchFactor(0, 3)
        splitter.setStretchFactor(1, 2)
        splitter.setSizes([600, 380])
        layout.addWidget(splitter, 1)
        root.addWidget(body, 1)

        self.timer = QTimer(self)
        self.timer.timeout.connect(self.refresh)
        self.timer.start(1000)
        for signal in (window._model.modelReset, window._model.rowsInserted,
                       window._model.rowsRemoved):
            signal.connect(self.refresh)
        window._table.selectionModel().selectionChanged.connect(self.refresh)
        self.apply_icons()
        self.refresh()

    # -- construction ------------------------------------------------------

    def _icon(self, widget, name: str, accent: bool = False) -> None:
        self._icon_targets.append((widget, name, accent))

    def _tool_button(self, text: str, icon: str, name: str, action=None,
                     cls=QToolButton) -> QToolButton:
        button = cls()
        if action is not None:
            follow_action(button, action)
        button.setText(text)
        button.setObjectName(name)
        button.setToolButtonStyle(Qt.ToolButtonStyle.ToolButtonTextBesideIcon)
        self._icon(button, icon)
        return button

    def _menu_button(self, text: str, icon: str, actions, name: str = "") -> QToolButton:
        button = self._tool_button(text, icon, name, cls=MenuButton)
        button.setPopupMode(QToolButton.ToolButtonPopupMode.InstantPopup)
        menu = QMenu(button)
        for action in actions:
            menu.addSeparator() if action is None else menu.addAction(action)
        button.setMenu(menu)
        return button

    def _build_sidebar(self) -> QWidget:
        w = self.window
        sidebar = QFrame()
        sidebar.setObjectName("sidebar")
        sidebar.setFixedWidth(180)
        nav = QVBoxLayout(sidebar)
        nav.setContentsMargins(10, 12, 10, 10)
        nav.setSpacing(2)

        brand = QHBoxLayout()
        brand.setSpacing(8)
        logo = QLabel()
        logo.setPixmap(glyphs.pixmap("brand", BLUE, 22))
        brand.addWidget(logo)
        brand.addWidget(label("NetInfoView", "brand"))
        brand.addStretch()
        nav.addLayout(brand)
        nav.addSpacing(12)

        self.nav_overview = self._tool_button("Network overview", "overview", "navSelected")
        self._icon_targets[-1] = (self.nav_overview, "overview", True)
        self.nav_overview.clicked.connect(lambda: w._table.setFocus())
        nav.addWidget(self.nav_overview)
        # Devices opens Add Hosts straight away; removing, enabling, loading
        # and the rest are on the grid's right-click menu.
        self.nav_devices = self._tool_button("Devices", "devices", "navButton", w.action_add)
        nav.addWidget(self.nav_devices)
        nav.addWidget(self._tool_button("Ping monitor", "ping", "navButton", w.action_route_monitor))
        # Discovery opens the LLDP/CDP window straight away. Trace Path MTU is
        # on the grid's right-click menu; MTU is checked automatically.
        self.nav_discovery = self._tool_button("Discovery", "discovery", "navButton",
                                               w.action_lldp_cdp)
        nav.addWidget(self.nav_discovery)
        # Net Path maps the routes to the selected device.
        self.nav_net_path = self._tool_button("Net Path", "netpath", "navButton", w.action_net_path)
        nav.addWidget(self.nav_net_path)
        # Repeat Ping: Cisco-style ping … repeat to the selected device.
        self.nav_repeat_ping = self._tool_button("Repeat Ping", "repeatping", "navButton",
                                                 w.action_repeat_ping)
        nav.addWidget(self.nav_repeat_ping)
        # Port Scan checks the selected device's TCP ports.
        self.nav_port_scan = self._tool_button("Port Scan", "portscan", "navButton",
                                               w.action_port_scan)
        nav.addWidget(self.nav_port_scan)
        # Settings opens Options straight away; the view toggles (dark
        # background, font, lower pane, ...) stay on the grid's right-click menu.
        self.nav_settings = self._tool_button("Settings", "settings", "navButton", w.action_options)
        nav.addWidget(self.nav_settings)
        nav.addStretch()
        # Both kinds of update in one place: the app itself, and the MAC
        # vendor list it names devices with.
        self.nav_updates = self._menu_button("Check for updates", "update", (
            w.action_check_updates, w.action_update_vendor_db,
        ), "navButton")
        nav.addWidget(self.nav_updates)

        line = QFrame()
        line.setObjectName("rule")
        line.setFixedHeight(1)
        nav.addSpacing(8)
        nav.addWidget(line)
        nav.addSpacing(8)
        footer = QGridLayout()
        footer.setContentsMargins(6, 0, 4, 0)
        footer.setHorizontalSpacing(10)
        footer.setVerticalSpacing(2)
        self.connection_dot = label("●", "dotOnline")
        self.connection_state = label("Go Live!", "strong")
        self.version_label = label(f"v{__version__}", "muted")
        self.version_label.setToolTip(f"NetInfoView {__version__}")
        self.computer_name = ElidedLabel(computer_name())
        self.connection_ip = label("", "muted")
        footer.addWidget(self.connection_dot, 0, 0)
        state_row = QHBoxLayout()
        state_row.setSpacing(6)
        state_row.addWidget(self.connection_state)
        state_row.addWidget(self.version_label)
        state_row.addStretch(1)
        footer.addLayout(state_row, 0, 1)
        footer.addWidget(self.computer_name, 1, 1)
        footer.addWidget(self.connection_ip, 2, 1)
        footer.setColumnStretch(1, 1)
        nav.addLayout(footer)
        return sidebar

    def _build_heading(self) -> QHBoxLayout:
        w = self.window
        heading = QHBoxLayout()
        titles = QVBoxLayout()
        titles.setSpacing(2)
        titles.addWidget(label("Network overview", "title"))
        self.subtitle = label("", "subtitle")
        titles.addWidget(self.subtitle)
        heading.addLayout(titles)
        heading.addStretch()
        self.start_button = self._tool_button("Start scan", "play", "primary", w.action_start)
        self.stop_button = self._tool_button("Stop scan", "stop", "danger", w.action_stop)
        for button in (self.start_button, self.stop_button):
            heading.addWidget(button)
        heading.addSpacing(6)
        self.export_button = self._menu_button("Export", "export", (
            w.action_export, w.action_save_hosts, w.action_copy,
        ), "large")
        heading.addWidget(self.export_button)
        return heading

    def _build_summary(self) -> QFrame:
        summary = QFrame()
        summary.setObjectName("card")
        row = QHBoxLayout(summary)
        row.setContentsMargins(16, 8, 16, 8)
        row.setSpacing(0)
        self.stats = []
        for i, (name, mark) in enumerate((("devices", "devices"), ("online", GREEN),
                                           ("offline", RED), ("avg. latency", "activity"))):
            if i:
                rule = QFrame()
                rule.setObjectName("vrule")
                rule.setFixedWidth(1)
                row.addWidget(rule)
            cell = QHBoxLayout()
            cell.setSpacing(7)
            cell.addStretch()
            marker = QLabel()
            if mark.startswith("#"):
                marker.setText("●")
                marker.setStyleSheet(f"color: {mark}; font-size: 12px;")
            else:
                self._icon(marker, mark)
            cell.addWidget(marker)
            value = label("—", "stat")
            self.stats.append(value)
            cell.addWidget(value)
            cell.addWidget(label(name, "statCaption"))
            cell.addStretch()
            row.addLayout(cell, 1)
        return summary

    def _build_filters(self) -> QHBoxLayout:
        w = self.window
        filters = QHBoxLayout()
        filters.setSpacing(8)
        self.search = QLineEdit()
        self.search.setObjectName("search")
        self.search.setPlaceholderText("Search by hostname, IP or MAC")
        self.search.setClearButtonEnabled(True)
        self.search.setMinimumWidth(200)
        self.search.textChanged.connect(self.search_changed)
        self._search_action = self.search.addAction(glyphs.icon("search", "#888"),
                                                    QLineEdit.ActionPosition.LeadingPosition)
        filters.addWidget(self.search, 1)

        segment = QFrame()
        segment.setObjectName("segment")
        seg = QHBoxLayout(segment)
        seg.setContentsMargins(2, 2, 2, 2)
        seg.setSpacing(2)
        self.filter_buttons = {}
        for mode, text in ((DisplayMode.ALL, "All"), (DisplayMode.SUCCEEDED, "Online"),
                           (DisplayMode.FAILED, "Offline")):
            button = QPushButton(text)
            button.setObjectName("segmentButton")
            button.setCheckable(True)
            button.setMinimumWidth(54)
            button.clicked.connect(lambda checked, m=mode: w._set_display_mode(m))
            self.filter_buttons[mode] = button
            seg.addWidget(button)
        filters.addWidget(segment)

        filters.addWidget(self._menu_button("Filters", "filter", (w.action_hide_disabled,), "large"))
        columns = self._menu_button("Columns", "columns", (), "large")
        menu = columns.menu()
        for index, column in enumerate(COLUMNS):
            if column.key in EXCLUDED_COLUMNS:
                continue
            action = QAction(grid_title(column), menu, checkable=True)
            action.setChecked(column.key in GRID_COLUMNS)
            action.toggled.connect(lambda checked, i=index: self.set_column_visible(i, checked))
            menu.addAction(action)
        filters.addWidget(columns)
        return filters

    def _setup_grid(self) -> None:
        w = self.window
        table = w._table
        header = table.horizontalHeader()
        for position, key in enumerate(GRID_COLUMNS):
            index = column_index(key)
            header.moveSection(header.visualIndex(index), position)
        for index, column in enumerate(COLUMNS):
            table.setColumnHidden(index, column.key not in GRID_COLUMNS)
        w._proxy.header_titles = {i: grid_title(c) for i, c in enumerate(COLUMNS)
                                  if grid_title(c) != c.title}
        for key, (_, width) in GRID_COLUMNS.items():
            if width is not None:
                table.setColumnWidth(column_index(key), width)
        header.setStretchLastSection(False)
        # Hostname fills the spare width, but stays Interactive (a Stretch
        # column can't be dragged, and is squeezed to nothing once the
        # Columns menu adds more than fit). Once dragged, it's left alone.
        self._stretch_user_sized = False
        self._fitting = False
        header.sectionResized.connect(self._on_section_resized)
        table.viewport().installEventFilter(self)
        self.fit_stretch_column()
        header.setDefaultAlignment(Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter)
        table.setItemDelegateForColumn(column_index("last_status"), StatusDelegate(table))
        table.setItemDelegateForColumn(column_index("last_rtt"), TextDelegate(table, " ms"))
        table.setItemDelegateForColumn(column_index("hostname"), TextDelegate(table))
        for key in ("ip_address", "mac_address"):
            table.setItemDelegateForColumn(column_index(key), TextDelegate(table, mono=True))
        table.setFrameShape(QFrame.Shape.NoFrame)
        table.setObjectName("grid")

    def set_column_visible(self, index: int, visible: bool) -> None:
        self.window._table.setColumnHidden(index, not visible)
        self.fit_stretch_column()

    def fit_stretch_column(self) -> None:
        """Widen Hostname to fill whatever the other visible columns leave,
        unless the user has sized it by hand."""
        if self._stretch_user_sized:
            return
        table = self.window._table
        header = table.horizontalHeader()
        stretch = column_index(STRETCH_COLUMN)
        others = sum(header.sectionSize(i) for i in range(header.count())
                     if i != stretch and not header.isSectionHidden(i))
        width = max(STRETCH_MIN_WIDTH, table.viewport().width() - others)
        self._fitting = True
        try:
            header.resizeSection(stretch, width)
        finally:
            self._fitting = False

    def _on_section_resized(self, index: int, old: int, new: int) -> None:
        if self._fitting:
            return
        if index == column_index(STRETCH_COLUMN):
            self._stretch_user_sized = True  # dragged by hand: keep it
        else:
            self.fit_stretch_column()

    def eventFilter(self, obj, event):
        if event.type() == QEvent.Type.Resize and obj is self.window._table.viewport():
            self.fit_stretch_column()
        return super().eventFilter(obj, event)

    def _build_inspector(self) -> None:
        w = self.window
        self.inspector = QWidget()
        self.inspector.setObjectName("inspector")
        layout = QVBoxLayout(self.inspector)
        layout.setContentsMargins(0, 8, 0, 0)
        layout.setSpacing(6)

        head = QHBoxLayout()
        head.setSpacing(8)
        self.selection_icon = QLabel()
        self._icon(self.selection_icon, "devices")
        head.addWidget(self.selection_icon)
        self.selection_title = label("Select a device to inspect", "selectionTitle")
        head.addWidget(self.selection_title)
        self.selection_rule = QFrame()
        self.selection_rule.setObjectName("vrule")
        self.selection_rule.setFixedSize(1, 16)
        head.addWidget(self.selection_rule)
        self.selection_ip = label("", "selectionIp")
        head.addWidget(self.selection_ip)
        self.selection_badge = label("", "badge")
        head.addWidget(self.selection_badge)
        head.addStretch()
        layout.addLayout(head)

        self.tabs = QTabWidget()
        self.tabs.tabBar().setDrawBase(False)
        self.overview = QWidget()
        grid = QGridLayout(self.overview)
        grid.setContentsMargins(12, 10, 12, 10)
        grid.setHorizontalSpacing(28)
        grid.setVerticalSpacing(10)
        self.overview_fields = {}
        names = ("Status", "Latency", "Packet loss", "Pings sent", "IP address", "Hostname",
                 "MAC address", "Vendor", "Device type", "MTU", "Open ports", "DNS name")
        for i, name in enumerate(names):
            r, c = divmod(i, 4)
            box = QVBoxLayout()
            box.setSpacing(2)
            box.addWidget(label(name, "fieldName"))
            value = label("—", "fieldValue")
            value.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
            # Long values (a list of open ports, a vendor's full name) wrap
            # within their column instead of widening it.
            value.setWordWrap(True)
            value.setAlignment(Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignTop)
            self.overview_fields[name] = value
            if name == "Open ports":
                value.setTextFormat(Qt.TextFormat.RichText)
            box.addWidget(value)
            box.addStretch()
            grid.addLayout(box, r, c)
        for c in range(4):
            grid.setColumnStretch(c, 1)  # four equal columns
        grid.setRowStretch(3, 1)
        # A host with many open ports (one per line) can outgrow the pane.
        scroll = QScrollArea()
        scroll.setObjectName("overviewScroll")
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.Shape.NoFrame)
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        scroll.setWidget(self.overview)

        history = QSplitter(Qt.Orientation.Horizontal)
        history.setChildrenCollapsible(False)
        chart_card = QFrame()
        chart_card.setObjectName("card")
        chart_layout = QVBoxLayout(chart_card)
        chart_layout.setContentsMargins(0, 0, 0, 0)
        self.chart = LatencyChart(w)
        chart_layout.addWidget(self.chart)
        history.addWidget(chart_card)
        hv = w._history_view
        hv.setFrameShape(QFrame.Shape.NoFrame)
        hv.setObjectName("historyGrid")
        w._history_proxy.header_titles = dict(HISTORY_TITLES)
        hv.horizontalHeader().setDefaultAlignment(Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter)
        hv.setItemDelegateForColumn(0, TimeDelegate(hv))
        hv.setItemDelegateForColumn(3, HistoryStatusDelegate(hv))
        hv.setItemDelegateForColumn(4, TextDelegate(hv, " ms"))
        hv.setItemDelegateForColumn(5, TextDelegate(hv))
        for index, width in ((0, 76), (1, 120), (2, 104), (3, 104), (4, 70), (5, 40)):
            hv.setColumnWidth(index, width)
        table_card = QFrame()
        table_card.setObjectName("card")
        table_layout = QVBoxLayout(table_card)
        table_layout.setContentsMargins(1, 1, 1, 1)
        table_layout.addWidget(hv)
        history.addWidget(table_card)
        history.setStretchFactor(0, 1)
        history.setStretchFactor(1, 1)
        history.setSizes([560, 440])
        # Two tabs: the ping history, and the device's details (the field
        # grid that used to be "Overview", replacing the old text dump).
        self.tabs.addTab(history, "Ping history")
        self.tabs.addTab(scroll, "Details")
        self.tabs.setCurrentIndex(0)
        layout.addWidget(self.tabs, 1)

    # -- behaviour ---------------------------------------------------------

    def apply_icons(self) -> None:
        colors = theme_colors(self.window.settings.dark_background)
        for widget, name, accent in self._icon_targets:
            color = colors["nav_ink"] if accent else colors["ink"]
            if widget.objectName() in ("primary", "danger"):
                color = "#ffffff"
            if isinstance(widget, QLabel):
                widget.setPixmap(glyphs.pixmap(name, color, 16))
                continue
            size, pad = (16, 8) if widget.objectName() in ("navButton", "navSelected") else (14, 5)
            widget.setIcon(glyphs.icon(name, color, size, pad))
            widget.setIconSize(QSize(size + pad, size))
            if isinstance(widget, MenuButton):
                widget.chevron_color = colors["ink"]
        self._search_action.setIcon(glyphs.icon("search", colors["muted"]))

    def search_changed(self, text):
        self.window._proxy.set_search_text(text)
        self.window._update_status_bar()

    def _network_text(self) -> tuple[str, str]:
        if not self.interfaces:
            return "No network connection", ""
        iface = self.interfaces[0]
        return f"Local network · {iface.cidr}", iface.ip_address

    def refresh(self, *_):
        w = self.window
        entries = w._model.entries()
        online = sum(e.last_status is not None and e.last_status.succeeded for e in entries)
        offline = sum(e.last_status is not None and not e.last_status.succeeded for e in entries)
        rtts = [e.last_rtt_ms for e in entries
                if e.last_status is not None and e.last_status.succeeded and e.last_rtt_ms is not None]
        values = (str(len(entries)), str(online), str(offline),
                  f"{sum(rtts) / len(rtts):.0f} ms" if rtts else "—")
        for widget, value in zip(self.stats, values):
            widget.setText(value)
        self.stats[0].setToolTip(f"{len(entries) - online - offline} not pinged yet")

        subtitle, ip = self._network_text()
        self.subtitle.setText(subtitle)
        self.connection_state.setText("Go Live!" if ip else "Not connected")
        self.connection_ip.setText(ip)
        self.connection_dot.setObjectName("dotOnline" if ip else "dotOffline")
        self.connection_dot.style().polish(self.connection_dot)

        running = w._engine is not None
        self.start_button.setVisible(not running)
        self.stop_button.setVisible(running)
        for mode, button in self.filter_buttons.items():
            button.setChecked(w._proxy.display_mode is mode)

        selected = w._selected_entries()
        single = len(selected) == 1
        w._history_view.setColumnHidden(1, single)
        w._history_view.setColumnHidden(2, single)
        for widget in (self.selection_rule, self.selection_ip, self.selection_badge):
            widget.setVisible(single)
        if single:
            self._show_entry(selected[0])
        else:
            self.selection_title.setText(
                f"{len(selected)} devices selected" if selected else "Select a device to inspect")
            for value in self.overview_fields.values():
                value.setText("—")
        self.chart.update()
        w._last_scan_label.setText(self._last_scan_text(entries))

    @staticmethod
    def _last_scan_text(entries) -> str:
        times = [t for e in entries for t in (e.last_succeed_on, e.last_failed_on) if t]
        if not times:
            return "Not scanned yet"
        age = time.time() - max(times)
        if age < 10:
            return "Last scan just now"
        if age < 60:
            return f"Last scan {age:.0f} s ago"
        if age < 3600:
            return f"Last scan {age / 60:.0f} min ago"
        return "Last scan " + datetime.fromtimestamp(max(times)).strftime("%H:%M")

    def _show_entry(self, e) -> None:
        self.selection_title.setText(e.hostname or e.display_name)
        ip = e.ip_address or e.host
        self.selection_ip.setText(ip)
        # A host with no name is titled by its address: don't show it twice.
        same = ip == self.selection_title.text()
        self.selection_ip.setVisible(not same)
        self.selection_rule.setVisible(not same)
        text, bg, fg = status_badge(e)
        self.selection_badge.setText(f"●  {text}")
        self.selection_badge.setStyleSheet(
            f"background: {bg}; color: {fg}; border-radius: 9px; padding: 2px 9px; font-weight: 600;")
        latency = "—" if e.last_rtt_ms is None else f"{e.last_rtt_ms:g} ms"
        exact = e.last_status.value if e.last_status else "Not pinged yet"
        fields = {
            "Status": exact, "Latency": latency, "Packet loss": f"{e.percent_failed:.1f}%",
            "Pings sent": str(e.total_sent), "IP address": e.ip_address or "—",
            "Hostname": e.hostname or "—", "MAC address": e.mac_address or "—",
            "Vendor": e.vendor or "—", "Device type": e.device_type_guess or "—",
            "MTU": str(e.mtu) if e.mtu else "—",
            "Open ports": open_ports_html(e.open_ports) if e.open_ports else "—", "DNS name": e.dns_name or "—",
        }
        for name, value in fields.items():
            self.overview_fields[name].setText(value)


def apply_theme(window) -> None:
    c = theme_colors(window.settings.dark_background)
    family = f"font-family: '{fonts.UI_FAMILY}';" if fonts.load() else ""
    mono_family = f"font-family: '{fonts.mono().family()}';"
    window.setStyleSheet(f"""
        QMainWindow {{ background: {c['bg']}; }}
        QWidget {{ color: {c['ink']}; font-size: 12px; {family} }}
        QWidget[mono="true"] {{ {mono_family} }}
        QWidget#body, QWidget#inspector, QSplitter {{ background: {c['bg']}; }}
        QScrollArea#overviewScroll, QScrollArea#overviewScroll > QWidget > QWidget {{ background: {c['bg']}; }}
        QDialog, QMenu {{ background: {c['surface']}; }}
        QMenu {{ border: 1px solid {c['border']}; padding: 4px; }}
        QMenu::item {{ padding: 5px 18px 5px 18px; border-radius: 4px; }}
        QMenu::item:selected {{ background: {c['select']}; color: {c['selected_ink']}; }}
        QMenu::separator {{ height: 1px; background: {c['border']}; margin: 4px 8px; }}
        QComboBox#chartRange {{ background: {c['hover']}; border: none; border-radius: 5px; padding: 2px 4px 2px 8px; }}
        QComboBox#chartRange::drop-down {{ width: 16px; border: none; }}
        QLabel {{ background: transparent; }}
        QFrame#sidebar {{ background: {c['sidebar']}; border-right: 1px solid {c['border']}; }}
        QFrame#rule, QFrame#vrule {{ background: {c['border']}; }}
        QLabel#brand {{ font-size: 15px; font-weight: 700; }}
        QLabel#title {{ font-size: 19px; font-weight: 700; }}
        QLabel#subtitle {{ color: {c['muted']}; font-size: 12px; }}
        QLabel#muted, QLabel#fieldName {{ color: {c['muted']}; }}
        QLabel#strong {{ font-weight: 600; }}
        QLabel#fieldValue {{ font-size: 12px; }}
        QLabel#dotOnline {{ color: {GREEN}; font-size: 11px; }}
        QLabel#dotOffline {{ color: {RED}; font-size: 11px; }}
        QLabel#stat {{ font-size: 16px; font-weight: 700; }}
        QLabel#statCaption {{ color: {c['muted']}; font-size: 12px; }}
        QLabel#selectionTitle {{ font-size: 14px; font-weight: 700; }}
        QLabel#selectionIp {{ color: {c['muted']}; font-size: 12px; }}
        QFrame#card {{ background: {c['surface']}; border: 1px solid {c['border']}; border-radius: 8px; }}
        QToolButton, QPushButton {{ background: {c['surface']}; border: 1px solid {c['border']};
            border-radius: 6px; padding: 5px 9px; }}
        QToolButton#large {{ padding: 5px 26px 5px 9px; font-size: 12px; }}
        QToolButton:hover, QPushButton:hover {{ background: {c['hover']}; }}
        QToolButton::menu-indicator {{ image: none; width: 0; }}
        QToolButton:disabled, QPushButton:disabled {{ color: {c['muted']}; }}
        QToolButton#primary, QToolButton#danger {{ background: {BLUE}; color: white; border: none;
            font-size: 12px; font-weight: 600; padding: 6px 14px; }}
        QToolButton#primary:hover {{ background: #006ee6; }}
        QToolButton#primary:disabled {{ background: {c['border']}; color: {c['muted']}; }}
        QToolButton#danger {{ background: {RED}; }}
        QToolButton#navButton, QToolButton#navSelected {{ border: none; background: transparent;
            text-align: left; padding: 6px 8px; font-size: 12px; min-width: 140px; }}
        QToolButton#navButton:hover {{ background: {c['hover']}; border-radius: 6px; }}
        QToolButton#navSelected {{ background: {c['nav']}; color: {c['nav_ink']}; font-weight: 600;
            border-radius: 6px; }}
        QFrame#segment {{ background: {c['surface']}; border: 1px solid {c['border']}; border-radius: 7px; }}
        QPushButton#segmentButton {{ border: none; background: transparent; font-size: 12px;
            padding: 3px 10px; border-radius: 5px; }}
        QPushButton#segmentButton:hover {{ background: {c['hover']}; }}
        QPushButton#segmentButton:checked {{ background: {BLUE}; color: white; }}
        QLineEdit#search {{ background: {c['surface']}; border: 1px solid {c['border']}; border-radius: 6px;
            padding: 5px 6px 5px 2px; font-size: 12px; color: {c['ink']};
            selection-background-color: {BLUE}; }}
        QLineEdit#search:focus {{ border-color: {BLUE}; }}
        QTableView {{ background: {c['surface']}; color: {c['ink']}; border: 1px solid {c['border']};
            border-radius: 8px; selection-background-color: {c['select']};
            selection-color: {c['selected_ink']}; outline: 0; font-size: 12px; }}
        QTableView#historyGrid {{ border: none; font-size: 12px; }}
        QTableView::item {{ padding: 0 8px; border-bottom: 1px solid {c['border']}; }}
        QTableView::item:selected {{ background: {c['select']}; color: {c['selected_ink']}; }}
        QHeaderView::section {{ background: {c['surface']}; color: {c['ink']}; border: none;
            border-bottom: 1px solid {c['border']}; border-right: 1px solid {c['border']};
            padding: 4px 8px; }}
        QTableCornerButton::section {{ background: {c['surface']}; border: none; }}
        QTabWidget::pane {{ border: none; background: {c['bg']}; padding-top: 6px; }}
        QTabWidget::tab-bar {{ left: 0; }}
        QTabBar {{ background: transparent; }}
        QTabBar::tab {{ padding: 3px 12px; margin-right: 6px; border: none; border-radius: 5px;
            background: transparent; color: {c['ink']}; font-size: 12px; }}
        QTabBar::tab:hover {{ background: {c['hover']}; }}
        QTabBar::tab:selected {{ background: {BLUE}; color: white; }}
        QSplitter::handle {{ background: {c['bg']}; }}
        QSplitter::handle:vertical {{ height: 6px; }}
        QSplitter::handle:horizontal {{ width: 10px; }}
        QStatusBar {{ padding-left: 12px; background: {c['bg']}; color: {c['muted']}; border-top: 1px solid {c['border']}; }}
        QStatusBar QLabel {{ color: {c['muted']}; padding-right: 12px; }}
        QScrollBar:vertical {{ width: 8px; background: transparent; }}
        QScrollBar::handle:vertical {{ background: {c['border']}; border-radius: 4px; min-height: 30px; }}
        QScrollBar::add-line, QScrollBar::sub-line {{ height: 0; }}
    """)
    for table in (window._table, window._history_view):
        table.setShowGrid(False)
        table.verticalHeader().setDefaultSectionSize(24)
        table.horizontalHeader().setMinimumHeight(26)
    if hasattr(window, "_dashboard"):
        window._dashboard.apply_icons()
