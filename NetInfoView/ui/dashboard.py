"""The main window's layout: a sidebar, the network overview (summary,
search and filters, device grid) and an inspector for the selected device.

It only arranges and restyles what MainWindow already owns (its actions,
models, table and history view), so every feature keeps working as before.
"""
from __future__ import annotations

import time
from datetime import datetime

from PyQt6.QtCore import QPointF, QRectF, QSize, Qt, QTimer
from PyQt6.QtGui import (
    QAction, QColor, QFont, QFontDatabase, QFontInfo, QPainter, QPainterPath, QPen,
)
from PyQt6.QtWidgets import (
    QFrame, QGridLayout, QHBoxLayout, QHeaderView, QLabel, QLineEdit, QMenu, QPushButton,
    QSplitter, QStyle, QStyledItemDelegate, QStyleOptionViewItem, QTabWidget,
    QToolButton, QVBoxLayout, QWidget,
)

from ..model.columns import COLUMNS
from ..model.samples import nice_ceiling
from ..settings import DisplayMode
from . import glyphs

BLUE = "#087dff"
GREEN = "#16a34a"
RED = "#e5383b"

#: The device grid's default columns, in order, with shorter headers and
#: starting widths. Hostname (width None) takes whatever room is left, so
#: the grid fits the window without a horizontal scroll bar.
GRID_COLUMNS = {
    "last_status": ("Status", 120),
    "ip_address": ("IP address", 140),
    "hostname": ("Hostname", None),
    "mac_address": ("MAC address", 170),
    "last_rtt": ("Latency", 96),
}
STRETCH_COLUMN = "hostname"
#: History view columns: time, host, IP, status, latency, TTL.
HISTORY_TITLES = {0: "Time", 1: "Host", 2: "IP address", 3: "Status", 4: "Latency", 5: "TTL"}


def column_index(key: str) -> int:
    return next(i for i, c in enumerate(COLUMNS) if c.key == key)


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
    width = painter.fontMetrics().horizontalAdvance(text) + 34
    pill = QRectF(rect.left(), rect.center().y() - 11, width, 22)
    painter.setPen(Qt.PenStyle.NoPen)
    painter.setBrush(QColor(bg))
    painter.drawRoundedRect(pill, 11, 11)
    painter.setBrush(QColor(fg))
    painter.drawEllipse(QPointF(pill.left() + 13, pill.center().y()), 3.5, 3.5)
    painter.setPen(QColor(fg))
    painter.drawText(pill.adjusted(22, 0, 0, 0), Qt.AlignmentFlag.AlignVCenter, text)
    painter.restore()


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

    def initStyleOption(self, option, index):
        super().initStyleOption(option, index)
        option.displayAlignment = Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter
        if option.text:
            option.text += self.suffix
        else:
            option.text = "—"
        if self.mono:
            font = QFontDatabase.systemFont(QFontDatabase.SystemFont.FixedFont)
            font.setPixelSize(QFontInfo(option.font).pixelSize())
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
        chevron = glyphs.pixmap("chevron", self.chevron_color, 14)
        painter.drawPixmap(self.width() - 26, (self.height() - 14) // 2, chevron)
        painter.end()


def y_steps(ceiling: float) -> int:
    """How many gridlines divide the latency axis into whole numbers
    (250 -> 5 steps of 50, not 4 of 62.5)."""
    for steps in (5, 4, 3, 2):
        if float(ceiling / steps).is_integer():
            return steps
    return 4


def x_intervals(width: float, label_width: float) -> int:
    """How many equal slices of the 60 s window fit their time labels
    side by side: 6 (every 10 s) when wide, down to 2 (every 30 s)."""
    for intervals in (6, 4, 3, 2):
        if width / intervals >= label_width:
            return intervals
    return 1


class LatencyChart(QWidget):
    """The selected device's latency over the last 60 seconds."""

    WINDOW_SECONDS = 60

    def __init__(self, window):
        super().__init__()
        self.window = window
        self.setMinimumSize(240, 140)

    def paintEvent(self, event):
        colors = theme_colors(self.window.settings.dark_background)
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        ink, muted, grid = QColor(colors["ink"]), QColor(colors["muted"]), QColor(colors["border"])
        title = QFont(self.font())
        title.setWeight(QFont.Weight.DemiBold)
        painter.setFont(title)
        painter.setPen(ink)
        painter.drawText(QRectF(16, 10, 200, 22), Qt.AlignmentFlag.AlignVCenter, "Latency (ms)")
        painter.setFont(self.font())
        painter.setPen(muted)
        painter.drawText(QRectF(0, 10, self.width() - 16, 22),
                         Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter, "Last 60 seconds")

        selected = self.window._selected_entries()
        end = self.window._stopped_at or time.time()
        start = end - self.WINDOW_SECONDS
        samples = self.window._samples.samples(selected[0].key, start) if len(selected) == 1 else []
        plot = QRectF(52, 42, max(1, self.width() - 80), max(1, self.height() - 72))
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
            stamp = datetime.fromtimestamp(start + self.WINDOW_SECONDS * i / intervals).strftime("%H:%M:%S")
            painter.drawText(QRectF(x - 40, plot.bottom() + 6, 80, 18), Qt.AlignmentFlag.AlignCenter, stamp)
        if not samples:
            painter.setPen(muted)
            painter.drawText(plot, Qt.AlignmentFlag.AlignCenter,
                             "Select one device to see its latency" if len(selected) != 1
                             else "Waiting for ping replies")
            return

        def point(sample):
            x = plot.left() + (sample.timestamp - start) / self.WINDOW_SECONDS * plot.width()
            return QPointF(x, plot.bottom() - min(sample.rtt_ms, ceiling) / ceiling * plot.height())

        runs, run = [], []
        for sample in samples:
            if sample.rtt_ms is None:
                if run:
                    runs.append(run)
                run = []
                x = plot.left() + (sample.timestamp - start) / self.WINDOW_SECONDS * plot.width()
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
        layout.setContentsMargins(20, 16, 20, 10)
        layout.setSpacing(12)
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
        sidebar.setFixedWidth(212)
        nav = QVBoxLayout(sidebar)
        nav.setContentsMargins(12, 16, 12, 12)
        nav.setSpacing(4)

        brand = QHBoxLayout()
        brand.setSpacing(7)
        logo = QLabel()
        logo.setPixmap(glyphs.pixmap("brand", BLUE, 16))
        brand.addWidget(logo)
        brand.addWidget(label("NetInfoView", "brand"))
        brand.addStretch()
        nav.addLayout(brand)
        nav.addSpacing(18)

        self.nav_overview = self._tool_button("Network overview", "overview", "navSelected")
        self._icon_targets[-1] = (self.nav_overview, "overview", True)
        self.nav_overview.clicked.connect(lambda: w._table.setFocus())
        nav.addWidget(self.nav_overview)
        nav.addWidget(self._menu_button("Devices", "devices", (
            w.action_add, w.action_remove, w.action_clear_all, None,
            w.action_enable, w.action_disable, w.action_clear_stats, None,
            w.action_load, w.action_save_hosts, w.action_copy, w.action_properties,
        ), "navButton"))
        nav.addWidget(self._tool_button("Ping monitor", "ping", "navButton", w.action_graph))
        nav.addWidget(self._menu_button("Discovery", "discovery", (
            w.action_check_mtu, w.action_trace_mtu, w.action_lldp_cdp, None,
            w.action_update_vendor_db,
        ), "navButton"))
        nav.addWidget(self._menu_button("Settings", "settings", (
            w.action_options, None, w.action_dark, w.action_odd_even, w.action_always_on_top,
            w.action_font, w.action_autosize, None, w.action_show_history,
            w.action_auto_scroll, w.action_clear_history, None, w.action_about,
        ), "navButton"))
        nav.addStretch()
        nav.addWidget(self._tool_button("Check for updates", "update", "navButton",
                                        w.action_check_updates))

        line = QFrame()
        line.setObjectName("rule")
        line.setFixedHeight(1)
        nav.addSpacing(8)
        nav.addWidget(line)
        nav.addSpacing(8)
        footer = QGridLayout()
        footer.setContentsMargins(8, 0, 4, 0)
        footer.setHorizontalSpacing(10)
        footer.setVerticalSpacing(2)
        self.connection_dot = label("●", "dotOnline")
        self.connection_state = label("Connected", "strong")
        self.connection_ip = label("", "muted")
        footer.addWidget(self.connection_dot, 0, 0)
        footer.addWidget(self.connection_state, 0, 1)
        footer.addWidget(self.connection_ip, 1, 1)
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
        row.setContentsMargins(24, 12, 24, 12)
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
            cell.setSpacing(10)
            cell.addStretch()
            marker = QLabel()
            if mark.startswith("#"):
                marker.setText("●")
                marker.setStyleSheet(f"color: {mark}; font-size: 16px;")
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
        filters.setSpacing(10)
        self.search = QLineEdit()
        self.search.setObjectName("search")
        self.search.setPlaceholderText("Search by hostname, IP or MAC")
        self.search.setClearButtonEnabled(True)
        self.search.setMinimumWidth(240)
        self.search.textChanged.connect(self.search_changed)
        self._search_action = self.search.addAction(glyphs.icon("search", "#888"),
                                                    QLineEdit.ActionPosition.LeadingPosition)
        filters.addWidget(self.search, 1)

        segment = QFrame()
        segment.setObjectName("segment")
        seg = QHBoxLayout(segment)
        seg.setContentsMargins(3, 3, 3, 3)
        seg.setSpacing(2)
        self.filter_buttons = {}
        for mode, text in ((DisplayMode.ALL, "All"), (DisplayMode.SUCCEEDED, "Online"),
                           (DisplayMode.FAILED, "Offline")):
            button = QPushButton(text)
            button.setObjectName("segmentButton")
            button.setCheckable(True)
            button.setMinimumWidth(64)
            button.clicked.connect(lambda checked, m=mode: w._set_display_mode(m))
            self.filter_buttons[mode] = button
            seg.addWidget(button)
        filters.addWidget(segment)

        filters.addWidget(self._menu_button("Filters", "filter", (w.action_hide_disabled,), "large"))
        columns = self._menu_button("Columns", "columns", (), "large")
        menu = columns.menu()
        for index, column in enumerate(COLUMNS):
            action = QAction(column.title, menu, checkable=True)
            action.setChecked(column.key in GRID_COLUMNS)
            action.toggled.connect(lambda checked, i=index: w._table.setColumnHidden(i, not checked))
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
        w._proxy.header_titles = {column_index(k): t for k, (t, _) in GRID_COLUMNS.items()}
        for key, (_, width) in GRID_COLUMNS.items():
            if width is not None:
                table.setColumnWidth(column_index(key), width)
        header.setStretchLastSection(False)
        header.setSectionResizeMode(column_index(STRETCH_COLUMN), QHeaderView.ResizeMode.Stretch)
        header.setDefaultAlignment(Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter)
        table.setItemDelegateForColumn(column_index("last_status"), StatusDelegate(table))
        table.setItemDelegateForColumn(column_index("last_rtt"), TextDelegate(table, " ms"))
        table.setItemDelegateForColumn(column_index("hostname"), TextDelegate(table))
        for key in ("ip_address", "mac_address"):
            table.setItemDelegateForColumn(column_index(key), TextDelegate(table, mono=True))
        table.setFrameShape(QFrame.Shape.NoFrame)
        table.setObjectName("grid")

    def _build_inspector(self) -> None:
        w = self.window
        self.inspector = QWidget()
        self.inspector.setObjectName("inspector")
        layout = QVBoxLayout(self.inspector)
        layout.setContentsMargins(0, 10, 0, 0)
        layout.setSpacing(8)

        head = QHBoxLayout()
        head.setSpacing(12)
        self.selection_icon = QLabel()
        self._icon(self.selection_icon, "devices")
        head.addWidget(self.selection_icon)
        self.selection_title = label("Select a device to inspect", "selectionTitle")
        head.addWidget(self.selection_title)
        self.selection_rule = QFrame()
        self.selection_rule.setObjectName("vrule")
        self.selection_rule.setFixedSize(1, 20)
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
        grid.setContentsMargins(16, 12, 16, 12)
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
            self.overview_fields[name] = value
            box.addWidget(value)
            grid.addLayout(box, r, c)
        grid.setRowStretch(3, 1)
        self.tabs.addTab(self.overview, "Overview")

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
        for index, width in ((0, 88), (1, 140), (2, 120), (3, 122), (4, 80), (5, 44)):
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
        self.tabs.addTab(history, "Ping history")

        self.details = label("Select a device to view details.", "details")
        self.details.setWordWrap(True)
        self.details.setAlignment(Qt.AlignmentFlag.AlignTop | Qt.AlignmentFlag.AlignLeft)
        self.details.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        self.tabs.addTab(self.details, "Details")
        self.tabs.setCurrentIndex(1)
        layout.addWidget(self.tabs, 1)

    # -- behaviour ---------------------------------------------------------

    def apply_icons(self) -> None:
        colors = theme_colors(self.window.settings.dark_background)
        for widget, name, accent in self._icon_targets:
            color = colors["nav_ink"] if accent else colors["ink"]
            if widget.objectName() in ("primary", "danger"):
                color = "#ffffff"
            if isinstance(widget, QLabel):
                widget.setPixmap(glyphs.pixmap(name, color, 20))
                continue
            size, pad = (20, 12) if widget.objectName() in ("navButton", "navSelected") else (16, 6)
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
        self.connection_state.setText("Connected" if ip else "Not connected")
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
            self.details.setText("Select one device to view its network details.")
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
            f"background: {bg}; color: {fg}; border-radius: 11px; padding: 3px 12px; font-weight: 600;")
        latency = "—" if e.last_rtt_ms is None else f"{e.last_rtt_ms:g} ms"
        exact = e.last_status.value if e.last_status else "Not pinged yet"
        fields = {
            "Status": exact, "Latency": latency, "Packet loss": f"{e.percent_failed:.1f}%",
            "Pings sent": str(e.total_sent), "IP address": e.ip_address or "—",
            "Hostname": e.hostname or "—", "MAC address": e.mac_address or "—",
            "Vendor": e.vendor or "—", "Device type": e.device_type_guess or "—",
            "MTU": str(e.mtu) if e.mtu else "—",
            "Open ports": ", ".join(map(str, e.open_ports)) or "—", "DNS name": e.dns_name or "—",
        }
        for name, value in fields.items():
            self.overview_fields[name].setText(value)
        dash = "—"
        self.details.setText(
            f"Host: {e.host}{'' if e.port is None else f':{e.port}'}\n"
            f"Description: {e.description or dash}     Group: {e.group or dash}\n"
            f"Hostname: {e.hostname or dash}     DNS: {e.dns_name or dash}\n"
            f"All IPs: {', '.join(e.all_resolved_ips) or dash}\n"
            f"MAC: {e.mac_address or dash}     Vendor: {e.vendor or dash}\n"
            f"Device: {e.device_type_guess or dash}     MTU: {e.mtu or dash}\n"
            f"Open ports: {', '.join(map(str, e.open_ports)) or dash}\n"
            f"Last status: {exact}     TTL: {dash if e.last_ttl is None else e.last_ttl}\n"
            f"Sent: {e.total_sent}     Succeeded: {e.succeed_count}     Failed: {e.failed_count}"
            f"     Packet loss: {e.percent_failed:.1f}%\n"
            f"Min / max RTT: {dash if e.min_rtt_ms is None else e.min_rtt_ms} / "
            f"{dash if e.max_rtt_ms is None else e.max_rtt_ms} ms     "
            f"Longest failure streak: {e.max_consecutive_failed}")


def apply_theme(window) -> None:
    c = theme_colors(window.settings.dark_background)
    window.setStyleSheet(f"""
        QMainWindow {{ background: {c['bg']}; }}
        QWidget {{ color: {c['ink']}; font-size: 13px; }}
        QWidget#body, QWidget#inspector, QSplitter {{ background: {c['bg']}; }}
        QDialog, QMenu {{ background: {c['surface']}; }}
        QMenu {{ border: 1px solid {c['border']}; padding: 4px; }}
        QMenu::item {{ padding: 6px 22px 6px 22px; border-radius: 4px; }}
        QMenu::item:selected {{ background: {c['select']}; color: {c['selected_ink']}; }}
        QMenu::separator {{ height: 1px; background: {c['border']}; margin: 4px 8px; }}
        QLabel {{ background: transparent; }}
        QFrame#sidebar {{ background: {c['sidebar']}; border-right: 1px solid {c['border']}; }}
        QFrame#rule, QFrame#vrule {{ background: {c['border']}; }}
        QLabel#brand {{ font-size: 17px; font-weight: 700; }}
        QLabel#title {{ font-size: 24px; font-weight: 700; }}
        QLabel#subtitle {{ color: {c['muted']}; font-size: 13px; }}
        QLabel#muted, QLabel#fieldName {{ color: {c['muted']}; }}
        QLabel#strong {{ font-weight: 600; }}
        QLabel#fieldValue {{ font-size: 14px; }}
        QLabel#dotOnline {{ color: {GREEN}; font-size: 14px; }}
        QLabel#dotOffline {{ color: {RED}; font-size: 14px; }}
        QLabel#stat {{ font-size: 20px; font-weight: 700; }}
        QLabel#statCaption {{ color: {c['muted']}; font-size: 14px; }}
        QLabel#selectionTitle {{ font-size: 16px; font-weight: 700; }}
        QLabel#selectionIp {{ color: {c['muted']}; font-size: 14px; }}
        QLabel#details {{ padding: 16px; background: {c['surface']}; }}
        QFrame#card {{ background: {c['surface']}; border: 1px solid {c['border']}; border-radius: 10px; }}
        QToolButton, QPushButton {{ background: {c['surface']}; border: 1px solid {c['border']};
            border-radius: 8px; padding: 7px 12px; }}
        QToolButton#large {{ padding: 7px 30px 7px 12px; font-size: 13px; }}
        QToolButton:hover, QPushButton:hover {{ background: {c['hover']}; }}
        QToolButton::menu-indicator {{ image: none; width: 0; }}
        QToolButton:disabled, QPushButton:disabled {{ color: {c['muted']}; }}
        QToolButton#primary, QToolButton#danger {{ background: {BLUE}; color: white; border: none;
            font-size: 14px; font-weight: 600; padding: 8px 18px; }}
        QToolButton#primary:hover {{ background: #006ee6; }}
        QToolButton#primary:disabled {{ background: {c['border']}; color: {c['muted']}; }}
        QToolButton#danger {{ background: {RED}; }}
        QToolButton#navButton, QToolButton#navSelected {{ border: none; background: transparent;
            text-align: left; padding: 8px 10px; font-size: 14px; min-width: 164px; }}
        QToolButton#navButton:hover {{ background: {c['hover']}; border-radius: 8px; }}
        QToolButton#navSelected {{ background: {c['nav']}; color: {c['nav_ink']}; font-weight: 600;
            border-radius: 8px; }}
        QFrame#segment {{ background: {c['surface']}; border: 1px solid {c['border']}; border-radius: 9px; }}
        QPushButton#segmentButton {{ border: none; background: transparent; font-size: 13px;
            padding: 5px 12px; border-radius: 7px; }}
        QPushButton#segmentButton:hover {{ background: {c['hover']}; }}
        QPushButton#segmentButton:checked {{ background: {BLUE}; color: white; }}
        QLineEdit#search {{ background: {c['surface']}; border: 1px solid {c['border']}; border-radius: 8px;
            padding: 7px 8px 7px 4px; font-size: 13px; color: {c['ink']};
            selection-background-color: {BLUE}; }}
        QLineEdit#search:focus {{ border-color: {BLUE}; }}
        QTableView {{ background: {c['surface']}; color: {c['ink']}; border: 1px solid {c['border']};
            border-radius: 10px; selection-background-color: {c['select']};
            selection-color: {c['selected_ink']}; outline: 0; font-size: 13px; }}
        QTableView#historyGrid {{ border: none; font-size: 13px; }}
        QTableView::item {{ padding: 0 10px; border-bottom: 1px solid {c['border']}; }}
        QHeaderView::section {{ background: {c['surface']}; color: {c['ink']}; border: none;
            border-bottom: 1px solid {c['border']}; border-right: 1px solid {c['border']};
            padding: 6px 10px; }}
        QTableCornerButton::section {{ background: {c['surface']}; border: none; }}
        QTabWidget::pane {{ border: none; background: {c['bg']}; padding-top: 8px; }}
        QTabWidget::tab-bar {{ left: 0; }}
        QTabBar {{ background: transparent; }}
        QTabBar::tab {{ padding: 5px 16px; margin-right: 8px; border: none; border-radius: 7px;
            background: transparent; color: {c['ink']}; font-size: 13px; }}
        QTabBar::tab:hover {{ background: {c['hover']}; }}
        QTabBar::tab:selected {{ background: {BLUE}; color: white; }}
        QSplitter::handle {{ background: {c['bg']}; }}
        QSplitter::handle:vertical {{ height: 6px; }}
        QSplitter::handle:horizontal {{ width: 14px; }}
        QStatusBar {{ padding-left: 12px; background: {c['bg']}; color: {c['muted']}; border-top: 1px solid {c['border']}; }}
        QStatusBar QLabel {{ color: {c['muted']}; padding-right: 12px; }}
        QScrollBar:vertical {{ width: 10px; background: transparent; }}
        QScrollBar::handle:vertical {{ background: {c['border']}; border-radius: 4px; min-height: 30px; }}
        QScrollBar::add-line, QScrollBar::sub-line {{ height: 0; }}
    """)
    for table in (window._table, window._history_view):
        table.setShowGrid(False)
        table.verticalHeader().setDefaultSectionSize(30)
        table.horizontalHeader().setMinimumHeight(32)
    if hasattr(window, "_dashboard"):
        window._dashboard.apply_icons()
