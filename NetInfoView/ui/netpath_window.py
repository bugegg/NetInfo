"""Net Path window: every route to a host as a graph (ping/netpath.py),
traced again every few seconds while Live is on, with a strip of past traces
to step back through."""

from __future__ import annotations

import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from itertools import pairwise

from PyQt6.QtCore import QPointF, QRectF, Qt, QThread, QTimer, pyqtSignal
from PyQt6.QtGui import QBrush, QColor, QFont, QPainter, QPainterPath, QPen
from PyQt6.QtWidgets import (
    QCheckBox, QComboBox, QLineEdit, QFrame, QGraphicsItem, QGraphicsObject, QGraphicsScene, QGraphicsView,
    QGridLayout, QHBoxLayout, QLabel, QPushButton, QSpinBox, QSplitter, QVBoxLayout, QWidget,
)

from ..ping import hostname, netpath, whois
from ..ping.netpath import DESTINATION, SOURCE, PathGraph, Sweep
from ..ping.netpath_tcp import DEFAULT_PORT, UNHEARD, TcpProber, TcpUnavailable
from ..ping.route_monitor import resolve
from .tracepath_window import country_flag, country_label
from .threads import retire, track

#: Seconds between traces while Live is on.
LIVE_INTERVAL = 15
#: Traces kept in the history strip.
HISTORY = 60
NAME_WORKERS = 6

COLUMN_GAP = 168
ROW_GAP = 104
#: Width of a hop's name and address under it; narrower than a column, so
#: neighbours' labels and the latency pills between them never overlap.
LABEL_WIDTH = 130
#: The graph is never shrunk below this to fit; past it, scroll.
MIN_FIT_SCALE = 0.7
NODE_RADIUS = 17
END_SIZE = 40

GREEN = "#16a34a"
AMBER = "#d97706"
RED = "#e5383b"
BLUE = "#087dff"
#: The status pill: SolarWinds' words for a path's worst hop or link.
LEVEL_TEXT = {"ok": "Up", "warn": "Warning", "crit": "Critical"}
LEVEL_FILLS = {"ok": "#dcf6e4", "warn": "#fef3c7", "crit": "#fde2e2"}
LEVEL_COLORS = {netpath.OK: GREEN, netpath.WARN: AMBER, netpath.CRIT: RED}

LIGHT = dict(bg="#f6f7f9", surface="#ffffff", ink="#16191f", muted="#5f6673", border="#e3e5e9")


class NetPathThread(QThread):
    """Traces the path to one host, again every LIVE_INTERVAL seconds while
    `live` is set, and looks up each new hop's name and country."""

    sweep_ready = pyqtSignal(object)
    #: Sweep: the trace so far, after each hop that answered.
    partial_ready = pyqtSignal(object)
    #: The TTL being probed, for the status line.
    progress = pyqtSignal(int)
    name_ready = pyqtSignal(str, str)
    country_ready = pyqtSignal(str, str)
    #: (address, its network's name in whois, e.g. "GOOGLE"; "" if none).
    org_ready = pyqtSignal(str, str)
    #: Why TCP probes can't be used here; the thread has stopped.
    failed = pyqtSignal(str)
    #: The target's IPv4 address, found before the first trace.
    resolved = pyqtSignal(str)
    #: Why the target has no address; the thread has stopped.
    unresolved = pyqtSignal(str)

    def __init__(self, ip: str, live: bool = True, probe=None,
                 port: int | None = DEFAULT_PORT) -> None:
        """`ip` may be a host name, looked up here off the UI thread.
        Probes are TCP SYNs to `port`, or ICMP echoes if it's None; a
        `probe` given overrides both (tests)."""
        super().__init__()
        self._ip = ip
        self.live = live
        self._probe = probe
        self._port = port
        self._stop = False
        self._looked_up: set[str] = set()

    def stop(self) -> None:
        self._stop = True

    def run(self) -> None:  # noqa: D102 - QThread entry point
        try:
            self._ip = resolve(self._ip)
        except (OSError, UnicodeError) as error:
            self.unresolved.emit(str(error) or f"{self._ip} wasn't found")
            return
        if self._stop:
            return
        self.resolved.emit(self._ip)
        self._lookups = ThreadPoolExecutor(max_workers=NAME_WORKERS)
        try:
            while not self._stop:
                probe, prober = self._probe, None
                if probe is None and self._port is not None:
                    probe = prober = TcpProber(self._port)
                try:
                    result = netpath.sweep(self._ip, probe, stopped=lambda: self._stop,
                                           on_ttl=self.progress.emit,
                                           on_partial=self.partial_ready.emit)
                except TcpUnavailable as error:
                    self.failed.emit(str(error))
                    break
                finally:
                    if prober is not None:
                        prober.close()
                if self._stop:
                    break
                if prober is not None and not any(result.routes):
                    # Not one hop answered: the routers' ICMP errors aren't
                    # reaching us (Windows Firewall), not a dead path.
                    self.failed.emit(UNHEARD)
                    break
                self.sweep_ready.emit(result)
                self._look_up(result)
                if not self.live:
                    break
                until = time.monotonic() + LIVE_INTERVAL
                while not self._stop and self.live and time.monotonic() < until:
                    self.msleep(100)
                if not self.live:
                    break
        finally:
            self._lookups.shutdown(wait=False, cancel_futures=True)
            # A lookup still out (a reverse lookup can take seconds) finishes
            # on its own; stopping needn't wait for it.

    def _look_up(self, result: Sweep) -> None:
        for route in result.routes:
            for answer in route:
                if answer is None or answer.address in self._looked_up:
                    continue
                self._looked_up.add(answer.address)
                self._lookups.submit(self._name, answer.address)
                self._lookups.submit(self._country, answer.address)

    def _name(self, address: str) -> None:
        if self._stop:
            return
        # Boxes go by AS: one name for all of a provider's blocks.
        self.org_ready.emit(address, whois.as_org(address))
        name = (hostname.resolve(address) or whois.netname(address)
                or whois.reserved_name(address))
        # "" too, so the window stops saying it's looking.
        self.name_ready.emit(address, name or "")

    def _country(self, address: str) -> None:
        if self._stop:
            return
        code = whois.country(address)
        if code:
            self.country_ready.emit(address, code)


def layout(graph: PathGraph) -> dict[str, QPointF]:
    """Where each node goes: one column per hop, the source on the left and
    the host on the right; within a column, nodes are ordered by where their
    parents sit, so routes cross as little as possible."""
    columns: dict[int, list[str]] = {}
    for key, node in graph.nodes.items():
        columns.setdefault(node.ttl, []).append(key)
    parents: dict[str, list[str]] = {}
    for edge in graph.edges.values():
        parents.setdefault(edge.child, []).append(edge.parent)
    positions: dict[str, QPointF] = {}
    # One column per hop distance that has something to draw, side by side:
    # a provider's box covers several hops, and leaves no gap behind it.
    for column, ttl in enumerate(sorted(columns)):
        keys = columns[ttl]

        def weight(key: str) -> tuple[float, str]:
            ys = [positions[p].y() for p in parents.get(key, []) if p in positions]
            return (sum(ys) / len(ys) if ys else 0.0, key)

        keys.sort(key=weight)
        top = -(len(keys) - 1) * ROW_GAP / 2
        for row, key in enumerate(keys):
            positions[key] = QPointF(column * COLUMN_GAP, top + row * ROW_GAP)
    return positions


def curve(start: QPointF, end: QPointF) -> QPainterPath:
    """A link from `start` to `end` that leaves and arrives level."""
    path = QPainterPath(start)
    bend = (end.x() - start.x()) / 2
    path.cubicTo(QPointF(start.x() + bend, start.y()), QPointF(end.x() - bend, end.y()), end)
    return path


#: How faint a hop is when the trace on screen didn't pass it.
PAST_OPACITY = 0.4


class NodeItem(QGraphicsObject):
    """A hop (a circle with its hop number), this computer, the host or a
    provider's hops as one box (rounded squares), with its name and address
    underneath."""

    #: Double-clicked: a provider's box to open, or one of its hops to fold.
    activated = pyqtSignal(str)

    def __init__(self, key: str, kind: str, ring: str, text: str, title: str, subtitle: str,
                 colors: dict[str, str], dashed: bool = False) -> None:
        super().__init__()
        self.key = key
        self.kind = kind  # "router", "source", "destination" or "group"
        self.ring = QColor(ring)
        self.text = text
        self.title = title
        self.subtitle = subtitle
        self.colors = colors
        self.dashed = dashed
        self.setFlag(QGraphicsItem.GraphicsItemFlag.ItemIsSelectable)
        self.setCursor(Qt.CursorShape.PointingHandCursor)
        self.setAcceptHoverEvents(True)
        self.setZValue(2)

    def mouseDoubleClickEvent(self, event) -> None:
        # Handled in full before telling anyone: what it sets off redraws
        # the scene, deleting this item.
        super().mouseDoubleClickEvent(event)
        event.accept()
        self.activated.emit(self.key)

    def _shape_rect(self) -> QRectF:
        size = END_SIZE if self.kind != "router" else NODE_RADIUS * 2
        return QRectF(-size / 2, -size / 2, size, size)

    def boundingRect(self) -> QRectF:
        half = LABEL_WIDTH / 2
        return QRectF(-half, -END_SIZE / 2 - 4, LABEL_WIDTH, END_SIZE + 44)

    def shape(self) -> QPainterPath:
        path = QPainterPath()
        path.addRect(self._shape_rect().adjusted(-4, -4, 4, 4))
        return path

    def paint(self, painter: QPainter, option, widget=None) -> None:
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        rect = self._shape_rect()
        if self.isSelected():
            painter.setPen(QPen(QColor(BLUE), 3))
            painter.setBrush(Qt.BrushStyle.NoBrush)
            outline = rect.adjusted(-5, -5, 5, 5)
            if self.kind == "router":
                painter.drawEllipse(outline)
            else:
                painter.drawRoundedRect(outline, 10, 10)
        pen = QPen(self.ring, 2.5)
        if self.dashed:
            pen.setStyle(Qt.PenStyle.DashLine)
        painter.setPen(pen)
        painter.setBrush(QColor(self.colors["surface"]))
        if self.kind == "router":
            painter.drawEllipse(rect)
        else:
            painter.drawRoundedRect(rect, 8, 8)
        font = QFont(painter.font())
        font.setPixelSize(12)
        font.setBold(True)
        painter.setFont(font)
        painter.setPen(self.ring if not self.dashed else QColor(self.colors["muted"]))
        painter.drawText(rect, Qt.AlignmentFlag.AlignCenter, self.text)
        top = rect.bottom() + 4
        font.setPixelSize(11)
        painter.setFont(font)
        painter.setPen(QColor(self.colors["ink"]))
        metrics = painter.fontMetrics()
        half = LABEL_WIDTH / 2
        title = metrics.elidedText(self.title, Qt.TextElideMode.ElideRight, LABEL_WIDTH - 4)
        painter.drawText(QRectF(-half, top, LABEL_WIDTH, 16), Qt.AlignmentFlag.AlignHCenter, title)
        font.setBold(False)
        painter.setFont(font)
        painter.setPen(QColor(self.colors["muted"]))
        painter.drawText(QRectF(-half, top + 15, LABEL_WIDTH, 16), Qt.AlignmentFlag.AlignHCenter,
                         self.subtitle)


class PathView(QGraphicsView):
    """The path graph: drag to pan, wheel to zoom."""

    def __init__(self) -> None:
        super().__init__()
        self.setScene(QGraphicsScene(self))
        self.setRenderHint(QPainter.RenderHint.Antialiasing)
        self.setDragMode(QGraphicsView.DragMode.ScrollHandDrag)
        self.setTransformationAnchor(QGraphicsView.ViewportAnchor.AnchorUnderMouse)
        self.setFrameShape(QFrame.Shape.NoFrame)
        self.setMinimumSize(360, 240)

    def wheelEvent(self, event) -> None:
        self.zoom(1.15 if event.angleDelta().y() > 0 else 1 / 1.15)

    def zoom(self, factor: float) -> None:
        scale = self.transform().m11() * factor
        if 0.2 <= scale <= 3:
            self.scale(factor, factor)

    def fit(self) -> None:
        rect = self.scene().itemsBoundingRect().adjusted(-30, -30, 30, 30)
        self.resetTransform()
        scale = min(1.0, self.viewport().width() / max(1.0, rect.width()),
                    self.viewport().height() / max(1.0, rect.height()))
        scale = max(scale, MIN_FIT_SCALE)
        self.scale(scale, scale)
        # Too long to fit: start from this computer's end.
        self.centerOn(QPointF(min(rect.center().x(), rect.left() + self.viewport().width() / scale / 2),
                              rect.center().y()))


class HistoryStrip(QWidget):
    """One block per past trace, colored by how much of it reached the host;
    click one to show that trace."""

    picked = pyqtSignal(int)

    def __init__(self) -> None:
        super().__init__()
        #: Each trace's level (ok / warn / crit): its worst hop or link.
        self.healths: list[str] = []
        self.selected = -1
        self.colors = LIGHT
        self.setFixedHeight(26)
        self.setCursor(Qt.CursorShape.PointingHandCursor)

    def _cell(self) -> float:
        return self.width() / HISTORY

    def paintEvent(self, event) -> None:
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        cell = self._cell()
        painter.setPen(Qt.PenStyle.NoPen)
        for i in range(HISTORY):
            rect = QRectF(i * cell + 1, 3, cell - 2, self.height() - 6)
            color = (QColor(LEVEL_COLORS[self.healths[i]]) if i < len(self.healths)
                     else QColor(self.colors["border"]))
            painter.setBrush(color)
            painter.drawRoundedRect(rect, 2, 2)
        if 0 <= self.selected < len(self.healths):
            painter.setPen(QPen(QColor(BLUE), 2))
            painter.setBrush(Qt.BrushStyle.NoBrush)
            painter.drawRoundedRect(QRectF(self.selected * cell, 1, cell, self.height() - 2), 3, 3)

    def mousePressEvent(self, event) -> None:
        index = int(event.position().x() // self._cell())
        if 0 <= index < len(self.healths):
            self.picked.emit(index)


def _label(text: str = "", name: str = "") -> QLabel:
    label = QLabel(text)
    label.setObjectName(name)
    label.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
    return label


class NetPathWindow(QWidget):
    """A non-modal window showing every route to one host: the one given,
    or one typed in the Target box."""

    def __init__(self, title: str = "", ip: str = "", parent: QWidget | None = None,
                 probe=None, source: tuple[str, str] = ("This computer", ""),
                 live: bool = True, port: int | None = DEFAULT_PORT) -> None:
        super().__init__(parent, Qt.WindowType.Window)
        self.setAttribute(Qt.WidgetAttribute.WA_DeleteOnClose)
        self.setWindowTitle(f"Net Path - {title or ip}" if title or ip else "Net Path")
        self.resize(1080, 640)
        self._title = title or ip
        #: The address traced (the target as typed until it's looked up).
        self._ip = ip
        #: The target as typed for the history on screen.
        self._target = ip
        self._probe = probe
        self._source = source
        self.sweeps: list[Sweep] = []
        #: Each trace's own graph, side by side with sweeps: what's usual for
        #: a hop or link is taken from the other traces.
        self.graphs: list[PathGraph] = []
        #: Every trace in the history as one graph: every route seen. It
        #: sets where hops go, so they stay put from trace to trace.
        self.everything: PathGraph | None = None
        #: (parent, child) -> (the drawn link, whether the trace on screen took it).
        self.edge_items: dict = {}
        self.shown = -1  # index into sweeps of the trace on screen
        self._follow = True  # show each new trace as it comes
        self.names: dict[str, str] = {}
        self.countries: dict[str, str] = {}
        self.orgs: dict[str, str] = {}
        #: Provider boxes opened to show their hops.
        self.expanded: set[str] = set()
        #: Every hop's box, opened or not: {hop key: group key}.
        self.group_of: dict[str, str] = {}
        #: Every trace in the history as one graph, hops as traced.
        self.history_graph: PathGraph | None = None
        # Org names come in one by one: redraw once they've settled.
        self._regroup = QTimer(self)
        self._regroup.setSingleShot(True)
        self._regroup.setInterval(400)
        self._regroup.timeout.connect(self.refresh_view)
        self.items: dict[str, NodeItem] = {}
        self._fitted = False
        self._thread: NetPathThread | None = None
        settings = getattr(parent, "settings", None)
        dark = bool(getattr(settings, "dark_background", False))
        if dark:
            from .dashboard import theme_colors
            self.colors = theme_colors(True)
        else:
            self.colors = LIGHT

        heading = QHBoxLayout()
        titles = QVBoxLayout()
        titles.setSpacing(2)
        self.heading = _label(self._title or "Net Path", "netpathTitle")
        titles.addWidget(self.heading)
        self.route_text = _label("", "muted")
        titles.addWidget(self.route_text)
        heading.addLayout(titles, 1)
        self.health = QLabel("Tracing…")
        self.health.setObjectName("netpathHealth")
        heading.addWidget(self.health)
        heading.addSpacing(8)
        heading.addWidget(QLabel("Target"))
        self.target = QLineEdit(ip)
        self.target.setPlaceholderText("Host name or IP address")
        self.target.setMinimumWidth(180)
        self.target.setToolTip("The host to map; press Return or Trace Now to trace it")
        self.target.returnPressed.connect(self.trace_target)
        heading.addWidget(self.target)
        heading.addSpacing(8)
        heading.addWidget(QLabel("Probe"))
        self.mode = QComboBox()
        self.mode.addItems(["TCP", "ICMP"])
        self.mode.setToolTip("TCP: a SYN to the service's port, like SolarWinds NetPath; it gets "
                             "through firewalls that drop ping and follows the application's "
                             "routes.\nICMP: ping, with each probe flow pinned to one route.")
        self.mode.setCurrentIndex(0 if port is not None else 1)
        heading.addWidget(self.mode)
        self.port = QSpinBox()
        self.port.setRange(1, 65535)
        self.port.setValue(port or DEFAULT_PORT)
        self.port.setToolTip("The TCP port the probes go to: the service's own, e.g. 443 for HTTPS")
        self.port.setVisible(port is not None)
        heading.addWidget(self.port)
        self.mode.currentIndexChanged.connect(self._on_mode)
        self.port.editingFinished.connect(self._on_port)
        self._traced_port = self.probe_port()
        self.live = QCheckBox("Live")
        self.live.setChecked(live)
        self.live.setToolTip(f"Trace again every {LIVE_INTERVAL} seconds")
        self.live.toggled.connect(self._on_live)
        heading.addWidget(self.live)
        self.button = QPushButton("Trace Now")
        self.button.setToolTip("Trace the target; while tracing, stop")
        self.button.clicked.connect(self.toggle)
        heading.addWidget(self.button)

        self.view = PathView()
        self.view.scene().selectionChanged.connect(self._show_details)
        zoom = QHBoxLayout()
        zoom.setSpacing(4)
        for text, tip, slot in (("+", "Zoom in", lambda: self.view.zoom(1.25)),
                                ("−", "Zoom out", lambda: self.view.zoom(0.8)),
                                ("Fit", "Fit the whole path", self.view.fit)):
            button = QPushButton(text)
            button.setToolTip(tip)
            button.setFixedWidth(40 if len(text) > 1 else 28)
            button.clicked.connect(slot)
            zoom.addWidget(button)
        zoom.addSpacing(10)
        self.group_box = QCheckBox("Group providers")
        self.group_box.setChecked(True)
        self.group_box.setToolTip("Show each provider's routers (e.g. GOOGLE) as one box; "
                                  "double-click a box to open it, a hop in it to fold it again")
        self.group_box.toggled.connect(self.refresh_view)
        zoom.addWidget(self.group_box)
        self.past_box = QCheckBox("Past routes")
        self.past_box.setToolTip("Also draw, thin and gray, the routes other traces took")
        self.past_box.toggled.connect(self.refresh_view)
        zoom.addWidget(self.past_box)
        zoom.addStretch(1)
        self.legend = _label("Bold = main route (most probes) · box = a provider's hops · "
                             "amber ≥25 ms or ≥5% lost · red ≥100 ms or ≥10% lost · dashed = no reply",
                             "muted")
        zoom.addWidget(self.legend)
        graph_side = QWidget()
        graph_layout = QVBoxLayout(graph_side)
        graph_layout.setContentsMargins(0, 0, 0, 0)
        graph_layout.addLayout(zoom)
        graph_layout.addWidget(self.view, 1)

        self.details = QFrame()
        self.details.setObjectName("netpathDetails")
        self.details.setMinimumWidth(250)
        details = QVBoxLayout(self.details)
        details.setContentsMargins(14, 12, 14, 12)
        self.details_title = _label("Path", "netpathDetailsTitle")
        self.details_title.setWordWrap(True)
        details.addWidget(self.details_title)
        self.details_grid = QGridLayout()
        self.details_grid.setHorizontalSpacing(12)
        self.details_grid.setVerticalSpacing(8)
        details.addLayout(self.details_grid)
        details.addStretch(1)
        self.detail_rows: list[tuple[QLabel, QLabel]] = []

        splitter = QSplitter(Qt.Orientation.Horizontal)
        splitter.addWidget(graph_side)
        splitter.addWidget(self.details)
        splitter.setStretchFactor(0, 1)
        splitter.setSizes([780, 280])

        self.history = HistoryStrip()
        self.history.colors = self.colors
        self.history.picked.connect(self.show_sweep)
        history_head = QHBoxLayout()
        history_head.addWidget(_label("Path history", "strong"))
        history_head.addStretch(1)
        self.history_text = _label("", "muted")
        history_head.addWidget(self.history_text)

        self.status = _label("", "muted")

        root = QVBoxLayout(self)
        root.setContentsMargins(16, 12, 16, 10)
        root.addLayout(heading)
        root.addWidget(splitter, 1)
        root.addLayout(history_head)
        root.addWidget(self.history)
        root.addWidget(self.status)
        self.setStyleSheet(f"""
            QLabel#netpathTitle {{ font-size: 16px; font-weight: 700; }}
            QLabel#netpathDetailsTitle {{ font-size: 13px; font-weight: 700; }}
            QLabel#netpathHealth {{ font-weight: 600; padding: 3px 10px; border-radius: 10px; }}
            QFrame#netpathDetails {{ background: {self.colors['surface']};
                border: 1px solid {self.colors['border']}; border-radius: 8px; }}
            QGraphicsView {{ background: {self.colors['surface']};
                border: 1px solid {self.colors['border']}; border-radius: 8px; }}
        """)
        self._set_health(None)
        self._show_route()
        self.start()

    # -- tracing -------------------------------------------------------------

    def toggle(self) -> None:
        if self._thread is not None:
            self.stop()
        else:
            self.trace_target()

    def trace_target(self) -> None:
        """Trace the host in the Target box, stopping any trace running."""
        self._detach_thread()
        self.start()

    def start(self) -> None:
        if self._thread is not None:
            return
        target = self.target.text().strip()
        if not target:
            self._set_stopped()
            self.status.setText("Type a host name or IP address and press Trace Now.")
            self.target.setFocus()
            return
        if target != self._target:
            # Another host: its routes are its own, so the history starts again.
            self._target = self._ip = self._title = target
            self.setWindowTitle(f"Net Path - {target}")
            self.heading.setText(target)
            self._clear()
        thread = NetPathThread(target, self.live.isChecked(), self._probe, self.probe_port())
        thread.resolved.connect(self._on_resolved)
        thread.unresolved.connect(self._on_unresolved)
        thread.sweep_ready.connect(self.add_sweep)
        thread.partial_ready.connect(self.show_partial)
        thread.failed.connect(self._on_failed)
        thread.progress.connect(lambda ttl: self.status.setText(f"Tracing {self._ip}: hop {ttl}…"))
        thread.name_ready.connect(self._on_name)
        thread.country_ready.connect(self._on_country)
        thread.org_ready.connect(self._on_org)
        thread.finished.connect(self._on_finished)
        self._thread = thread
        self.button.setText("Stop")
        self._set_health(None)
        self.status.setText(f"Finding {target}…")
        track(thread)
        thread.start()

    def stop(self) -> None:
        self._detach_thread()
        if self.sweeps:
            self._set_health(*self.trace_level(self.graphs[self.shown]))
            self.status.setText(f"Stopped · {self._summary(self.sweeps[-1])}")
        else:
            self._set_stopped()
            self.status.setText("Stopped.")

    def _on_resolved(self, ip: str) -> None:
        self._ip = ip
        self._show_route()

    def _on_unresolved(self, message: str) -> None:
        self._set_stopped()
        self.status.setText(f"Can't trace {self._target}: {message}")

    def probe_port(self) -> int | None:
        """The TCP port probed, or None for ICMP."""
        return self.port.value() if self.mode.currentIndex() == 0 else None

    def probe_text(self) -> str:
        port = self.probe_port()
        return f"TCP SYN to port {port}" if port is not None else "ICMP echo (ping)"

    def _show_route(self) -> None:
        name, address = self._source
        self.route_text.setText(f"Source: {name}{f' ({address})' if address else ''}   →   "
                                f"Destination: {self._ip or '—'}   ·   {self.probe_text()}")

    def _on_mode(self) -> None:
        self.port.setVisible(self.mode.currentIndex() == 0)
        self.restart()

    def _on_port(self) -> None:
        if self.probe_port() != self._traced_port:
            self.restart()

    def restart(self) -> None:
        """Start over with the probes now chosen: their routes differ, so
        the history starts again too."""
        self._detach_thread()
        self._clear()
        self.start()

    def _clear(self) -> None:
        """Forget every trace, e.g. for new probes or a new target."""
        self._traced_port = self.probe_port()
        self.sweeps.clear()
        self.graphs.clear()
        self.everything = None
        self.history_graph = None
        self.expanded.clear()
        self.shown = -1
        self._follow = True
        self._fitted = False
        self.history.healths = []
        self.history.selected = -1
        self.history.update()
        self.history_text.setText("")
        self.items = {}
        self.edge_items = {}
        self.graph = None
        self.view.scene().clear()
        self._set_rows("Path overview", [])
        self._set_health(None)
        self._show_route()

    def _on_failed(self, message: str) -> None:
        """TCP probes can't be used here: fall back to ICMP, saying why."""
        self.mode.blockSignals(True)
        self.mode.setCurrentIndex(1)
        self.mode.blockSignals(False)
        self.port.setVisible(False)
        self.restart()
        self.status.setText(f"{message}. Using ICMP instead.")

    def _detach_thread(self) -> None:
        """Let the running trace finish on its own, its results unheard."""
        thread, self._thread = self._thread, None
        if thread is not None:
            thread.stop()
            for signal in (thread.sweep_ready, thread.progress, thread.name_ready,
                           thread.country_ready, thread.org_ready, thread.failed,
                           thread.resolved, thread.unresolved, thread.finished):
                signal.disconnect()
            # Qt mustn't destroy a running QThread along with this window.
            retire(thread)
        self.button.setText("Trace Now")

    def _on_live(self, on: bool) -> None:
        # Live while stopped only sets how the next Trace Now traces.
        if self._thread is not None:
            self._thread.live = on

    def _on_finished(self) -> None:
        thread, self._thread = self._thread, None
        if thread is not None:
            thread.wait()
        self.button.setText("Trace Now")
        if self.sweeps:
            self.status.setText(self._summary(self.sweeps[-1]))

    def add_sweep(self, result: Sweep) -> None:
        self.sweeps.append(result)
        self.graphs.append(netpath.build_graph([result], self._ip))
        if len(self.sweeps) > HISTORY:
            del self.sweeps[0]
            del self.graphs[0]
            self.shown -= 1
        self.history_graph = netpath.build_graph(self.sweeps, self._ip)
        self.history.healths = [self.trace_level(g)[0] for g in self.graphs]
        status = self._summary(result)
        if self._thread is not None and self._thread.live:
            status += f" · next trace in {LIVE_INTERVAL} s"
        self.status.setText(status)
        if self._follow or self.shown < 0:
            self.show_sweep(len(self.sweeps) - 1)
        else:
            self.history.update()

    def show_partial(self, result: Sweep) -> None:
        """Draw the first trace hop by hop while it runs. Once a trace has
        finished, later ones replace it only when done, so a live view
        doesn't redraw half a path every LIVE_INTERVAL."""
        if self.sweeps:
            return
        graph = netpath.build_graph([result], self._ip)
        self.raw_graph = graph
        orgs = {**self.orgs, **netpath.private_hop_orgs(graph, self.orgs, self._source[1])}
        self.group_of = (netpath.provider_groups(graph, orgs)
                         if self.group_box.isChecked() else {})
        folded = {key: group for key, group in self.group_of.items()
                  if group not in self.expanded}
        collapsed = netpath.collapse(graph, folded)
        self.render(collapsed, collapsed)
        # Keep the growing path in view, and fit the finished one again.
        self.view.fit()
        self._fitted = False

    def _summary(self, result: Sweep) -> str:
        stamp = datetime.fromtimestamp(result.started).strftime("%H:%M:%S")
        return f"Last trace {stamp}: {result.reached_flows()} of {result.flows} probe flows reached {self._ip}"

    # -- showing a trace -------------------------------------------------------

    def show_sweep(self, index: int) -> None:
        if not 0 <= index < len(self.sweeps):
            return
        self.shown = index
        self._follow = index == len(self.sweeps) - 1
        self.history.selected = index
        self.history.update()
        result = self.sweeps[index]
        stamp = datetime.fromtimestamp(result.started).strftime("%Y-%m-%d %H:%M:%S")
        self.history_text.setText(f"Showing {stamp}" + ("" if self._follow else " · click the "
                                                       "last block to follow live"))
        self._set_health(*self.trace_level(self.graphs[index]))
        #: The trace on screen with every hop as traced (boxes hold its keys).
        self.raw_graph = self.graphs[index]
        history = self.history_graph or self.graphs[index]
        # Carriers' inside routers have private addresses and no AS: count
        # them with the provider around them, so the carrier is a box too.
        orgs = {**self.orgs,
                **netpath.private_hop_orgs(history, self.orgs, self._source[1])}
        self.group_of = (netpath.provider_groups(history, orgs)
                         if self.group_box.isChecked() else {})
        folded = {key: group for key, group in self.group_of.items()
                  if group not in self.expanded}
        self.render(netpath.collapse(self.graphs[index], folded),
                    netpath.collapse(history, folded))

    def refresh_view(self) -> None:
        """Draw the trace on screen again, e.g. with new groups or options."""
        if 0 <= self.shown < len(self.sweeps):
            self.show_sweep(self.shown)

    def _on_org(self, address: str, org: str) -> None:
        self.orgs[address] = org
        if org:
            self._regroup.start()

    def _activate(self, key: str) -> None:
        """Open a provider's box, or fold the one a hop belongs to."""
        if key.startswith("group:"):
            self.expanded.add(key)
        elif self.group_of.get(key) in self.expanded:
            self.expanded.discard(self.group_of[key])
        else:
            return
        self.refresh_view()

    def trace_level(self, graph: PathGraph) -> tuple[str, list[str]]:
        """A whole trace's level, its worst hop or link, and why."""
        found = [self.node_condition(graph, key) for key in graph.nodes]
        level = netpath.worst(*(lv for lv, _ in found))
        return level, [reason for lv, reasons in found if lv != netpath.OK for reason in reasons]

    def _set_stopped(self) -> None:
        """The health pill with no trace to judge and none running."""
        self.health.setText("Stopped")
        self.health.setToolTip("")
        self.health.setStyleSheet(f"color: {self.colors['muted']};")

    def _set_health(self, level: str | None, reasons: list[str] | None = None) -> None:
        if level is None:
            self.health.setText("Tracing…")
            self.health.setStyleSheet(f"color: {self.colors['muted']};")
            return
        color = LEVEL_COLORS[level]
        self.health.setText(f"●  {LEVEL_TEXT[level]}")
        self.health.setToolTip("\n".join(reasons or []) or "Every hop and link within thresholds")
        self.health.setStyleSheet(f"color: {color}; background: {LEVEL_FILLS[level]};")

    def render(self, graph: PathGraph, everything: PathGraph | None = None) -> None:
        """Draw `graph`, the trace on screen, in thick lines over the routes
        of every trace in `everything`, which are drawn thin and faint."""
        everything = everything if everything is not None else graph
        self.graph, self.everything = graph, everything
        selected = next((key for key, item in self.items.items() if item.isSelected()), None)
        scene = self.view.scene()
        scene.blockSignals(True)
        scene.clear()
        self.items = {}
        self.edge_items = {}
        past = self.past_box.isChecked()
        positions = layout(everything if past else graph)
        muted = QColor(self.colors["muted"])
        # Routes taken in other traces: thin, under the ones taken now.
        for pair, edge in everything.edges.items() if past else ():
            if pair in graph.edges:
                continue
            silent = everything.nodes[edge.parent].silent or everything.nodes[edge.child].silent
            style = Qt.PenStyle.DashLine if edge.unknown or silent else Qt.PenStyle.SolidLine
            item = scene.addPath(curve(positions[edge.parent], positions[edge.child]),
                                 QPen(muted, 1.5, style))
            item.setZValue(-1)
            item.setOpacity(0.7)
            self.edge_items[pair] = (item, False)
        likely = netpath.likely_edges(graph, everything)
        #: The route most probes took: drawn bold, the other routes faint.
        self.main_route = netpath.main_route(graph, likely)
        main = set(pairwise(self.main_route))
        for edge in graph.edges.values():
            if (edge.parent, edge.child) not in likely:
                continue  # rarely taken: left out, like low transit likelihood
            on_main = (edge.parent, edge.child) in main
            path = curve(positions[edge.parent], positions[edge.child])
            share = len(edge.flows) / max(1, graph.flows)
            silent = graph.nodes[edge.parent].silent or graph.nodes[edge.child].silent
            level, _ = self.edge_condition(graph, edge)
            if edge.unknown or silent:
                color = muted if level == netpath.OK else QColor(LEVEL_COLORS[level])
                pen = QPen(color, 3 if on_main else 1.5, Qt.PenStyle.DashLine)
            elif on_main:
                pen = QPen(QColor(LEVEL_COLORS[level]), 5 + 3 * share)
            else:
                pen = QPen(QColor(LEVEL_COLORS[level]), 1.5 + 2 * share)
            pen.setCapStyle(Qt.PenCapStyle.RoundCap)
            item = scene.addPath(path, pen)
            item.setZValue(0.5 if on_main else 0)
            if not on_main:
                item.setOpacity(0.45)
            known = everything.edges.get((edge.parent, edge.child))
            if known is not None and not edge.unknown:
                item.setToolTip(f"Transit likelihood {len(known.flows) / max(1, everything.flows):.0%}"
                                f" of the probes over {len(self.sweeps)} trace"
                                f"{'s' * (len(self.sweeps) != 1)}")
            self.edge_items[(edge.parent, edge.child)] = (item, True)
            latency = graph.edge_latency(edge)
            if latency is not None:
                self._add_pill(scene, path.pointAtPercent(0.5), format_latency(latency))
        reached = graph.nodes[DESTINATION].rtts
        for key in everything.nodes if past else graph.nodes:
            node = graph.nodes.get(key)
            if node is None:  # a hop of another trace's route
                past = everything.nodes[key]
                name = self.names.get(past.address, "")
                item = NodeItem(key, "router", self.colors["muted"], str(past.ttl),
                                "No reply" if past.silent else name or past.address,
                                past.address if name else "", self.colors, dashed=past.silent)
                item.setOpacity(PAST_OPACITY)
            elif key == SOURCE:
                name, address = self._source
                item = NodeItem(key, "source", BLUE, "PC", name, address, self.colors)
            elif key == DESTINATION:
                level, _ = self.node_condition(graph, key)
                item = NodeItem(key, "destination", LEVEL_COLORS[level], "◎",
                                self._title, self._ip, self.colors, dashed=not reached)
            elif node.members:
                ring = LEVEL_COLORS[self.node_condition(graph, key)[0]]
                routers = [m for m in node.members if not self.raw_graph.nodes[m].silent]
                last = max((self.history_graph.nodes[m].ttl for m in node.members
                            if self.history_graph and m in self.history_graph.nodes),
                           default=node.ttl)
                hops = f"hop {node.ttl}" if last == node.ttl else f"hops {node.ttl}–{last}"
                item = NodeItem(key, "group", ring, str(len(routers) or len(node.members)),
                                node.label, f"{len(routers)} routers · {hops}", self.colors)
                item.setToolTip("Double-click to show this provider's routers")
            elif node.silent:
                item = NodeItem(key, "router", self.colors["muted"], str(node.ttl), "No reply",
                                "", self.colors, dashed=True)
            else:
                ring = LEVEL_COLORS[self.node_condition(graph, key)[0]]
                name = self.names.get(node.address, "")
                item = NodeItem(key, "router", ring, str(node.ttl), name or node.address,
                                node.address if name else "", self.colors)
            item.setPos(positions[key])
            # Later, not in the item's own event handler: redrawing deletes
            # the item, and Qt would carry on with it once the handler returns.
            item.activated.connect(
                lambda key: QTimer.singleShot(0, lambda: self._activate(key)))
            scene.addItem(item)
            self.items[key] = item
        scene.setSceneRect(scene.itemsBoundingRect().adjusted(-40, -40, 40, 40))
        scene.blockSignals(False)
        if selected in self.items:
            self.items[selected].setSelected(True)
        if not self._fitted:
            self._fitted = True
            self.view.fit()
        self._show_details()

    # -- how healthy each hop and link is -------------------------------------

    def _others(self) -> list[PathGraph]:
        """The traces other than the one on screen: what "usual" comes from."""
        return [g for i, g in enumerate(self.graphs) if i != self.shown]

    def usual_node_ms(self, key: str) -> float | None:
        values = [g.nodes[key].latency()[1] for g in self._others()
                  if key in g.nodes and g.nodes[key].latency() is not None]
        return netpath.usual(values)

    def node_condition(self, graph: PathGraph, key: str) -> tuple[str, list[str]]:
        """(level, reasons) for a hop: the link into it slow, flows lost
        after it, or a router saying the host can't be reached.
        Latency is judged on the link, not the hop's round trip, so a slow
        link marks only the hop after it, not every hop beyond."""
        node = graph.nodes[key]
        if key == SOURCE or node.silent:
            return netpath.OK, []
        found: list[tuple[str, str]] = [
            self.edge_condition(graph, edge) for edge in graph.edges.values()
            if edge.child == key and not edge.unknown]
        if key == DESTINATION:
            share = 1 - graph.reached / graph.flows if graph.flows else 0.0
            level = netpath.share_level(share)
            if level != netpath.OK:
                found.append((level, f"{graph.flows - graph.reached} of {graph.flows} "
                                     "flows didn't reach it"))
        else:
            found.append(netpath.loss_level(node))
            if node.unreachable:
                found.append((netpath.CRIT, "Says the host can't be reached"))
        reasons = [reason for _, reason in found if reason]
        return netpath.worst(*(level for level, _ in found)), reasons

    def edge_condition(self, graph: PathGraph, edge) -> tuple[str, str]:
        """(level, reason) for a link: its latency; for the guessed link to
        a host that wasn't reached, the loss where it broke."""
        if edge.unknown:
            return netpath.loss_level(graph.nodes[edge.parent])
        return netpath.latency_level(graph.edge_latency(edge), "Link latency")

    def _add_pill(self, scene: QGraphicsScene, at: QPointF, text: str) -> None:
        label = scene.addSimpleText(text)
        font = QFont(label.font())
        font.setPixelSize(10)
        label.setFont(font)
        label.setBrush(QBrush(QColor(self.colors["ink"])))
        box = label.boundingRect().adjusted(-6, -2, 6, 2)
        pill = QPainterPath()
        pill.addRoundedRect(box, box.height() / 2, box.height() / 2)
        back = scene.addPath(pill, QPen(QColor(self.colors["border"])),
                             QBrush(QColor(self.colors["surface"])))
        offset = QPointF(at.x() - box.width() / 2 + 6, at.y() - box.height() / 2 + 2)
        back.setPos(offset)
        label.setPos(offset)
        back.setZValue(1)
        label.setZValue(1.5)

    # -- details panel ---------------------------------------------------------

    def _show_details(self) -> None:
        graph = getattr(self, "graph", None)
        if graph is None:
            return
        key = next((k for k, item in self.items.items() if item.isSelected()), None)
        if key is None:
            self._details_for_path(graph)
        elif key not in graph.nodes:
            self._details_for_past(key)
        else:
            self._details_for_node(graph, key)

    def _main_route_text(self, graph: PathGraph) -> str:
        """The bold route, hop by hop, and how many probes took all of it."""
        route = getattr(self, "main_route", [])
        steps = []
        for key in route[1:]:
            node = graph.nodes[key]
            if key == DESTINATION:
                steps.append(self._title)
            elif node.members:
                steps.append(node.label)
            elif node.silent:
                steps.append(f"{node.ttl}: *")
            else:
                steps.append(f"{node.ttl}: {node.address}")
        flows = None
        for pair in pairwise(route):
            edge = graph.edges.get(pair)
            if edge is not None:
                flows = set(edge.flows) if flows is None else flows & edge.flows
        share = f"{len(flows or ())} of {graph.flows} probe flows took all of it\n"
        return share + " → ".join(steps) if steps else "—"

    def _details_for_group(self, graph: PathGraph, key: str) -> None:
        """A provider's hops shown as one box."""
        node = graph.nodes[key]
        members = [self.raw_graph.nodes[m] for m in node.members]
        routers = sorted((m for m in members if m.address), key=lambda m: (m.ttl, m.address))
        latency = node.latency()
        listed = "\n".join(f"{m.ttl}: {m.address}" for m in routers[:12])
        if len(routers) > 12:
            listed += f"\n… and {len(routers) - 12} more"
        rows = [
            ("Provider", node.label),
            ("Routers", f"{len(routers)} on this trace"),
            ("Flows", f"{len(node.flows)} of {graph.flows}"),
            ("Latency", format_range(latency) if latency else "—"),
            ("Status", "\n".join(self.node_condition(graph, key)[1]) or "Normal"),
            ("Hops", listed or "—"),
            ("Open", "Double-click the box to show each router"),
        ]
        self._set_rows(node.label, rows)

    def _details_for_past(self, key: str) -> None:
        """A hop the trace on screen didn't pass, from the other traces."""
        node = self.everything.nodes[key]
        seen = sum(1 for g in self.graphs if key in g.nodes)
        latency = node.latency()
        rows = [
            ("Address", node.address or "—"),
            ("Hop", str(node.ttl)),
            ("Seen in", f"{seen} of {len(self.graphs)} traces"),
            ("This trace", "Didn't pass here: a route taken at other times"),
            ("Latency", format_range(latency) if latency else "—"),
        ]
        title = (f"Hop {node.ttl}: no reply" if node.silent
                 else self.names.get(node.address) or node.address)
        self._set_rows(title, rows, self.countries.get(node.address, ""))

    def _set_rows(self, title: str, rows: list[tuple[str, str]], flag: str = "") -> None:
        self.details_title.setText(title)
        while self.details_grid.count():
            widget = self.details_grid.takeAt(0).widget()
            if widget is not None:
                widget.hide()
                widget.deleteLater()
        for row, (name, value) in enumerate(rows):
            key = _label(name, "muted")
            key.setAlignment(Qt.AlignmentFlag.AlignTop)
            text = _label(value)
            text.setWordWrap(True)
            if name == "Country" and flag:
                icon = country_flag(flag)
                if not icon.isNull():
                    holder = QWidget()
                    line = QHBoxLayout(holder)
                    line.setContentsMargins(0, 0, 0, 0)
                    line.setSpacing(6)
                    picture = QLabel()
                    picture.setPixmap(icon.pixmap(16, 12))
                    line.addWidget(picture)
                    line.addWidget(text, 1)
                    self.details_grid.addWidget(key, row, 0)
                    self.details_grid.addWidget(holder, row, 1)
                    continue
            self.details_grid.addWidget(key, row, 0)
            self.details_grid.addWidget(text, row, 1)

    def _details_for_path(self, graph: PathGraph) -> None:
        hops = max((n.ttl for k, n in graph.nodes.items() if k != DESTINATION), default=0)
        # Every router that answered, those inside providers' boxes too.
        routers = sum(1 for key, node in self.raw_graph.nodes.items()
                      if key not in (SOURCE, DESTINATION) and not node.silent)
        splits = sum(1 for k in graph.nodes
                     if sum(1 for e in graph.edges.values() if e.parent == k) > 1)
        end = graph.nodes[DESTINATION].latency()
        rows = [
            ("Destination", f"{self._title}\n{self._ip}" if self._title != self._ip else self._ip),
            ("Reached", f"{graph.reached} of {graph.flows} probe flows"),
            ("Probe", self.probe_text()),
            ("Links", "Each probe has its own source port, so between hops that branch the "
                      "links are inferred from samples" if self.probe_port() is not None
             else "Traced per flow"),
            ("Hops", str(hops)),
            ("Routers", str(routers)),
            ("Branch points", str(splits) if splits else "None: a single route"),
            ("Main route", self._main_route_text(graph)),
            ("Latency", format_range(end) if end else "—"),
        ]
        problems = []
        for key, node in sorted(graph.nodes.items(), key=lambda item: item[1].ttl):
            level, reasons = self.node_condition(graph, key)
            if level != netpath.OK:
                where = (self._title if key == DESTINATION else node.label if node.members
                         else f"Hop {node.ttl} ({node.address})")
                problems.append(f"{where}: {'; '.join(reasons)}")
        rows.append(("Problems", "\n".join(problems[:4]) if problems else "None"))
        self._set_rows("Path overview", rows)

    def _details_for_node(self, graph: PathGraph, key: str) -> None:
        node = graph.nodes[key]
        if node.members:
            self._details_for_group(graph, key)
            return
        if key == SOURCE:
            name, address = self._source
            self._set_rows(name, [("Address", address or "—"), ("Role", "Where the probes start")])
            return
        everywhere = self.everything.nodes.get(key) if self.everything else None
        latency = everywhere.latency() if everywhere else None
        if key == DESTINATION:
            rows = [("Address", self._ip),
                    ("Reached", f"{graph.reached} of {graph.flows} probe flows"),
                    ("Hop", str(node.ttl) if node.rtts else "—"),
                    ("Latency", format_range(latency) if latency else "—"),
                    ("Over", f"the last {len(self.sweeps)} trace{'s' * (len(self.sweeps) != 1)}"),
                    ("Status", "\n".join(self.node_condition(graph, key)[1]) or "Normal")]
            self._set_rows(self._title, rows)
            return
        if node.silent:
            self._set_rows(f"Hop {node.ttl}: no reply", [
                ("Flows", f"{len(node.flows)} of {graph.flows}"),
                ("Note", "This router forwards the probes but doesn't answer them, or its "
                         "answers were lost. That is common and not a fault on its own."),
            ])
            return
        code = self.countries.get(node.address, "")
        parents = [e.parent for e in graph.edges.values() if e.child == key]
        children = [e.child for e in graph.edges.values() if e.parent == key]
        rows = [
            ("Address", node.address),
            ("Name", self.names.get(node.address) or ("—" if node.address in self.names
                                                       else "Looking up…")),
            ("Country", country_label(code) if code else "—"),
            ("Hop", str(node.ttl)),
            ("Flows", f"{len(node.flows)} of {graph.flows}"),
            ("Latency", format_range(latency) if latency else "—"),
            ("Over", f"the last {len(self.sweeps)} trace{'s' * (len(self.sweeps) != 1)}"),
        ]
        if len(children) > 1:
            rows.append(("Splits to", str(len(children)) + " next hops (load balancing)"))
        if len(parents) > 1:
            rows.append(("Joined from", f"{len(parents)} previous hops"))
        usual_ms = self.usual_node_ms(key)
        if usual_ms is not None:
            rows.append(("Usual", f"{usual_ms:.1f} ms (median of the other traces)"))
        rows.append(("Status", "\n".join(self.node_condition(graph, key)[1]) or "Normal"))
        self._set_rows(self.names.get(node.address) or node.address, rows, code)

    def _on_name(self, address: str, name: str) -> None:
        self.names[address] = name
        self._refresh_labels()

    def _on_country(self, address: str, code: str) -> None:
        self.countries[address] = code
        self._show_details()

    def _refresh_labels(self) -> None:
        for item in self.items.values():
            node = self.everything.nodes.get(item.key) if self.everything else None
            if node is not None and item.kind == "router" and self.names.get(node.address):
                item.title, item.subtitle = self.names[node.address], node.address
                item.update()
        self._show_details()

    def closeEvent(self, event) -> None:
        self._detach_thread()
        super().closeEvent(event)


def format_latency(ms: float) -> str:
    return "<1 ms" if ms < 1 else f"{ms:.0f} ms"


def format_range(values: tuple[float, float, float]) -> str:
    low, average, high = values
    return f"{average:.1f} ms avg  ({low:.1f} – {high:.1f})"
