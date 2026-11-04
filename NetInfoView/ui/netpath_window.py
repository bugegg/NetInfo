"""Net Path window: every route to a host as a graph (ping/netpath.py),
traced again every few seconds while Live is on, with a strip of past traces
to step back through."""

from __future__ import annotations

import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime

from PyQt6.QtCore import QCoreApplication, QPointF, QRectF, Qt, QThread, pyqtSignal
from PyQt6.QtGui import (
    QBrush, QColor, QFont, QGuiApplication, QKeySequence, QPainter, QPainterPath, QPen, QShortcut,
)
from PyQt6.QtWidgets import (
    QCheckBox, QFrame, QGraphicsItem, QGraphicsObject, QGraphicsScene, QGraphicsView,
    QGridLayout, QHBoxLayout, QLabel, QMenu, QPushButton, QSplitter, QVBoxLayout, QWidget,
)

from ..ping import hostname, netpath, whois
from ..ping.netpath import DESTINATION, SOURCE, PathGraph, Sweep
from .tracepath_window import country_flag, country_label

#: Seconds between traces while Live is on.
LIVE_INTERVAL = 15
#: Traces kept in the history strip.
HISTORY = 60
NAME_WORKERS = 6

COLUMN_GAP = 124
ROW_GAP = 88
#: The graph is never shrunk below this to fit; past it, scroll.
MIN_FIT_SCALE = 0.7
NODE_RADIUS = 17
END_SIZE = 40

GREEN = "#16a34a"
AMBER = "#d97706"
RED = "#e5383b"
BLUE = "#087dff"
HEALTH_COLORS = {"ok": GREEN, "partial": AMBER, "down": RED}
HEALTH_TEXT = {"ok": "Reachable", "partial": "Partly reachable", "down": "Unreachable"}
HEALTH_FILLS = {"ok": "#dcf6e4", "partial": "#fef3c7", "down": "#fde2e2"}

LIGHT = dict(bg="#f6f7f9", surface="#ffffff", ink="#16191f", muted="#5f6673", border="#e3e5e9")


class NetPathThread(QThread):
    """Traces the path to one host, again every LIVE_INTERVAL seconds while
    `live` is set, and looks up each new hop's name and country."""

    sweep_ready = pyqtSignal(object)
    #: The TTL being probed, for the status line.
    progress = pyqtSignal(int)
    name_ready = pyqtSignal(str, str)
    country_ready = pyqtSignal(str, str)

    def __init__(self, ip: str, live: bool = True, probe=None) -> None:
        super().__init__()
        self._ip = ip
        self.live = live
        self._probe = probe
        self._stop = False
        self._looked_up: set[str] = set()

    def stop(self) -> None:
        self._stop = True

    def run(self) -> None:  # noqa: D102 - QThread entry point
        self._lookups = ThreadPoolExecutor(max_workers=NAME_WORKERS)
        try:
            while not self._stop:
                result = netpath.sweep(self._ip, self._probe, stopped=lambda: self._stop,
                                       on_ttl=self.progress.emit)
                if self._stop:
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
            self._lookups.shutdown(wait=True, cancel_futures=True)

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
    for ttl in sorted(columns):
        keys = columns[ttl]

        def weight(key: str) -> tuple[float, str]:
            ys = [positions[p].y() for p in parents.get(key, []) if p in positions]
            return (sum(ys) / len(ys) if ys else 0.0, key)

        keys.sort(key=weight)
        top = -(len(keys) - 1) * ROW_GAP / 2
        for row, key in enumerate(keys):
            positions[key] = QPointF(ttl * COLUMN_GAP, top + row * ROW_GAP)
    return positions


class NodeItem(QGraphicsObject):
    """A hop (a circle with its hop number), this computer or the host
    (rounded squares), with its name and address underneath."""

    def __init__(self, key: str, kind: str, ring: str, text: str, title: str, subtitle: str,
                 colors: dict[str, str], dashed: bool = False) -> None:
        super().__init__()
        self.key = key
        self.kind = kind  # "router", "source" or "destination"
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

    def _shape_rect(self) -> QRectF:
        size = END_SIZE if self.kind != "router" else NODE_RADIUS * 2
        return QRectF(-size / 2, -size / 2, size, size)

    def boundingRect(self) -> QRectF:
        return QRectF(-70, -END_SIZE / 2 - 4, 140, END_SIZE + 44)

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
        title = metrics.elidedText(self.title, Qt.TextElideMode.ElideRight, 136)
        painter.drawText(QRectF(-70, top, 140, 16), Qt.AlignmentFlag.AlignHCenter, title)
        font.setBold(False)
        painter.setFont(font)
        painter.setPen(QColor(self.colors["muted"]))
        painter.drawText(QRectF(-70, top + 15, 140, 16), Qt.AlignmentFlag.AlignHCenter, self.subtitle)


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
            color = (QColor(HEALTH_COLORS[self.healths[i]]) if i < len(self.healths)
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
    """A non-modal window showing every route to one host."""

    def __init__(self, title: str, ip: str, parent: QWidget | None = None,
                 probe=None, source: tuple[str, str] = ("This computer", ""),
                 live: bool = True) -> None:
        super().__init__(parent, Qt.WindowType.Window)
        self.setAttribute(Qt.WidgetAttribute.WA_DeleteOnClose)
        self.setWindowTitle(f"Net Path - {title}")
        self.resize(1080, 640)
        self._title = title
        self._ip = ip
        self._probe = probe
        self._source = source
        self.sweeps: list[Sweep] = []
        self.shown = -1  # index into sweeps of the trace on screen
        self._follow = True  # show each new trace as it comes
        self.names: dict[str, str] = {}
        self.countries: dict[str, str] = {}
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
        self.heading = _label(f"{title}", "netpathTitle")
        titles.addWidget(self.heading)
        name, address = source
        self.route_text = _label(
            f"Source: {name}{f' ({address})' if address else ''}   →   Destination: {ip}", "muted")
        titles.addWidget(self.route_text)
        heading.addLayout(titles, 1)
        self.health = QLabel("Tracing…")
        self.health.setObjectName("netpathHealth")
        heading.addWidget(self.health)
        self.live = QCheckBox("Live")
        self.live.setChecked(live)
        self.live.setToolTip(f"Trace again every {LIVE_INTERVAL} seconds")
        self.live.toggled.connect(self._on_live)
        heading.addWidget(self.live)
        self.button = QPushButton("Trace Now")
        self.button.clicked.connect(self.start)
        heading.addWidget(self.button)
        self.copy_button = QPushButton("Copy")
        self.copy_button.setToolTip("Copy the selected hop's details, or the whole path as text")
        self.copy_button.clicked.connect(self.copy_selection)
        heading.addWidget(self.copy_button)
        QShortcut(QKeySequence.StandardKey.Copy, self, self.copy_selection)

        self.view = PathView()
        self.view.scene().selectionChanged.connect(self._show_details)
        self.view.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.view.customContextMenuRequested.connect(self._context_menu)
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
        zoom.addStretch(1)
        self.legend = _label("Circle = hop, numbered by distance · line width = share of "
                             "probe flows · dashed = no reply", "muted")
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
        self.start()

    # -- tracing -------------------------------------------------------------

    def start(self) -> None:
        if self._thread is not None:
            return
        thread = NetPathThread(self._ip, self.live.isChecked(), self._probe)
        thread.sweep_ready.connect(self.add_sweep)
        thread.progress.connect(lambda ttl: self.status.setText(f"Tracing {self._ip}: hop {ttl}…"))
        thread.name_ready.connect(self._on_name)
        thread.country_ready.connect(self._on_country)
        thread.finished.connect(self._on_finished)
        self._thread = thread
        self.button.setEnabled(False)
        thread.start()

    def _on_live(self, on: bool) -> None:
        if self._thread is not None:
            self._thread.live = on
        elif on:
            self.start()

    def _on_finished(self) -> None:
        thread, self._thread = self._thread, None
        if thread is not None:
            thread.wait()
        self.button.setEnabled(True)
        if self.sweeps:
            self.status.setText(self._summary(self.sweeps[-1]))

    def add_sweep(self, result: Sweep) -> None:
        self.sweeps.append(result)
        if len(self.sweeps) > HISTORY:
            del self.sweeps[0]
            self.shown -= 1
        self.history.healths = [netpath.health(s) for s in self.sweeps]
        status = self._summary(result)
        if self._thread is not None and self._thread.live:
            status += f" · next trace in {LIVE_INTERVAL} s"
        self.status.setText(status)
        if self._follow or self.shown < 0:
            self.show_sweep(len(self.sweeps) - 1)
        else:
            self.history.update()

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
        self._set_health(netpath.health(result))
        self.render(netpath.build_graph([result], self._ip))

    def _set_health(self, health: str | None) -> None:
        if health is None:
            self.health.setText("Tracing…")
            self.health.setStyleSheet(f"color: {self.colors['muted']};")
            return
        color = HEALTH_COLORS[health]
        self.health.setText(f"●  {HEALTH_TEXT[health]}")
        self.health.setStyleSheet(f"color: {color}; background: {HEALTH_FILLS[health]};")

    def render(self, graph: PathGraph) -> None:
        self.graph = graph
        selected = next((key for key, item in self.items.items() if item.isSelected()), None)
        scene = self.view.scene()
        scene.blockSignals(True)
        scene.clear()
        self.items = {}
        positions = layout(graph)
        muted = QColor(self.colors["muted"])
        for edge in graph.edges.values():
            start, end = positions[edge.parent], positions[edge.child]
            path = QPainterPath(start)
            bend = (end.x() - start.x()) / 2
            path.cubicTo(QPointF(start.x() + bend, start.y()), QPointF(end.x() - bend, end.y()), end)
            share = len(edge.flows) / max(1, graph.flows)
            silent = graph.nodes[edge.parent].silent or graph.nodes[edge.child].silent
            if edge.unknown or silent:
                pen = QPen(muted, 2, Qt.PenStyle.DashLine)
            else:
                color = RED if graph.nodes[edge.child].unreachable else GREEN
                pen = QPen(QColor(color), 2 + 5 * share)
            pen.setCapStyle(Qt.PenCapStyle.RoundCap)
            item = scene.addPath(path, pen)
            item.setZValue(0)
            latency = graph.edge_latency(edge)
            if latency is not None:
                self._add_pill(scene, path.pointAtPercent(0.5), format_latency(latency))
        reached = graph.nodes[DESTINATION].rtts
        for key, node in graph.nodes.items():
            if key == SOURCE:
                name, address = self._source
                item = NodeItem(key, "source", BLUE, "PC", name, address, self.colors)
            elif key == DESTINATION:
                health = ("ok" if graph.reached == graph.flows else "partial" if graph.reached
                          else "down")
                item = NodeItem(key, "destination", HEALTH_COLORS[health], "◎",
                                self._title, self._ip, self.colors, dashed=not reached)
            elif node.silent:
                item = NodeItem(key, "router", self.colors["muted"], str(node.ttl), "No reply",
                                "", self.colors, dashed=True)
            else:
                ring = RED if node.unreachable else GREEN
                name = self.names.get(node.address, "")
                item = NodeItem(key, "router", ring, str(node.ttl), name or node.address,
                                node.address if name else "", self.colors)
            item.setPos(positions[key])
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
        else:
            self._details_for_node(graph, key)

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
        routers = sum(1 for k, n in graph.nodes.items() if k not in (SOURCE, DESTINATION)
                      and not n.silent)
        splits = sum(1 for k in graph.nodes
                     if sum(1 for e in graph.edges.values() if e.parent == k) > 1)
        end = graph.nodes[DESTINATION].latency()
        rows = [
            ("Destination", f"{self._title}\n{self._ip}" if self._title != self._ip else self._ip),
            ("Reached", f"{graph.reached} of {graph.flows} probe flows"),
            ("Hops", str(hops)),
            ("Routers", str(routers)),
            ("Branch points", str(splits) if splits else "None: a single route"),
            ("Latency", format_range(end) if end else "—"),
        ]
        self._set_rows("Path overview", rows)

    def _details_for_node(self, graph: PathGraph, key: str) -> None:
        node = graph.nodes[key]
        if key == SOURCE:
            name, address = self._source
            self._set_rows(name, [("Address", address or "—"), ("Role", "Where the probes start")])
            return
        everywhere = netpath.build_graph(self.sweeps, self._ip).nodes.get(key)
        latency = everywhere.latency() if everywhere else None
        if key == DESTINATION:
            rows = [("Address", self._ip),
                    ("Reached", f"{graph.reached} of {graph.flows} probe flows"),
                    ("Hop", str(node.ttl) if node.rtts else "—"),
                    ("Latency", format_range(latency) if latency else "—"),
                    ("Over", f"the last {len(self.sweeps)} trace{'s' * (len(self.sweeps) != 1)}")]
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
        if node.unreachable:
            rows.append(("Status", "Says the host can't be reached"))
        self._set_rows(self.names.get(node.address) or node.address, rows, code)

    def _on_name(self, address: str, name: str) -> None:
        self.names[address] = name
        self._refresh_labels()

    def _on_country(self, address: str, code: str) -> None:
        self.countries[address] = code
        self._show_details()

    def _refresh_labels(self) -> None:
        for item in self.items.values():
            node = getattr(self, "graph", None) and self.graph.nodes.get(item.key)
            if node is not None and item.kind == "router" and self.names.get(node.address):
                item.title, item.subtitle = self.names[node.address], node.address
                item.update()
        self._show_details()

    # -- copying ---------------------------------------------------------------

    def selected_key(self) -> str | None:
        return next((k for k, item in self.items.items() if item.isSelected()), None)

    def copy_selection(self) -> str:
        """The selected hop's details, or with none selected the whole path,
        onto the clipboard; returns what was copied."""
        key = self.selected_key()
        text = self.details_text() if key is not None else self.path_text()
        if text:
            QGuiApplication.clipboard().setText(text)
            self.status.setText("Copied " + ("the hop's details" if key is not None else "the path"))
        return text

    def details_text(self) -> str:
        """The details panel as "Name: value" lines, under its title."""
        lines = [self.details_title.text()]
        grid = self.details_grid
        for row in range(grid.rowCount()):
            cells = []
            for column in (0, 1):
                item = grid.itemAtPosition(row, column)
                widget = item.widget() if item is not None else None
                if widget is not None and not isinstance(widget, QLabel):
                    widget = next((w for w in widget.findChildren(QLabel) if w.text()), None)
                cells.append(widget.text().replace("\n", " ") if widget is not None else "")
            if any(cells):
                lines.append(f"{cells[0]}: {cells[1]}")
        return "\n".join(lines)

    def path_text(self) -> str:
        """The trace on screen as a table, one line per hop, like traceroute."""
        graph = getattr(self, "graph", None)
        if graph is None or not 0 <= self.shown < len(self.sweeps):
            return ""
        result = self.sweeps[self.shown]
        stamp = datetime.fromtimestamp(result.started).strftime("%Y-%m-%d %H:%M:%S")
        name, address = self._source
        target = f"{self._title} ({self._ip})" if self._title != self._ip else self._ip
        lines = [
            f"Net Path to {target}, {stamp}",
            f"From {name}{f' ({address})' if address else ''}: "
            f"{graph.reached} of {graph.flows} probe flows reached the host",
            "",
            f"{'Hop':<4} {'Address':<16} {'Name':<32} {'Avg latency':>11}  Flows",
        ]
        rows = [n for k, n in graph.nodes.items() if k != SOURCE]
        rows.sort(key=lambda n: (n.key == DESTINATION, n.ttl, -len(n.flows), n.address))
        for node in rows:
            if node.key == DESTINATION:
                if not node.rtts:
                    lines.append(f"{'-':<4} {self._ip:<16} (not reached)")
                    continue
                address, label = self._ip, self._title if self._title != self._ip else ""
            elif node.silent:
                address, label = "*", "No reply"
            else:
                address, label = node.address, self.names.get(node.address, "")
            latency = node.latency()
            average = f"{latency[1]:.1f} ms" if latency else ""
            lines.append(f"{node.ttl:<4} {address:<16} {label[:32]:<32} {average:>11}  "
                         f"{len(node.flows)}/{graph.flows}")
        return "\n".join(lines)

    def _context_menu(self, position) -> None:
        item = self.view.itemAt(position)
        while item is not None and not isinstance(item, NodeItem):
            item = item.parentItem()
        menu = QMenu(self)
        if item is not None:
            self.view.scene().clearSelection()
            item.setSelected(True)
            node = self.graph.nodes[item.key]
            if item.key == DESTINATION:
                address, name = self._ip, self._title
            elif item.key == SOURCE:
                name, address = self._source
            else:
                address, name = node.address, self.names.get(node.address, "")
            if address:
                menu.addAction("Copy Address",
                               lambda: QGuiApplication.clipboard().setText(address))
            if name and name != address:
                menu.addAction("Copy Name", lambda: QGuiApplication.clipboard().setText(name))
            menu.addAction("Copy Details",
                           lambda: QGuiApplication.clipboard().setText(self.details_text()))
            menu.addSeparator()
        menu.addAction("Copy Path", lambda: QGuiApplication.clipboard().setText(self.path_text()))
        menu.exec(self.view.viewport().mapToGlobal(position))

    def closeEvent(self, event) -> None:
        thread, self._thread = self._thread, None
        if thread is not None:
            thread.stop()
            for signal in (thread.sweep_ready, thread.progress, thread.name_ready,
                           thread.country_ready, thread.finished):
                signal.disconnect()
            # Qt mustn't destroy a running QThread along with this window.
            thread.setParent(QCoreApplication.instance())
            thread.finished.connect(thread.deleteLater)
        super().closeEvent(event)


def format_latency(ms: float) -> str:
    return "<1 ms" if ms < 1 else f"{ms:.0f} ms"


def format_range(values: tuple[float, float, float]) -> str:
    low, average, high = values
    return f"{average:.1f} ms avg  ({low:.1f} – {high:.1f})"
