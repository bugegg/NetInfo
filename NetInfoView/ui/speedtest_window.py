"""Speed Test window (ping/speedtest.py): a speedometer gauge beside the
result cards and the session's earlier runs,
laid out after nPerf's test page."""

from __future__ import annotations

import functools
import math
import re
import statistics
import tempfile
import threading
import urllib.parse
from datetime import datetime
from pathlib import Path

from PyQt6.QtCore import (
    QEasingCurve, QEvent, QPointF, QRectF, QSize, Qt, QThread, QVariantAnimation, pyqtSignal,
)
from PyQt6 import sip
from PyQt6.QtGui import (
    QColor, QConicalGradient, QFont, QFontMetricsF, QPainter, QPainterPath, QPalette, QPen,
)
from PyQt6.QtWidgets import (
    QApplication,
    QComboBox,
    QFrame,
    QGridLayout,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QPushButton,
    QSizePolicy,
    QToolButton,
    QTreeWidget,
    QTreeWidgetItem,
    QVBoxLayout,
    QWidget,
)

from . import glyphs
from ..ping import device_link, logos, provider, speedtest
from ..ping.device_link import rssi_text, strength, wifi_generation
from ..ping.speedtest import CLOUDFLARE, ServerSpec, SpeedResult, SpeedTestOptions
from ..ping.speed_locations import locate
from . import fonts
from .provider_badge import LogoStore, ProviderBadge, signal_pixmap
from .server_picker import ServerPicker, same_choice
from .threads import retire, track

BLUE = "#087dff"     # download
PURPLE = "#8b5cf6"   # upload
GREEN = "#16a34a"    # ping, jitter, success
RED = "#e5383b"
AMBER = "#d97706"

#: (label, seconds per direction).
DURATIONS = (("Quick · 5 s", 5.0), ("Standard · 14 s", 14.0), ("Long · 20 s", 20.0))
DEFAULT_WINDOW = QSize(1060, 820)
#: The gauge-and-cards panel grows no taller than this.
TOP_PANEL_MAX = 420
#: The content shrinks to fit down to this size (see SpeedTestWindow._rescale).
MIN_WINDOW = QSize(760, 560)


#: Gauge scale marks in Mbps; the scale grows to the next range once a
#: reading goes past its end.
#: The gauge's marks in ms while it shows ping.
PING_MARKS = (0, 5, 10, 20, 50, 100, 200, 500, 1000)
SCALES = (
    (0, 5, 10, 25, 50, 100, 250, 500, 1000),
    (0, 10, 50, 100, 250, 500, 1000, 2500, 5000, 10000),
)
ARC_START = 240.0   # degrees, Qt's counter-clockwise from 3 o'clock
ARC_SPAN = -300.0
#: The reading's colour along the ring (0 = empty, 1 = full), per phase.
GAUGE_COLORS = {
    "download": ((0.0, "#2f6fe4"), (0.35, "#3fa7b8"), (0.65, "#5fd672"), (1.0, "#b3c93a")),
    "upload": ((0.0, "#6d3fe0"), (0.5, "#a35cf0"), (1.0, "#e9559b")),
    "ping": ((0.0, "#16a34a"), (0.5, "#84cc16"), (1.0, "#f59e0b")),
}
#: How much of each new reading (already a rolling second) the needle moves by.
NEEDLE_SMOOTHING = 0.6


class NeedleSmoother:
    """What the needle and card show while a transfer runs: through the
    ramp, the last second's speed eased in (it climbs as TCP opens up);
    after it, the average so far, which settles towards the result instead
    of swinging with every Wi-Fi hiccup. The result itself is computed apart
    (speedtest.summarize), so this changes only the display."""

    def __init__(self, ramp_s: float, alpha: float = NEEDLE_SMOOTHING) -> None:
        self.ramp_s = ramp_s
        self.alpha = alpha
        self.value = 0.0
        self._sum = 0.0
        self._count = 0

    def add(self, seconds: float, mbps: float) -> float:
        if seconds < self.ramp_s:
            target = mbps
        else:
            self._sum += mbps
            self._count += 1
            target = self._sum / self._count
        self.value += (target - self.value) * self.alpha
        return self.value


def palette(dark: bool) -> dict[str, str]:
    if dark:
        return dict(bg="#121821", panel="#1a222e", border="#2c3747", ink="#e8edf5",
                    muted="#98a5b8", grid="#243042", track="#475569", field="#121821",
                    down="#13253d", up="#211c3a", ok="#132a20", head="#1f2835",
                    button="#243042", pill_ok="#14361f", pill_run="#13253d",
                    pill_bad="#3a1a1c", pill_idle="#243042")
    return dict(bg="#f5f6f8", panel="#ffffff", border="#e3e6eb", ink="#111827",
                muted="#5f6673", grid="#eef0f3", track="#334155", field="#ffffff",
                down="#eaf3ff", up="#f3eeff", ok="#ecf8f0", head="#f7f8fa",
                button="#ffffff", pill_ok="#dcf5e3", pill_run="#e3efff",
                pill_bad="#fde4e4", pill_idle="#eef0f3")


def format_mbps(value: float | None) -> str:
    if value is None:
        return "–"
    return f"{value:,.2f}"  # 334.48, as speedtest.net shows it


def format_ms(value: float | None) -> str:
    return "–" if value is None else f"{value:.0f}" if value >= 10 else f"{value:.1f}"


def tls_text(tls: str) -> str:
    return tls.replace("TLSv", "TLS ") if tls else ""


def server_text(meta: dict[str, str], show_ip: bool = True) -> str:
    if not meta:
        return ""
    where = meta.get("colo", "")
    if meta.get("loc") and meta.get("loc") != where:
        where = f"{where} ({meta['loc']})" if where else meta["loc"]
    parts = [meta.get("host", ""), where, tls_text(meta.get("tls", ""))]
    if show_ip and meta.get("ip"):
        parts.append(f"your IP {meta['ip']}")
    return "  ·  ".join(p for p in parts if p)


def result_text(result: SpeedResult) -> str:
    """Plain-text summary for Copy results."""
    lines = [f"Speed test  {datetime.now():%Y-%m-%d %H:%M}"]
    if result.meta:
        lines.append(f"Server      {server_text(result.meta)}")
    lines.append(f"Ping        {format_ms(result.latency_ms)} ms   "
                 f"jitter {format_ms(result.jitter_ms)} ms")
    for name in ("download", "upload"):
        t = getattr(result, name)
        if t is not None:
            loaded = (f"   loaded ping {format_ms(t.loaded_latency_ms)} ms"
                      if t.loaded_latency_ms is not None else "")
            lines.append(f"{name.capitalize():<11} {format_mbps(t.mbps)} Mbps   "
                         f"peak {format_mbps(t.peak_mbps)}{loaded}")
    if result.error:
        lines.append(f"Error       {result.error}")
    return "\n".join(lines)


# ------------------------------------------------------------------ thread


def from_thread(slot):
    """For a slot a background thread's signal calls: if the window is being
    torn down while the answer arrives (Qt deletes its widgets one by one),
    drop the answer rather than let PyQt abort the app on the error."""
    @functools.wraps(slot)
    def guarded(self, *args):
        if sip.isdeleted(self):
            return None
        try:
            return slot(self, *args)
        except RuntimeError as error:
            if "has been deleted" in str(error):
                return None
            raise
    return guarded


class SpeedTestThread(QThread):
    phase = pyqtSignal(str)
    sample = pyqtSignal(str, float, float)  # phase, seconds, Mbps
    progress = pyqtSignal(object)           # SpeedResult so far, after each phase
    done = pyqtSignal(object)               # SpeedResult

    def __init__(self, options: SpeedTestOptions) -> None:
        super().__init__()
        self._options = options
        self._stop = threading.Event()

    def stop(self) -> None:
        self._stop.set()

    def run(self) -> None:
        result = speedtest.run_test(self._options, self.phase.emit, self.sample.emit,
                                    self._stop, self.progress.emit)
        self.done.emit(result)


class ServerListThread(QThread):
    """Every server, each with how near it is."""
    loaded = pyqtSignal(object)  # list[(ServerSpec, ms | None)]
    #: The servers reached so far, ranked, while the rest are still timed.
    partial = pyqtSignal(object)
    #: Then the nearest few re-ranked by WebSocket ping (speedtest.ws_best),
    #: what Automatic tests, as speedtest.net chooses.
    picked = pyqtSignal(object)  # list[(ServerSpec, ms)]

    def stop(self) -> None:
        pass  # finishes within a few seconds on its own

    def run(self) -> None:
        try:
            ranked = speedtest.rank_servers(speedtest.fetch_servers(),
                                            on_progress=self.partial.emit)
            self.loaded.emit(ranked)
            best = speedtest.ws_best(ranked)
            if best:
                self.picked.emit(best)
        except RuntimeError:  # the app quit while it ran: nobody to tell
            pass
        except Exception:
            # An exception escaping QThread.run() aborts the whole app (PyQt6);
            # an empty list just shows "Couldn't load the server list".
            try:
                self.loaded.emit([])
            except RuntimeError:
                pass


class DeviceThread(QThread):
    """This machine's own link (ping/device_link.py), read again and again
    while the window is open, so the Wi-Fi rate, signal and band stay live
    (and a switch between Wi-Fi and Ethernet shows up)."""
    found = pyqtSignal(object)  # DeviceLink, each time it's read

    #: Pause between reads. macOS's system_profiler itself takes ~5 s, so a
    #: Mac updates about every 7 s; on Windows netsh answers at once (the
    #: slow PowerShell adapter lookup is cached), so about every 2 s.
    INTERVAL_S = 2.0

    def __init__(self) -> None:
        super().__init__()
        self._stop = threading.Event()

    def stop(self) -> None:
        self._stop.set()

    def run(self) -> None:
        previous = None
        while not self._stop.is_set():
            link = device_link.carry_over(previous, device_link.device_link())
            previous = link
            if self._stop.is_set():
                break
            self.found.emit(link)
            if self._stop.wait(self.INTERVAL_S):
                break


class ProviderThread(QThread):
    """Whether the Internet is reachable, and who provides it."""
    found = pyqtSignal(bool, object)  # online, Provider | None

    def stop(self) -> None:
        pass

    def run(self) -> None:
        online, found = provider.fetch_provider()
        self.found.emit(online, found)


# ----------------------------------------------------------------- widgets


class Themed:
    """Mixin: the window's colours, light or dark."""

    def colors(self) -> dict[str, QColor]:
        window = self.window()
        c = getattr(window, "theme", None) or palette(False)
        return {k: QColor(v) for k, v in c.items()}


class Gauge(Themed, QWidget):
    """Speedometer: a broad 300° ring with evenly spaced marks, filled in a
    gradient up to the reading, which sits in the middle."""

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setMinimumSize(150, 120)
        self.value = 0.0
        self.phase = ""
        self.color = QColor(BLUE)
        self.marks = SCALES[0]
        self._sweep = QVariantAnimation(self)
        self._sweep.setEasingCurve(QEasingCurve.Type.InOutCubic)
        self._sweep.valueChanged.connect(lambda v: self._move(float(v)))
        self._then = None

    def _move(self, value: float) -> None:
        self.value = max(0.0, value)
        self.update()

    def sweep_to(self, value: float, ms: int = 700, then=None) -> None:
        """Swing the needle to `value`, then call `then`."""
        self._sweep.stop()
        try:
            self._sweep.finished.disconnect()
        except TypeError:
            pass
        if then is not None:
            self._sweep.finished.connect(then)
        self._sweep.setDuration(ms)
        self._sweep.setStartValue(float(self.value))
        self._sweep.setEndValue(float(value))
        self._sweep.start()

    def set_value(self, value: float, phase: str | None = None) -> None:
        self._sweep.stop()
        if phase is not None:
            self.phase = phase
            self.color = QColor({"upload": PURPLE, "ping": GREEN}.get(phase, BLUE))
            if phase == "ping":
                self.marks = PING_MARKS
            elif self.marks is PING_MARKS:
                self.marks = SCALES[0]
        self.value = max(0.0, value)
        if (self.marks is not PING_MARKS and self.value > self.marks[-1]
                and self.marks is not SCALES[-1]):
            self.marks = SCALES[-1]
        self.update()

    @property
    def ping(self) -> bool:
        return self.marks is PING_MARKS

    def reset(self) -> None:
        self._sweep.stop()
        self.value, self.phase, self.marks = 0.0, "", SCALES[0]
        self.update()

    def fraction(self, value: float) -> float:
        """Where `value` sits along the arc: equal steps between the marks."""
        marks = self.marks
        if value <= 0:
            return 0.0
        if value >= marks[-1]:
            return 1.0
        step = 1 / (len(marks) - 1)
        for i in range(len(marks) - 1):
            lo, hi = marks[i], marks[i + 1]
            if value <= hi:
                return step * (i + (value - lo) / (hi - lo))
        return 1.0

    def _band(self, center: QPointF, outer: float, inner: float,
              start: float, span: float) -> QPainterPath:
        """The ring between radii `inner` and `outer`, from `start` degrees
        through `span` (negative: clockwise)."""
        o = QRectF(center.x() - outer, center.y() - outer, 2 * outer, 2 * outer)
        i = QRectF(center.x() - inner, center.y() - inner, 2 * inner, 2 * inner)
        path = QPainterPath()
        path.arcMoveTo(o, start)
        path.arcTo(o, start, span)
        path.arcTo(i, start + span, -span)
        path.closeSubpath()
        return path

    def paintEvent(self, event):
        c = self.colors()
        dark = c["bg"].lightness() < 128
        p = QPainter(self)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        # The ring opens at the bottom: its ends reach sin(60°) of the
        # radius below the centre, plus the outline.
        R = max(40.0, min((self.width() - 16) / 2, (self.height() - 12) / 1.88))
        center = QPointF(self.width() / 2, 6 + R)
        thick = R * 0.27
        inner = R - thick
        sweeping = self._sweep.state() == QVariantAnimation.State.Running
        live = self.phase in ("download", "upload", "ping") or sweeping
        frac = self.fraction(self.value)

        outline = QColor("#0b1220" if dark else "#1f2a37")
        track = QColor("#334155" if dark else "#c3cad3")
        # The empty track, outlined.
        p.setPen(QPen(outline, max(1.0, R / 160), cap=Qt.PenCapStyle.RoundCap,
                      join=Qt.PenJoinStyle.RoundJoin))
        p.setBrush(track)
        p.drawPath(self._band(center, R, inner, ARC_START, ARC_SPAN))

        # The reading: a band coloured along its length, lighter in the middle.
        if frac > 0:
            gradient = QConicalGradient(center, ARC_START)
            stops = GAUGE_COLORS.get(self.phase if self.phase in GAUGE_COLORS else "download")
            gradient.setColorAt(0.0, QColor(stops[0][1]))
            for f, color in stops:
                gradient.setColorAt(1 - f * abs(ARC_SPAN) / 360, QColor(color))
            p.setPen(Qt.PenStyle.NoPen)
            p.setBrush(gradient)
            gap = max(1.5, R / 90)
            p.drawPath(self._band(center, R - gap, inner + gap, ARC_START, ARC_SPAN * frac))
            p.setBrush(QColor(255, 255, 255, 60 if dark else 120))
            p.drawPath(self._band(center, R - thick * 0.22, inner + thick * 0.22,
                                  ARC_START, ARC_SPAN * frac))

        # Marks: a tick at the rim, the value inside the band.
        small = QFont(self.font())
        small.setPixelSize(max(9, int(R / 13)))
        small.setWeight(QFont.Weight.DemiBold)
        p.setFont(small)
        ink = c["ink"]
        for i, mark in enumerate(self.marks):
            angle = math.radians(ARC_START + ARC_SPAN * i / (len(self.marks) - 1))
            cos, sin = math.cos(angle), -math.sin(angle)
            p.setPen(QPen(outline, max(1.0, R / 140)))
            p.drawLine(QPointF(center.x() + R * cos, center.y() + R * sin),
                       QPointF(center.x() + (R - thick * 0.22) * cos,
                               center.y() + (R - thick * 0.22) * sin))
            if self.ping:
                text = "1s" if mark == 1000 else str(mark)
            else:
                text = f"{mark // 1000}G" if mark >= 1000 and mark % 1000 == 0 else str(mark)
            # The end labels step in from the ring's square ends.
            last = len(self.marks) - 1
            inward = 7 if i == 0 else -7 if i == last else 0  # degrees along the ring
            label = math.radians(ARC_START + ARC_SPAN * i / last - inward)
            r = R - thick * 0.55
            pt = QPointF(center.x() + r * math.cos(label), center.y() - r * math.sin(label))
            p.setPen(ink)
            p.drawText(QRectF(pt.x() - 30, pt.y() - 10, 60, 20), Qt.AlignmentFlag.AlignCenter, text)

        # The reading in the middle.
        big = QFont(self.font())
        big.setPixelSize(max(14, int(inner * 0.5)))
        big.setWeight(QFont.Weight.Bold)
        p.setFont(big)
        p.setPen(ink)
        text = ((format_ms(self.value) if self.ping else format_mbps(self.value))
                if live else "–")
        # Two decimals make "1,234.56": shrink the reading to fit the dial.
        room = 1.7 * inner
        width = QFontMetricsF(big).horizontalAdvance(text)
        if width > room:
            big.setPixelSize(max(12, int(big.pixelSize() * room / width)))
            p.setFont(big)
        p.drawText(QRectF(center.x() - inner, center.y() - inner * 0.42, 2 * inner, inner * 0.6),
                   Qt.AlignmentFlag.AlignCenter, text)
        unit_font = QFont(self.font())
        unit_font.setPixelSize(max(11, int(inner * 0.17)))
        p.setFont(unit_font)
        unit = "ms" if self.ping else "Mbps"
        p.setPen(c["muted"])
        p.drawText(QRectF(center.x() - inner, center.y() + inner * 0.2, 2 * inner, inner * 0.25),
                   Qt.AlignmentFlag.AlignCenter,
                   f"{unit} {self.phase}" if live and not sweeping else unit)


def _chevron_file(color: str) -> str:
    """A combo box's arrow has to come from a file: write the chevron glyph
    to the temp folder once per colour."""
    path = Path(tempfile.gettempdir()) / f"netinfoview-chevron-{color.lstrip('#')}.svg"
    if not path.exists():
        path.write_bytes(glyphs.svg("chevron", color, 2.2))
    return path.as_posix()


def format_link(mbps: float | None) -> str:
    if not mbps:
        return "–"
    if mbps >= 1000:
        return f"{mbps / 1000:.1f} Gbps".replace(".0 ", " ")
    return f"{mbps:,.0f} Mbps"


def server_domain(spec: ServerSpec) -> str:
    """The website whose logo stands for a server's provider."""
    where = locate(spec)
    return logos.domain_for(where.sponsor, spec.sponsor_url, spec.url)


class MiddleElidedLabel(QLabel):
    """A label that shortens itself in the middle ("2407:b1c0:…:6719:c108")
    rather than cutting the end off when it doesn't fit."""

    def __init__(self, text: str = "", name: str = "") -> None:
        super().__init__(text)
        if name:
            self.setObjectName(name)

    def minimumSizeHint(self) -> QSize:
        return QSize(40, super().minimumSizeHint().height())

    def paintEvent(self, event) -> None:
        painter = QPainter(self)
        painter.setPen(self.palette().color(QPalette.ColorRole.WindowText))
        painter.setFont(self.font())
        text = painter.fontMetrics().elidedText(self.text(), Qt.TextElideMode.ElideMiddle,
                                                self.contentsRect().width())
        painter.drawText(self.contentsRect(), int(self.alignment()) or
                         int(Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter), text)


def _label(text: str = "", name: str = "") -> QLabel:
    widget = QLabel(text)
    if name:
        widget.setObjectName(name)
    return widget


def _icon_label(name: str, color: str, size: int = 18) -> QLabel:
    widget = QLabel()
    widget.setPixmap(glyphs.pixmap(name, color, size))
    widget.setFixedSize(size + 2, size + 2)
    return widget


class Card(QFrame):
    """One result on a tinted tile: icon and title, value, then notes."""

    def __init__(self, title: str, icon: str, color: str, tone: str) -> None:
        super().__init__()
        self.setObjectName("card")
        self.setProperty("tone", tone)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(16, 12, 16, 12)
        layout.setSpacing(2)
        head = QHBoxLayout()
        head.setSpacing(8)
        head.addWidget(_icon_label(icon, color))
        head.addWidget(_label(title, "cardTitle"))
        head.addStretch(1)
        layout.addLayout(head)
        layout.addSpacing(4)
        self.value = _label("–", "cardValue")
        self.note = _label(" \n ", "cardNote")
        layout.addWidget(self.value)
        layout.addWidget(self.note)
        layout.addStretch(1)

    def set(self, value: str, note: str = " \n ") -> None:
        self.value.setText(value)
        self.note.setText(note)
        # When the notes are hidden (a short window), they still show on hover.
        self.setToolTip(note.strip())


class ServerField(QPushButton):
    """Looks like a combo box: the chosen server's flag and name."""

    def __init__(self) -> None:
        super().__init__()
        self.setObjectName("serverField")
        self.setCursor(Qt.CursorShape.PointingHandCursor)
        self.setMinimumWidth(180)
        row = QHBoxLayout(self)
        row.setContentsMargins(10, 0, 10, 0)
        row.setSpacing(8)
        self.lead = ProviderBadge(26)
        self.text = QLabel()
        self.chevron = QLabel()
        for w in (self.lead, self.text, self.chevron):
            w.setAttribute(Qt.WidgetAttribute.WA_TransparentForMouseEvents)
        row.addWidget(self.lead)
        row.addWidget(self.text, 1)
        row.addWidget(self.chevron)
        self._choice: ServerSpec | str = CLOUDFLARE
        self._colo = ""

    def sizeHint(self) -> QSize:
        return QSize(280, 36)

    def set_colors(self, ink: str, muted: str, surface: str = "#ffffff",
                   border: str = "#e3e6eb") -> None:
        self.chevron.setPixmap(glyphs.pixmap("chevron", muted, 16))
        self._muted = muted
        self.lead.set_colors(surface, border)
        self.show_choice(self._choice, self._colo)

    def show_choice(self, choice: ServerSpec | str, colo: str = "") -> None:
        self._choice, self._colo = choice, colo
        muted = getattr(self, "_muted", "#5f6673")
        #: Set by the window: the nearest server, which Automatic tests.
        nearest = getattr(self, "nearest", None)
        if isinstance(choice, ServerSpec) and choice.url == CLOUDFLARE.url:
            if nearest is not None and not colo:
                # Automatic shows the server it will use, not "Automatic".
                where = locate(nearest)
                self.lead.set_provider(where.sponsor or where.country, server_domain(nearest),
                                       getattr(self, "logos", None))
                self.text.setText(where.short)
                self.setToolTip(f"Automatic: the nearest server\n{nearest.name}\n{nearest.url}")
            else:
                self.lead.set_pixmap(glyphs.pixmap("globe", BLUE, 16))
                self.text.setText(f"Automatic · {colo}" if colo else "Automatic (Cloudflare)")
                self.setToolTip("Cloudflare's nearest data centre, until the nearest "
                                "server in Thailand is found")
        elif isinstance(choice, ServerSpec):
            where = locate(choice)
            self.lead.set_provider(where.sponsor or where.country, server_domain(choice),
                                   getattr(self, "logos", None))
            self.text.setText(where.short)
            self.setToolTip(f"{choice.name}\n{choice.url}")
        else:
            self.lead.set_pixmap(glyphs.pixmap("link", muted, 16))
            host = urllib.parse.urlsplit(choice).hostname or choice
            self.text.setText(host)
            self.setToolTip(choice)


class Panel(QFrame):
    def __init__(self) -> None:
        super().__init__()
        self.setObjectName("panel")


# ------------------------------------------------------------------ window


class SpeedTestWindow(QWidget):
    """A non-modal window: pick a server and a mode, then Start."""

    HISTORY_COLUMNS = ("Time", "Server", "Download", "Upload", "Ping", "Jitter")

    def __init__(self, parent: QWidget | None = None, load_servers: bool = True) -> None:
        super().__init__(parent, Qt.WindowType.Window)
        self.setObjectName("speedTest")
        self.setAttribute(Qt.WidgetAttribute.WA_DeleteOnClose)
        self.setWindowTitle("Speed Test")
        self.setMinimumSize(MIN_WINDOW)
        self.resize(DEFAULT_WINDOW)
        self._thread: SpeedTestThread | None = None
        self._result: SpeedResult | None = None
        self._phase = ""
        self._pings: list[float] = []
        self._show_ip = False
        self.theme = palette(self._dark())
        self._needle = NeedleSmoother(SpeedTestOptions().ramp_s)

        title = _label("Speed Test", "pageTitle")
        subtitle = _label("Measure your connection performance.", "pageSubtitle")

        # The connection: a status pill by the title, then two cards, the
        # Internet side (provider, public IP) and this device's own link.
        self.connection = QLabel()
        self.connection.setObjectName("connectionPill")
        self.connection.setTextFormat(Qt.TextFormat.RichText)
        self._build_connection_cards()
        self._provider_thread: ProviderThread | None = None
        self._device_thread: DeviceThread | None = None
        self._link = None  # the last DeviceLink read
        self._public_ipv4 = ""
        self._public_ipv6 = ""
        self._local_ip = ""

        self._choice: ServerSpec | str = CLOUDFLARE
        #: What Automatic (the CLOUDFLARE choice) chooses among: the nearest
        #: few Ookla servers once the list is timed (speedtest.nearest_ookla).
        self._candidates: tuple[ServerSpec, ...] = ()
        #: Providers' logos, from their websites (ping/logos.py).
        self.logos = LogoStore(self)
        self.server = ServerField()
        self.server.logos = self.logos
        self.server.setToolTip("Click to choose where the test runs: Automatic (the nearest "
                               "server in Thailand, as speedtest.net picks), a server in "
                               "Thailand or abroad, or your own server's URL")
        self.server.clicked.connect(self.open_picker)
        self.duration = QComboBox()
        for text, seconds in DURATIONS:
            self.duration.addItem(text, seconds)
        self.duration.setCurrentIndex(1)
        self.duration.setMinimumWidth(130)
        self.duration.setToolTip("How long each of download and upload runs. "
                                 "A 1 Gbps line moves about 1.2 GB in 10 s.")
        self.copy_button = QPushButton("Copy results")
        self.copy_button.setObjectName("secondary")
        self.copy_button.setEnabled(False)
        self.copy_button.clicked.connect(self.copy)
        self.button = QPushButton("Start")
        self.button.setObjectName("primary")
        self.button.setDefault(True)
        self.button.clicked.connect(self._toggle)
        for b in (self.copy_button, self.button):
            b.setIconSize(QSize(16, 16))
            b.setCursor(Qt.CursorShape.PointingHandCursor)
        divider = QFrame()
        divider.setObjectName("divider")
        divider.setFixedSize(1, 26)

        # Server and mode, then the buttons: side by side, or the buttons on
        # a row of their own when the window is narrow.
        self._choices = QWidget()
        choices = QHBoxLayout(self._choices)
        choices.setContentsMargins(0, 0, 0, 0)
        choices.setSpacing(10)
        choices.addWidget(_label("Server:"))
        choices.addWidget(self.server, 2)
        choices.addSpacing(8)
        choices.addWidget(_label("Mode:"))
        choices.addWidget(self.duration, 1)
        self._actions = QWidget()
        actions = QHBoxLayout(self._actions)
        actions.setContentsMargins(0, 0, 0, 0)
        actions.setSpacing(10)
        actions.addStretch(1)
        actions.addWidget(self.copy_button)
        actions.addWidget(self.button)
        self._divider = divider
        controls = QGridLayout()
        controls.setHorizontalSpacing(20)
        controls.setVerticalSpacing(10)
        self._controls = controls
        self._stacked: bool | None = None
        self._arrange_controls(stacked=False)

        # Gauge panel, with the status pill under the reading.
        self.gauge = Gauge()
        self.status = QLabel()
        self.status.setObjectName("pill")
        self.status.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self._status_icon = QLabel()
        pill = QFrame()
        pill.setObjectName("pillFrame")
        pill_row = QHBoxLayout(pill)
        pill_row.setContentsMargins(12, 4, 14, 4)
        pill_row.setSpacing(6)
        pill_row.addWidget(self._status_icon)
        pill_row.addWidget(self.status)
        self._pill = pill
        gauge_panel = QWidget()
        gauge_layout = QVBoxLayout(gauge_panel)
        gauge_layout.setContentsMargins(16, 16, 16, 18)
        gauge_layout.addWidget(self.gauge, 1)
        gauge_layout.addWidget(pill, 0, Qt.AlignmentFlag.AlignHCenter)

        self.card_down = Card("Download", "download", BLUE, "down")
        self.card_up = Card("Upload", "upload", PURPLE, "up")
        self.card_ping = Card("Ping", "ping", GREEN, "ok")
        self.card_jitter = Card("Jitter", "activity", "#64748b", "neutral")
        cards_panel = QWidget()
        cards = QGridLayout(cards_panel)
        cards.setContentsMargins(18, 18, 18, 18)
        cards.setSpacing(18)
        cards.addWidget(self.card_down, 0, 0)
        cards.addWidget(self.card_up, 0, 1)
        cards.addWidget(self.card_ping, 1, 0)
        cards.addWidget(self.card_jitter, 1, 1)

        # Gauge and results share one panel, a rule between them.
        top_panel = Panel()
        top = QHBoxLayout(top_panel)
        top.setContentsMargins(6, 6, 6, 6)
        top.setSpacing(6)
        top.addWidget(gauge_panel, 9)
        rule = QFrame()
        rule.setObjectName("divider")
        rule.setFixedWidth(1)
        top.addWidget(rule)
        top.addWidget(cards_panel, 10)

        # Session history.
        self.history = QTreeWidget()
        self.history.setObjectName("history")
        self.history.setRootIsDecorated(False)
        self.history.setHeaderLabels(self.HISTORY_COLUMNS)
        header = self.history.header()
        header.setStretchLastSection(False)
        header.setSectionResizeMode(QHeaderView.ResizeMode.Fixed)
        header.setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        for col, width in ((0, 140), (2, 150), (3, 150), (4, 110), (5, 110)):
            header.resizeSection(col, width)
        for col in range(2, 6):
            self.history.headerItem().setTextAlignment(
                col, Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)
        # Room for the header and three runs; it scrolls beyond that.
        self.history.setMinimumHeight(118)
        self.history.setMaximumHeight(190)
        self.history.setFocusPolicy(Qt.FocusPolicy.NoFocus)  # no heavy focus/selection bar
        self.history.setUniformRowHeights(True)
        history_panel = Panel()
        history_layout = QVBoxLayout(history_panel)
        history_layout.setContentsMargins(20, 14, 20, 14)
        history_layout.addWidget(_label("Session history", "panelTitle"))
        history_layout.addWidget(self.history)

        # Footer: where the test ran (the public IP is on the Internet card).
        self._info_icon = QLabel()
        self.server_label = _label(" ", "muted")
        self.server_label.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        footer = QHBoxLayout()
        footer.setSpacing(8)
        footer.addWidget(self._info_icon)
        footer.addWidget(self.server_label, 1)

        # No scroll bar: as the window shrinks, fonts and gaps shrink with it
        # (see _rescale) and the history and subtitle give way when it's short.
        layout = QVBoxLayout(self)
        layout.setSizeConstraint(QVBoxLayout.SizeConstraint.SetNoConstraint)
        layout.setContentsMargins(28, 20, 28, 14)
        layout.setSpacing(14)
        self._subtitle = subtitle
        self._history_panel = history_panel
        #: (layout, margins, spacing) at full size, scaled by _rescale.
        self._spacing = [
            (layout, (28, 20, 28, 14), 14), (gauge_layout, (16, 16, 16, 18), 6),
            (cards, (18, 18, 18, 18), 18), (top, (6, 6, 6, 6), 6),
            (history_layout, (20, 14, 20, 14), 6),
        ]
        heading = QVBoxLayout()
        heading.setSpacing(2)
        heading.addWidget(title)
        heading.addWidget(subtitle)
        header = QHBoxLayout()
        header.addLayout(heading, 1)
        header.addWidget(self.connection, 0, Qt.AlignmentFlag.AlignTop)
        layout.addLayout(header)
        self._cards_row = QHBoxLayout()
        self._cards_row.setSpacing(14)
        self._cards_row.addWidget(self.provider_card, 1)
        self._cards_row.addWidget(self.device_card, 1)
        layout.addLayout(self._cards_row)
        layout.addLayout(controls)
        # The gauge and cards stop growing at a comfortable size; a taller
        # window gives the room to the history instead.
        top_panel.setMaximumHeight(TOP_PANEL_MAX)
        layout.addWidget(top_panel, 5)
        layout.addWidget(history_panel, 2)
        layout.addStretch(0)
        layout.addLayout(footer)

        self.picker = ServerPicker(self)
        self.picker.chosen.connect(self.set_choice)
        self._scale = 1.0
        self._apply_theme()
        self._set_status("idle", "Ready")
        self._show_connection()
        self.set_choice(CLOUDFLARE)
        self._restore_choice()
        self._list_thread: ServerListThread | None = None
        if load_servers:
            self.load_servers()
            self.find_provider()
            self.find_device()

    # ----------------------------------------------------------- servers

    def _settings(self):
        return getattr(self.parent(), "settings", None)

    def set_choice(self, choice: ServerSpec | str, colo: str = "") -> None:
        """The server the next test runs against."""
        self._choice = choice
        self.server.show_choice(choice, colo)
        if self._result is None:
            if same_choice(choice, CLOUDFLARE) and self._candidates:
                # Automatic: the nearest server (Cloudflare only when there's
                # nothing nearby).
                choice = self._candidates[0]
            url = choice.url if isinstance(choice, ServerSpec) else choice
            host = urllib.parse.urlsplit(url).hostname or url
            self.server_label.setText(f"Next test: {host}")

    def open_picker(self) -> None:
        if self._thread is None:
            self.picker.open_panel(self._choice)

    def _restore_choice(self) -> None:
        settings = self._settings()
        if settings is None:
            return
        seconds = float(settings.speed_test_seconds)
        if seconds == 10.0:  # the old Standard, now 14 s as speedtest.net runs
            seconds = 14.0
        index = self.duration.findData(seconds)
        if index >= 0:
            self.duration.setCurrentIndex(index)
        # The server isn't restored: every window starts on Automatic (the
        # nearest server), and a server picked by hand lasts while it's open.

    def _remember_choice(self, options: SpeedTestOptions) -> None:
        settings = self._settings()
        if settings is None:
            return
        settings.speed_test_seconds = options.duration_s

    def find_provider(self) -> None:
        self._provider_thread = track(ProviderThread())
        self._provider_thread.found.connect(self._provider_found)
        self._provider_thread.start()

    def _gone(self) -> bool:
        """Whether Qt has deleted this window (or its picker) while a
        background thread's answer was on its way."""
        return sip.isdeleted(self) or sip.isdeleted(self.picker) or sip.isdeleted(self.history)

    def find_device(self) -> None:
        # The local address is instant; the rest of the card follows the first read.
        if not self._local_ip:
            self._local_ip = device_link.local_address()
            self.local_ip.setText(self._local_ip or "–")
            self.copy_local.setEnabled(bool(self._local_ip))
        thread = DeviceThread()
        # It reads until told to stop: the app owns it (so it outlives the
        # window's own deletion) and it stops however the window goes.
        retire(thread)
        thread.found.connect(self._device_found)
        self.destroyed.connect(thread.stop)
        self._device_thread = thread
        thread.start()

    def _show_connection(self, online: bool | None = None, kind: str | None = None) -> None:
        """The pill: Offline unless both the Internet answered (`online`,
        from the provider lookup) and this device's link is up; then which
        kind of link. Either argument left out keeps what's known."""
        if online is not None or not hasattr(self, "_online"):
            self._online = online
        if kind is not None:
            self._kind = kind
        link = getattr(self, "_link", None)
        link_down = link is not None and not link.connected
        if link_down or self._online is False:
            text, color, tone = "Offline", RED, "bad"
        elif self._online is None:
            text, color, tone = "Checking…", self.theme["muted"], "idle"
        else:
            kind = getattr(self, "_kind", "")
            text = f"{kind} connected" if kind in ("Wi-Fi", "Ethernet") else "Connected"
            color, tone = GREEN, "ok"
        self.connection.setProperty("tone", tone)
        self.connection.style().unpolish(self.connection)
        self.connection.style().polish(self.connection)
        self.connection.setText(f"<span style='color:{color}'>●&nbsp; {text}</span>")

    @from_thread
    def _provider_found(self, online: bool, found) -> None:
        if self._gone():
            return
        self._provider_thread = None
        self._show_connection(online)
        self._public_ipv4 = found.ipv4 if found is not None else ""
        self._public_ipv6 = found.ipv6 if found is not None else ""
        if found is not None and found.name:
            self.provider_badge.set_provider(found.name, logos.domain_for(found.name), self.logos)
            self.provider_name.setText(found.name)
            self.provider_card.setToolTip(
                f"{found.organisation}\n{found.network}" + (f" · {found.country}" if found.country else ""))
        elif online:  # addresses, but no registry answer
            self.provider_badge.set_pixmap(glyphs.pixmap("globe", self.theme["muted"], 20))
            self.provider_name.setText("Unknown")
            self.provider_card.setToolTip("The registry didn't say who holds this address")
        else:
            self.provider_badge.set_pixmap(glyphs.pixmap("globe", RED, 20))
            self.provider_name.setText("No Internet")
            self.provider_card.setToolTip("Check the network, then run the test")
        self._show_public_ip()

    def _show_public_ip(self) -> None:
        shown = self.ip_eye.isChecked()
        for ip, label, button, version in (
                (self._public_ipv4, self.public_ip, self.copy_public, "IPv4"),
                (self._public_ipv6, self.public_ipv6, self.copy_public6, "IPv6")):
            if not ip:
                label.setText("–")
                label.setToolTip(f"No public {version} address on this connection")
            else:
                label.setText(ip if shown else "••••••••••")
                label.setToolTip(ip if shown else "Hidden: press the eye to show it again")
            button.setEnabled(bool(ip))
        self.ip_eye.setIcon(glyphs.icon("eyeoff" if shown else "eye", self.theme["muted"], 15))
        self.ip_eye.setToolTip("Hide the public IP" if shown else "Show the public IP")

    @from_thread
    def _device_found(self, link) -> None:
        if self._gone():
            return
        self._link = link
        self._local_ip = link.local_ip
        self.local_ip.setText(link.local_ip or "–")
        self.copy_local.setEnabled(bool(link.local_ip))
        self.link_speed.setText(format_link(link.link_mbps))
        # Wi-Fi shows its network, band and signal; a cable its adapter,
        # duplex and whether the link is up.
        # Wi-Fi names the standard in use ("Wi-Fi 6 (802.11ax)") when known.
        generation = wifi_generation(link.phy, link.band) if link.wifi else ""
        if generation:
            generation = f"{generation} ({link.phy.replace(' ', '')})"
        self.device_tag.setText("LAN" if link.kind == "Ethernet" else generation or link.kind or "")
        self.device_tag.setVisible(bool(link.kind))
        self.link_icon.setPixmap(glyphs.pixmap("wifi" if link.wifi else "rj45", BLUE, 26))
        self.network_icon.setPixmap(glyphs.pixmap("wifi" if link.wifi else "cable", BLUE, 18))
        self.network_name.setToolTip("")
        if link.wifi:
            # "Wi-Fi network" on every system, as macOS shows it (it hides the
            # name from apps without Location Services); the name, if known,
            # is in the tooltip.
            self.network_name.setText("Wi-Fi network")
            self.network_name.setToolTip(link.ssid)
            # "5 GHz · 160 MHz": the band and, where the system tells it
            # (macOS does, netsh doesn't), the channel width.
            self.band_tag.setText(" · ".join(x for x in (link.band, link.width) if x))
            self.band_tag.setToolTip(f"Channel {link.channel}" if link.channel else "")
            self.band_tag.setVisible(bool(link.band))
            label, bars = strength(link)
            signal = (f"{link.signal_dbm} dBm" if link.signal_dbm is not None
                      else f"{link.signal_percent} %" if link.signal_percent is not None else "")
            self.signal_icon.setPixmap(signal_pixmap(
                None, self.theme["border"], 16, bars=bars,
                color=GREEN if bars >= 3 else AMBER if bars == 2 else RED))
            self.signal_label.setText(label)
            self.signal_label.setToolTip(signal)
            rssi = rssi_text(link)
            self.rssi_label.setText(rssi)
            self.rssi_label.setToolTip(
                "RSSI: the received signal strength" if link.signal_dbm is not None
                else f"RSSI estimated from Windows' signal quality ({link.signal_percent} %)")
            self.rssi_label.setVisible(bool(rssi))
            self._band_rule.setVisible(bool(link.band))
            for w in (self.signal_icon, self.signal_label, self._signal_rule):
                w.setVisible(bool(label))
        else:
            port = re.sub(r"\s*\((\w+)\)$", "", link.port).strip()  # "Ethernet Adapter (en4)"
            self.network_name.setText(port or (f"{link.kind} · {link.interface}" if link.interface
                                               else link.kind or "Not connected"))
            if link.interface:
                self.network_name.setToolTip(f"{link.port or link.kind} ({link.interface})")
            self.band_tag.setText(link.duplex)
            self.band_tag.setToolTip("")
            self.band_tag.setVisible(bool(link.duplex))
            self._band_rule.setVisible(bool(link.duplex))
            up = link.active if link.active is not None else link.connected
            self.signal_icon.setPixmap(glyphs.pixmap("dot", GREEN if up else RED, 12))
            self.signal_label.setText("Link active" if up else "No link")
            self.rssi_label.hide()
            self.signal_label.setToolTip("")
            for w in (self.signal_icon, self.signal_label, self._signal_rule):
                w.setVisible(bool(link.kind))
        self._show_connection(kind=link.kind)  # a dropped link shows Offline
        # Back online after being offline: ask who provides it again.
        if link.connected and self._online is False and self._provider_thread is None:
            self.find_provider()

    def _copy_text(self, text: str) -> None:
        if text:
            QApplication.clipboard().setText(text)

    def _build_connection_cards(self) -> None:
        mono = QFont(self.font())
        mono.setFamilies([fonts.MONO_FAMILY, "Menlo", "Consolas", "monospace"])

        def value(text: str = "–", name: str = "cardFigure") -> QLabel:
            return _label(text, name)  # copied with its button, not by selecting

        def small_button(icon: str, tip: str) -> QPushButton:
            button = QPushButton()
            button.setObjectName("tinyButton")
            button.setFixedSize(30, 30)
            button.setToolTip(tip)
            button.setCursor(Qt.CursorShape.PointingHandCursor)
            button.setIcon(glyphs.icon(icon, self.theme["muted"], 16))
            return button

        def rule(vertical: bool = True) -> QFrame:
            line = QFrame()
            line.setObjectName("divider")
            if vertical:
                line.setFixedWidth(1)
                line.setMinimumHeight(30)
            else:
                line.setFixedHeight(1)
            return line

        def stack(caption: str, figure: QLabel) -> QVBoxLayout:
            box = QVBoxLayout()
            box.setSpacing(1)
            box.addWidget(_label(caption, "muted"))
            box.addWidget(figure)
            return box

        # Internet connection: provider and public IP.
        self.provider_card = Panel()
        outer = QVBoxLayout(self.provider_card)
        outer.setContentsMargins(20, 12, 20, 14)
        outer.setSpacing(10)
        internet_head = _label("INTERNET CONNECTION", "sectionHead")
        outer.addWidget(internet_head)
        row = QHBoxLayout()
        row.setSpacing(12)
        self.provider_badge = ProviderBadge(46)
        self.provider_name = value("Finding…", "cardFigure")
        row.addWidget(self.provider_badge)
        row.addLayout(stack("Internet provider", self.provider_name), 1)
        row.addWidget(rule())
        globe = QLabel()
        globe.setPixmap(glyphs.pixmap("globe", self.theme["ink"], 26))
        self._globe_icon = globe
        row.addWidget(globe)
        # Public IP: IPv4 and IPv6 on lines of their own, each with a copy
        # button; the eye hides both (e.g. to share the screen).
        ips = QGridLayout()
        ips.setHorizontalSpacing(8)
        ips.setVerticalSpacing(2)
        ips.addWidget(_label("Public IP", "muted"), 0, 0, 1, 2)
        self.ip_eye = small_button("eyeoff", "Hide the public IP")
        self.ip_eye.setCheckable(True)
        self.ip_eye.setChecked(True)
        self.ip_eye.setFixedSize(26, 22)
        self.ip_eye.toggled.connect(lambda _: self._show_public_ip())
        ips.addWidget(self.ip_eye, 0, 2, Qt.AlignmentFlag.AlignRight)
        self.public_ip = value("–", "ipFigure")
        self.public_ipv6 = MiddleElidedLabel("–", "ipSmall")
        self.copy_public = small_button("copy", "Copy the public IPv4 address")
        self.copy_public.clicked.connect(lambda: self._copy_text(self._public_ipv4))
        self.copy_public6 = small_button("copy", "Copy the public IPv6 address")
        self.copy_public6.clicked.connect(lambda: self._copy_text(self._public_ipv6))
        for line, (tag, label, button) in enumerate(
                (("IPv4", self.public_ip, self.copy_public),
                 ("IPv6", self.public_ipv6, self.copy_public6)), start=1):
            ips.addWidget(_label(tag, "ipTag"), line, 0, Qt.AlignmentFlag.AlignVCenter)
            label.setFont(mono)
            label.setSizePolicy(QSizePolicy.Policy.Ignored, QSizePolicy.Policy.Preferred)
            ips.addWidget(label, line, 1)
            button.setFixedSize(26, 24)
            button.setEnabled(False)
            ips.addWidget(button, line, 2)
        ips.setColumnStretch(1, 1)
        row.addLayout(ips, 3)
        outer.addLayout(row)
        outer.addStretch(1)

        # This device: local IP, link speed, and the network.
        self.device_card = Panel()
        outer = QVBoxLayout(self.device_card)
        outer.setContentsMargins(20, 12, 20, 12)
        outer.setSpacing(8)
        head = QHBoxLayout()
        device_head = _label("THIS DEVICE", "sectionHead")
        head.addWidget(device_head)
        head.addStretch(1)
        self.device_tag = _label("", "tag")
        # Its own height only: a short window hides the heading, and the
        # card's spare height mustn't swell the tag into a tall box.
        self.device_tag.setSizePolicy(QSizePolicy.Policy.Preferred, QSizePolicy.Policy.Fixed)
        self.device_tag.hide()
        head.addWidget(self.device_tag, 0, Qt.AlignmentFlag.AlignVCenter)
        outer.addLayout(head)
        row = QHBoxLayout()
        row.setSpacing(12)
        laptop = QLabel()
        laptop.setPixmap(glyphs.pixmap("laptop", self.theme["ink"], 30))
        self._laptop_icon = laptop
        row.addWidget(laptop)
        self.local_ip = value("–", "ipFigure")
        self.local_ip.setFont(mono)
        row.addLayout(stack("Local IP", self.local_ip), 1)
        self.copy_local = small_button("copy", "Copy the local IP")
        self.copy_local.setEnabled(False)
        self.copy_local.clicked.connect(lambda: self._copy_text(self._local_ip))
        row.addWidget(self.copy_local)
        row.addWidget(rule())
        self.link_icon = QLabel()
        self.link_icon.setPixmap(glyphs.pixmap("wifi", BLUE, 26))
        row.addWidget(self.link_icon)
        self.link_speed = value("–", "cardFigure")
        row.addLayout(stack("Link speed", self.link_speed), 1)
        outer.addLayout(row)
        self._device_rule = rule(vertical=False)
        outer.addWidget(self._device_rule)
        self._network_row = QWidget()
        net = QHBoxLayout(self._network_row)
        net.setContentsMargins(0, 0, 0, 0)
        net.setSpacing(10)
        self.network_icon = QLabel()
        self.network_icon.setPixmap(glyphs.pixmap("wifi", BLUE, 18))
        self.network_name = _label("Finding the network…", "networkName")
        self.network_name.setSizePolicy(QSizePolicy.Policy.Ignored, QSizePolicy.Policy.Preferred)
        net.addWidget(self.network_icon)
        net.addWidget(self.network_name, 2)
        self._band_rule = rule()
        self._band_rule.setMinimumHeight(18)
        net.addWidget(self._band_rule)
        self.band_tag = _label("", "tag")
        self.band_tag.hide()
        net.addWidget(self.band_tag)
        self._signal_rule = rule()
        self._signal_rule.setMinimumHeight(18)
        net.addWidget(self._signal_rule)
        self.signal_icon = QLabel()
        self.signal_label = _label("", "networkName")
        self.rssi_label = _label("", "networkName")  # "-57 dBm"
        self.rssi_label.hide()
        net.addWidget(self.rssi_label)
        net.addWidget(self.signal_icon)
        net.addWidget(self.signal_label)
        for w in (self._band_rule, self._signal_rule, self.signal_icon, self.signal_label):
            w.hide()
        outer.addWidget(self._network_row)
        self._section_heads = (internet_head, device_head)
        self._show_public_ip_ready = True

    def load_servers(self) -> None:
        self._list_thread = track(ServerListThread())
        self._list_thread.loaded.connect(self._servers_loaded)
        self._list_thread.partial.connect(self._servers_partial)
        self._list_thread.picked.connect(self._servers_picked)
        self._list_thread.start()

    @from_thread
    def _servers_partial(self, ranked) -> None:
        if not self._gone():
            self.picker.set_servers(ranked)
            self._set_nearest(ranked)

    @from_thread
    def _servers_picked(self, best) -> None:
        """The nearest servers re-ranked by WebSocket ping: Automatic now
        tests the first of these."""
        if self._gone():
            return
        self._ws_picked = True
        self._use_candidates(best[:speedtest.AUTO_CANDIDATES])

    def _set_nearest(self, ranked) -> None:
        if getattr(self, "_ws_picked", False):
            return  # the WebSocket ranking stands
        self._use_candidates(speedtest.nearest_ookla(ranked, speedtest.AUTO_CANDIDATES))

    def _use_candidates(self, nearest) -> None:
        candidates = tuple(spec for spec, _ in nearest)
        if candidates == self._candidates:
            return
        self._candidates = candidates
        self.server.nearest = candidates[0] if candidates else None
        self.picker.set_nearest(nearest[0] if nearest else None)
        if self._thread is None and same_choice(self._choice, CLOUDFLARE):
            self.set_choice(self._choice)

    @from_thread
    def _servers_loaded(self, ranked) -> None:
        if self._gone():
            return
        self._list_thread = None
        self.picker.set_servers(ranked)
        self._set_nearest(ranked)

    # ------------------------------------------------------------- theme

    def _dark(self) -> bool:
        settings = getattr(self.parent(), "settings", None)
        if settings is not None and hasattr(settings, "dark_background"):
            return bool(settings.dark_background)
        return self.palette().color(QPalette.ColorRole.Window).lightness() < 128

    def _apply_theme(self) -> None:
        self.theme = c = palette(self._dark())
        chevron = _chevron_file(c["muted"])
        k = getattr(self, "_scale", 1.0)

        def px(n: float, least: int = 10) -> int:
            return max(least, round(n * k))
        self.setStyleSheet(f"""
            QWidget#speedTest, QWidget#speedContent, QScrollArea#speedScroll
                {{ background: {c['bg']}; border: none; }}
            QLabel, QComboBox, QPushButton, QToolButton, QTreeWidget, QHeaderView, QLineEdit
                {{ color: {c['ink']}; font-size: {px(13, 11)}px; }}
            QLabel {{ background: transparent; }}
            QLabel#pageTitle {{ font-size: {px(26, 18)}px; font-weight: 700; }}
            QLabel#pageSubtitle, QLabel#muted, QLabel#cardNote, QLabel#legend
                {{ color: {c['muted']}; }}
            QLabel#panelTitle {{ font-size: {px(16, 13)}px; font-weight: 700; }}
            QFrame#panel {{ background: {c['panel']}; border: 1px solid {c['border']};
                            border-radius: 14px; }}
            QFrame#divider {{ background: {c['border']}; }}
            QFrame#card {{ border: none; border-radius: 12px; }}
            QFrame#card[tone="down"] {{ background: {c['down']}; }}
            QFrame#card[tone="up"] {{ background: {c['up']}; }}
            QFrame#card[tone="ok"] {{ background: {c['ok']}; }}
            QLabel#cardTitle {{ font-size: {px(14, 11)}px; font-weight: 600; }}
            QLabel#cardValue {{ font-size: {px(28, 18)}px; font-weight: 700; }}
            QLabel#cardNote {{ font-size: {px(13, 11)}px; }}
            QComboBox {{ background: {c['field']}; border: 1px solid {c['border']};
                         border-radius: 8px; padding: {px(6, 3)}px 10px; }}
            QComboBox::drop-down {{ border: none; width: 26px; }}
            QComboBox::down-arrow {{ image: url("{chevron}"); width: 14px; height: 14px; }}
            QPushButton {{ border-radius: 8px; padding: {px(8, 5)}px {px(18, 10)}px; font-weight: 600; }}
            QPushButton#secondary {{ background: {c['button']}; border: 1px solid {c['border']}; }}
            QPushButton#secondary:disabled {{ color: {c['muted']}; }}
            QPushButton#primary {{ background: {BLUE}; color: #ffffff; border: none;
                                   min-width: 96px; }}
            QPushButton#primary:hover {{ background: #0a6fe0; }}
            QPushButton#primary:disabled {{ background: #7fb6ff; }}
            QFrame#pillFrame {{ border-radius: 15px; min-height: 30px; max-height: 30px; }}
            QFrame#pillFrame[tone="ok"] {{ background: {c['pill_ok']}; }}
            QFrame#pillFrame[tone="run"] {{ background: {c['pill_run']}; }}
            QFrame#pillFrame[tone="bad"] {{ background: {c['pill_bad']}; }}
            QFrame#pillFrame[tone="idle"] {{ background: {c['pill_idle']}; }}
            QLabel#pill {{ font-weight: 600; }}
            QTreeWidget#history {{ background: {c['panel']}; border: 1px solid {c['border']};
                                   border-radius: 8px; }}
            QTreeWidget#history::item {{ padding: 5px 10px; }}
            QTreeWidget#history::item:selected {{ background: {c['pill_run']}; color: {c['ink']}; }}
            QTreeWidget#history::item:hover {{ background: {c['head']}; }}
            QTreeWidget#history QHeaderView::section {{ background: {c['head']};
                                    color: {c['muted']}; font-weight: 600;
                                    border: none; border-bottom: 1px solid {c['border']};
                                    padding: 5px 10px; }}
            QHeaderView::section {{ background: {c['head']}; color: {c['ink']};
                                    border: none; border-bottom: 1px solid {c['border']};
                                    border-right: 1px solid {c['border']}; padding: 7px 10px; }}
            QToolButton#ipButton {{ border: none; color: {c['muted']}; padding: 2px 4px; }}
            QLabel#sectionHead {{ color: {c['muted']}; font-size: {px(12, 10)}px; font-weight: 700;
                                  letter-spacing: 1px; }}
            QLabel#cardFigure {{ font-size: {px(20, 14)}px; font-weight: 700; }}
            QLabel#ipFigure {{ font-size: {px(18, 13)}px; font-weight: 700; }}
            QLabel#ipSmall {{ font-size: {px(13, 11)}px; font-weight: 600; }}
            QLabel#ipTag {{ color: {c['muted']}; background: {c['grid']}; border: 1px solid {c['grid']};
                            border-radius: 6px; padding: 0 5px; font-size: {px(11, 9)}px;
                            font-weight: 700; }}
            QLabel#networkName {{ font-weight: 600; }}
            QLabel#tag {{ background: {c['down']}; color: {BLUE}; border: 1px solid {c['down']};
                          border-radius: 7px; padding: 1px 9px; font-size: {px(12, 10)}px;
                          font-weight: 600; }}
            QLabel#connectionPill {{ border-radius: 10px; padding: 3px 12px;
                                     font-size: {px(15, 12)}px; font-weight: 600; }}
            QLabel#connectionPill[tone="ok"] {{ background: {c['pill_ok']}; border: 1px solid {c['pill_ok']}; }}
            QLabel#connectionPill[tone="bad"] {{ background: {c['pill_bad']}; border: 1px solid {c['pill_bad']}; }}
            QLabel#connectionPill[tone="idle"] {{ background: {c['pill_idle']}; border: 1px solid {c['pill_idle']}; }}
            QPushButton#tinyButton {{ background: {c['button']}; border: 1px solid {c['border']};
                                      border-radius: 8px; padding: 0; }}
            QPushButton#tinyButton:checked {{ background: {c['down']}; }}
            QPushButton#iconButton {{ background: {c['button']}; border: 1px solid {c['border']};
                                      padding: {px(8, 5)}px {px(10, 7)}px; }}
            QPushButton#iconButton:disabled {{ background: {c['panel']}; }}
            QFrame#card[tone="neutral"] {{ background: {c['grid']}; }}
            QFrame#serverRow[selected="true"]
                {{ background: {c['down']}; border: 2px solid {BLUE}; border-radius: 10px; }}
            QLabel#pickerSelected {{ font-size: 13px; font-weight: 600; }}
            QPushButton#serverField {{ background: {c['field']}; border: 1px solid {c['border']};
                                       border-radius: 8px; padding: 0; min-height: 34px;
                                       text-align: left; font-weight: 400; }}
            QPushButton#serverField:hover {{ border-color: {BLUE}; }}
            QPushButton#serverField:disabled QLabel {{ color: {c['muted']}; }}
            QPushButton#link {{ background: transparent; border: none; color: {BLUE};
                                padding: 4px 6px; font-weight: 500; }}
            QPushButton#link:disabled {{ color: {c['muted']}; }}
            QFrame#scrim {{ background: rgba(15, 23, 42, 70); }}
            QFrame#picker {{ background: {c['panel']}; border-left: 1px solid {c['border']};
                             border-top-left-radius: 16px; border-bottom-left-radius: 16px; }}
            QFrame#pickerShadow {{ background: {c['panel']};
                             border-top-left-radius: 16px; border-bottom-left-radius: 16px; }}
            QLabel#pickerTitle {{ font-size: 22px; font-weight: 700; }}
            QLabel#pickerSubtitle, QLabel#pickerNote {{ color: {c['muted']}; font-size: 12px; }}
            QPushButton#pickerClose {{ background: transparent; border: none; padding: 0;
                                       border-radius: 15px; }}
            QPushButton#pickerClose:hover {{ background: {c['grid']}; }}
            QLineEdit#pickerSearch {{ background: {c['field']}; border: 1px solid {c['border']};
                                      border-radius: 8px; padding: 7px 8px; }}
            QLineEdit#pickerSearch:focus {{ border-color: {BLUE}; }}
            QPushButton#chip {{ background: {c['panel']}; border: 1px solid {c['border']};
                                border-radius: 13px; padding: 0 11px; font-weight: 500; }}
            QPushButton#chip:hover {{ border-color: {BLUE}; }}
            QPushButton#chip:checked {{ background: {BLUE}; border-color: {BLUE}; color: #ffffff; }}
            QFrame#serverRow {{ border-radius: 10px; background: transparent; }}
            QFrame#serverRow:hover {{ background: {c['head']}; }}
            QFrame#serverRow[selected="true"] {{ background: {c['down']}; }}
            QLabel#rowTitle {{ font-weight: 600; }}
            QLabel#rowSubtitle, QLabel#rowLatency {{ color: {c['muted']}; font-size: 12px; }}
            QLabel#rowLatency {{ font-size: 13px; color: {c['ink']}; }}
            QFrame#serverRow:disabled QLabel {{ color: {c['muted']}; }}
            QLabel#rowIcon {{ background: {c['down']}; border-radius: 18px; }}
            QFrame#serverRow QRadioButton::indicator {{ width: 14px; height: 14px; border-radius: 9px;
                                                         border: 2px solid {c['muted']};
                                                         background: {c['panel']}; }}
            QFrame#serverRow QRadioButton::indicator:checked {{
                width: 8px; height: 8px; border: 5px solid {BLUE}; background: #ffffff; }}
            QFrame#serverRow QRadioButton::indicator:disabled {{ border-color: {c['border']}; }}
            QLabel#isoBadge {{ background: {c['grid']}; border-radius: 4px; font-size: 11px;
                               font-weight: 700; color: {c['muted']}; }}
            QLabel#listHead {{ color: {c['muted']}; font-size: 11px; font-weight: 600; }}
            QWidget#pickerList, QScrollArea#pickerScroll {{ background: transparent; }}
        """)
        self._info_icon.setPixmap(glyphs.pixmap("info", c["muted"], 18))
        self.server.set_colors(c["ink"], c["muted"], c["panel"], c["border"])
        self.provider_badge.set_colors(c["panel"], c["border"])
        self._globe_icon.setPixmap(glyphs.pixmap("globe", c["ink"], 26))
        self._laptop_icon.setPixmap(glyphs.pixmap("laptop", c["ink"], 30))
        for button, icon in ((self.copy_public, "copy"), (self.copy_public6, "copy"),
                             (self.copy_local, "copy")):
            button.setIcon(glyphs.icon(icon, c["muted"], 16))
        if getattr(self, "_show_public_ip_ready", False):
            self._show_public_ip()
        if hasattr(self, "picker"):
            self.picker.apply_theme()
        self._refresh_button_icons()
        self.gauge.update()

    def _refresh_button_icons(self) -> None:
        self.copy_button.setIcon(glyphs.icon("copy", self.theme["ink"], 16))
        running = self._thread is not None
        self.button.setIcon(glyphs.icon("stop" if running else "play", "#ffffff", 16))

    def changeEvent(self, event) -> None:
        if event.type() in (QEvent.Type.PaletteChange, QEvent.Type.ApplicationPaletteChange,
                            QEvent.Type.ParentChange):
            if hasattr(self, "theme") and palette(self._dark()) != self.theme:
                self._apply_theme()
        super().changeEvent(event)

    def fit_to_screen(self) -> None:
        """Open no bigger than the screen's free area (a laptop's is often
        shorter than the default height)."""
        screen = self.screen() or QApplication.primaryScreen()
        if screen is None:
            return
        free = screen.availableGeometry()
        width = min(self.width(), int(free.width() * 0.95))
        height = min(self.height(), int(free.height() * 0.92))
        if (width, height) != (self.width(), self.height()):
            self.resize(width, height)

    def showEvent(self, event) -> None:
        if not getattr(self, "_fitted", False):
            self._fitted = True
            self.fit_to_screen()
        if palette(self._dark()) != self.theme:  # the app's theme changed meanwhile
            self._apply_theme()
        super().showEvent(event)

    def _set_status(self, tone: str, text: str, tooltip: str = "") -> None:
        color = {"ok": GREEN, "run": BLUE, "bad": RED, "idle": self.theme["muted"]}[tone]
        self._pill.setProperty("tone", tone)
        self._pill.style().unpolish(self._pill)
        self._pill.style().polish(self._pill)
        self.status.setText(text)
        self.status.setStyleSheet(f"color: {color};")
        self._pill.setToolTip(tooltip)
        icon = {"ok": "check", "run": "activity", "bad": "info", "idle": "speed"}[tone]
        self._status_icon.setPixmap(glyphs.pixmap(icon, color, 16))

    # ----------------------------------------------------------- running

    def options(self) -> SpeedTestOptions:
        if same_choice(self._choice, CLOUDFLARE) and self._candidates:
            # Automatic: straight to the nearest server.
            return SpeedTestOptions(server=self._candidates[0],
                                    duration_s=self.duration.currentData())
        return SpeedTestOptions(server=self._choice, duration_s=self.duration.currentData())

    def _toggle(self) -> None:
        if self._thread is None:
            self.start()
        else:
            self.stop()

    def start(self) -> None:
        if self._thread is not None:
            return
        options = self.options()
        self._remember_choice(options)
        self._result = None
        self._phase = ""
        self.gauge.reset()
        for card in (self.card_down, self.card_up, self.card_ping, self.card_jitter):
            card.set("–")
        self.server_label.setText(options.server.name if isinstance(options.server, ServerSpec)
                                  else options.server)
        self._set_status("run", "Connecting…")
        self.copy_button.setEnabled(False)
        self.server.setEnabled(False)
        self.duration.setEnabled(False)
        self.button.setText("Stop")
        self._thread = track(SpeedTestThread(options))
        self._thread.phase.connect(self._on_phase)
        self._thread.sample.connect(self._on_sample)
        self._thread.progress.connect(self._show_cards)
        self._thread.done.connect(self._finished)
        self._thread.finished.connect(self._thread_ended)
        self._thread.start()
        self._refresh_button_icons()

    def stop(self) -> None:
        if self._thread is not None:
            self._thread.stop()
            self.button.setEnabled(False)
            self._set_status("run", "Stopping…")

    def _on_phase(self, phase: str) -> None:
        previous, self._phase = self._phase, phase
        if phase == "pause":
            # The needle falls back to 0 while the line settles.
            self.gauge.sweep_to(0.0, 600, self.gauge.reset)
            self._set_status("run", "Preparing upload…" if previous == "download"
                             else "Preparing ping…")
            return
        if phase == "ping":
            self._pings = []
            self.gauge.set_value(0.0, "ping")  # the needle now reads ms
            for card in (self.card_ping, self.card_jitter):
                card.set("–", "Measuring…\n ")
            self._set_status("run", "Testing ping…")
            return
        self.gauge.set_value(0.0, phase)
        self._needle = NeedleSmoother(self.options().ramp_s)
        self._set_status("run", {"connect": "Connecting…",
                                 "download": "Testing download…",
                                 "upload": "Testing upload…"}.get(phase, ""))

    def _on_sample(self, phase: str, seconds: float, value: float) -> None:
        if phase == "ping":
            # Each round trip as it comes: median and jitter so far.
            self._pings.append(value)
            self.gauge.sweep_to(value, 180)  # swings to each round trip
            done, total = len(self._pings), self.options().latency_count
            self.card_ping.set(f"{format_ms(statistics.median(self._pings))} ms",
                               f"Measuring… {done}/{total}\n ")
            self.card_jitter.set(f"{format_ms(speedtest.jitter(self._pings))} ms"
                                 if done > 1 else "–")
            return
        smoothed = self._needle.add(seconds, value)
        self.gauge.set_value(smoothed)
        card = self.card_down if phase == "download" else self.card_up
        card.set(f"{format_mbps(smoothed)} Mbps", "Measuring…\n ")

    def _footer_text(self) -> str:
        if self._result is None or not self._result.meta:
            return self.server_label.text()
        return server_text(self._result.meta, show_ip=False)

    def _show_picked(self, result: SpeedResult) -> None:
        """On Automatic, name the server it chose as soon as it has chosen
        (the first progress report, before the download starts)."""
        if not same_choice(self._choice, CLOUDFLARE) or "server_url" not in result.meta:
            return
        colo = "" if self.server.nearest is not None else result.meta.get("colo", "")
        self.server.show_choice(CLOUDFLARE, colo)

    def _show_cards(self, result: SpeedResult) -> None:
        """Fill in the cards for every phase done so far."""
        self._show_picked(result)
        if result.latency_ms is not None:
            self.card_ping.set(f"{format_ms(result.latency_ms)} ms",
                               f"Median of {result.ping_count} pings\n ")
            self.card_jitter.set(f"{format_ms(result.jitter_ms)} ms")
        for card, transfer in ((self.card_down, result.download), (self.card_up, result.upload)):
            if transfer is None:
                continue
            note = f"Peak {format_mbps(transfer.peak_mbps)} Mbps"
            note += (f"\nLoaded ping {format_ms(transfer.loaded_latency_ms)} ms"
                     if transfer.loaded_latency_ms is not None else "\n ")
            card.set(f"{format_mbps(transfer.mbps)} Mbps", note)

    def _finished(self, result: SpeedResult) -> None:
        self._result = result
        self._show_picked(result)
        self.server_label.setText(self._footer_text())
        self._show_cards(result)
        if result.upload is None and self.card_up.note.text().startswith("Measuring"):
            self.card_up.set("–")  # stopped mid-upload
        if result.download is None and self.card_down.note.text().startswith("Measuring"):
            self.card_down.set("–")
        # Back to the start: the needle swings home and the reading clears;
        # the cards keep the results.
        self.gauge.sweep_to(0.0, 900, self.gauge.reset)
        if result.error:
            self._set_status("bad", "Test failed", result.error)
            self.server_label.setText(f"✗ {result.error}")
        elif result.download is None or (self.options().upload and result.upload is None):
            self._set_status("idle", "Stopped")
        else:
            self._set_status("ok", "Test complete")
        has_result = result.latency_ms is not None or result.download is not None
        self.copy_button.setEnabled(has_result)
        if has_result:
            self._add_history(result)

    def _add_history(self, result: SpeedResult) -> None:
        meta = result.meta
        item = QTreeWidgetItem([
            datetime.now().strftime("%H:%M:%S"),
            (meta.get("colo") or meta.get("host", "")).split(",")[0],
            f"{format_mbps(result.download.mbps)} Mbps" if result.download else "–",
            f"{format_mbps(result.upload.mbps)} Mbps" if result.upload else "–",
            f"{format_ms(result.latency_ms)} ms",
            f"{format_ms(result.jitter_ms)} ms",
        ])
        for col in range(2, 6):
            item.setTextAlignment(col, Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)
        self.history.insertTopLevelItem(0, item)

    def _thread_ended(self) -> None:
        self._thread = None
        self.button.setText("Run again" if self._result is not None else "Start")
        self.button.setEnabled(True)
        self.server.setEnabled(True)
        self.duration.setEnabled(True)
        self._refresh_button_icons()

    def copy(self) -> None:
        if self._result is not None:
            QApplication.clipboard().setText(result_text(self._result))

    #: Below this width the buttons go on a row of their own.
    STACK_BELOW = 900

    def _arrange_controls(self, stacked: bool) -> None:
        if stacked == self._stacked:
            return
        self._stacked = stacked
        self._controls.removeWidget(self._choices)
        self._controls.removeWidget(self._actions)
        if stacked:
            self._controls.addWidget(self._choices, 0, 0)
            self._controls.addWidget(self._actions, 1, 0)
        else:
            self._controls.addWidget(self._choices, 0, 0)
            self._controls.addWidget(self._actions, 0, 1)

    #: Scale steps (full size at 1.0) and the window size that gets 1.0.
    SCALE_STEPS = (0.7, 0.78, 0.86, 0.93, 1.0)
    #: Below these heights the history, then the subtitle, are hidden.
    HIDE_HISTORY_BELOW = 740
    HIDE_SUBTITLE_BELOW = 620
    #: Below this height the cards drop their notes (peak, loaded ping), and
    #: the provider card its second line.
    HIDE_NOTES_BELOW = 620

    def scale_for(self, width: int, height: int) -> float:
        fit = min(width / DEFAULT_WINDOW.width(), height / DEFAULT_WINDOW.height())
        return max([s for s in self.SCALE_STEPS if s <= fit] or [self.SCALE_STEPS[0]])

    def _rescale(self) -> None:
        w, h = self.width(), self.height()
        self._history_panel.setVisible(h >= self.HIDE_HISTORY_BELOW)
        self._subtitle.setVisible(h >= self.HIDE_SUBTITLE_BELOW)
        roomy = h >= self.HIDE_NOTES_BELOW
        for card in (self.card_down, self.card_up, self.card_ping, self.card_jitter):
            card.note.setVisible(roomy)
        self.provider_badge.set_size(46 if roomy else 34)
        # The cards keep their headings and the network row at every size,
        # so a short window (Windows at 125-150 % scaling) looks like a tall one.
        scale = self.scale_for(w, h)
        if scale == self._scale:
            return
        self._scale = scale
        for box, margins, spacing in self._spacing:
            if margins is not None:
                box.setContentsMargins(*(round(m * scale) for m in margins))
            box.setSpacing(round(spacing * scale))
        self._apply_theme()

    def resizeEvent(self, event) -> None:
        super().resizeEvent(event)
        self._arrange_controls(self.width() < self.STACK_BELOW)
        self._rescale()
        self.picker.reposition()

    def closeEvent(self, event) -> None:
        self.picker.close_panel()
        self.logos.shutdown()
        for name in ("_provider_thread", "_device_thread"):
            thread = getattr(self, name)
            if thread is not None:
                thread.found.disconnect()
                thread.stop()
                retire(thread)
                setattr(self, name, None)
        if self._list_thread is not None:
            self._list_thread.loaded.disconnect()
            retire(self._list_thread)
            self._list_thread = None
        if self._thread is not None:
            for signal in (self._thread.phase, self._thread.sample, self._thread.progress,
                           self._thread.done):
                signal.disconnect()
            # Only this window's slot: threads.track listens on finished too.
            self._thread.finished.disconnect(self._thread_ended)
            self._thread.stop()
            retire(self._thread)
            self._thread = None
        super().closeEvent(event)
