"""Small pictures for Speed Test: a provider's badge (its initials in a
rounded tile, in a colour of its own; brands' logos aren't ours to ship)
and signal bars for a latency."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed

from PyQt6.QtCore import (
    QBuffer, QByteArray, QIODevice, QObject, QRectF, QSize, Qt, QThread, QTimer, pyqtSignal,
)
from PyQt6.QtGui import QColor, QFont, QImage, QImageReader, QPainter, QPen, QPixmap
from PyQt6.QtSvg import QSvgRenderer
from PyQt6.QtWidgets import QWidget

from ..ping import logos
from ..ping.provider import badge_color, initials
from .threads import retire, track

GREEN = "#16a34a"
AMBER = "#d97706"
RED = "#e5383b"


class ProviderBadge(QWidget):
    """A provider's initials on a tile; or an icon pixmap in their place."""

    def __init__(self, size: int = 40, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._size = size
        self.setFixedSize(size, size)
        self._name = ""
        self._pixmap: QPixmap | None = None
        self._logo: QPixmap | None = None
        self._domain = ""
        self._surface = QColor("#ffffff")
        self._border = QColor("#e3e6eb")
        self.setAttribute(Qt.WidgetAttribute.WA_TransparentForMouseEvents)

    def sizeHint(self) -> QSize:
        return QSize(self._size, self._size)

    def set_size(self, size: int) -> None:
        self._size = size
        self.setFixedSize(size, size)
        self.update()

    def set_colors(self, surface: str, border: str) -> None:
        self._surface, self._border = QColor(surface), QColor(border)
        self.update()

    def set_provider(self, name: str, domain: str = "", store: "LogoStore | None" = None) -> None:
        """The provider's initials, replaced by the logo from its website
        (`domain`) once `store` has it."""
        self._name, self._pixmap, self._logo, self._domain = name, None, None, domain
        self.setToolTip(name)
        if domain and store is not None:
            if store.request(domain):  # coming from the website
                store.loaded.connect(self._logo_loaded)
            else:  # in memory already, or just read from the cache folder
                self._logo = store.pixmap(domain)
        self.update()

    def _logo_loaded(self, domain: str) -> None:
        store = self.sender()
        if domain == self._domain and isinstance(store, LogoStore):
            self._logo = store.pixmap(domain)
            self.update()

    def set_pixmap(self, pixmap: QPixmap) -> None:
        self._name, self._pixmap, self._logo, self._domain = "", pixmap, None, ""
        self.update()

    def paintEvent(self, event) -> None:
        p = QPainter(self)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        rect = QRectF(0.5, 0.5, self.width() - 1, self.height() - 1)
        radius = self.width() * 0.24
        p.setPen(QPen(self._border, 1))
        # Logos are drawn for light backgrounds: theirs is white in dark mode too.
        has_logo = self._logo is not None and not self._logo.isNull()
        p.setBrush(QColor("#ffffff") if has_logo else self._surface)
        p.drawRoundedRect(rect, radius, radius)
        if self._logo is not None and not self._logo.isNull():
            inner = rect.adjusted(rect.width() * 0.16, rect.height() * 0.16,
                                  -rect.width() * 0.16, -rect.height() * 0.16)
            logo = self._logo.size()
            scale = min(inner.width() / logo.width(), inner.height() / logo.height())
            w, h = logo.width() * scale, logo.height() * scale
            p.setRenderHint(QPainter.RenderHint.SmoothPixmapTransform)
            p.drawPixmap(QRectF(inner.center().x() - w / 2, inner.center().y() - h / 2, w, h),
                         self._logo, QRectF(0, 0, logo.width(), logo.height()))
            return
        if self._pixmap is not None:
            pm = self._pixmap
            size = pm.deviceIndependentSize()
            p.drawPixmap(int((self.width() - size.width()) / 2),
                         int((self.height() - size.height()) / 2), pm)
            return
        if not self._name:
            return
        text = initials(self._name)
        font = QFont(self.font())
        font.setWeight(QFont.Weight.Black)
        font.setPixelSize(max(9, int(self.height() * (0.42 if len(text) <= 2 else 0.32))))
        p.setFont(font)
        p.setPen(QColor(badge_color(self._name)))
        p.drawText(rect, Qt.AlignmentFlag.AlignCenter, text)


def signal_level(ms: float | None) -> tuple[int, str]:
    """(bars out of 4, colour) for a latency."""
    if ms is None:
        return 0, RED
    if ms < 40:
        return 4, GREEN
    if ms < 100:
        return 3, GREEN
    if ms < 200:
        return 2, AMBER
    return 1, RED


def signal_pixmap(ms: float | None, empty: str, height: int = 14, ratio: float = 2.0,
                  bars: int | None = None, color: str | None = None) -> QPixmap:
    """Four rising bars, as many lit as the latency deserves."""
    lit, tint = signal_level(ms)
    if bars is not None:
        lit = bars
    if color is not None:
        tint = color
    width = height + 4
    pm = QPixmap(int(width * ratio), int(height * ratio))
    pm.fill(Qt.GlobalColor.transparent)
    pm.setDevicePixelRatio(ratio)
    p = QPainter(pm)
    p.setRenderHint(QPainter.RenderHint.Antialiasing)
    p.setPen(Qt.PenStyle.NoPen)
    bar_w = width / 4 - 1.5
    for i in range(4):
        h = height * (0.35 + 0.65 * (i + 1) / 4)
        p.setBrush(QColor(tint if i < lit else empty))
        p.drawRoundedRect(QRectF(i * (bar_w + 1.5), height - h, bar_w, h), 1, 1)
    p.end()
    return pm


# ------------------------------------------------------------------ logos


def decode_logo(data: bytes | None) -> QPixmap | None:
    """The largest image in an icon file (an .ico holds several), or an SVG
    drawn at 128 px."""
    if not data:
        return None
    head = data[:2000].lstrip()
    if head.startswith(b"<svg") or (head.startswith(b"<?xml") and b"<svg" in head):
        renderer = QSvgRenderer(QByteArray(data))
        if not renderer.isValid():
            return None
        image = QImage(128, 128, QImage.Format.Format_ARGB32_Premultiplied)
        image.fill(Qt.GlobalColor.transparent)
        painter = QPainter(image)
        renderer.render(painter)
        painter.end()
        return QPixmap.fromImage(image)
    buffer = QBuffer()
    buffer.setData(QByteArray(data))
    buffer.open(QIODevice.OpenModeFlag.ReadOnly)
    reader = QImageReader(buffer)
    best = None
    for i in range(max(1, reader.imageCount())):
        if i and not reader.jumpToImage(i):
            break
        image = reader.read()
        if not image.isNull() and (best is None or image.width() > best.width()):
            best = image
    return QPixmap.fromImage(best) if best is not None else None


class LogoThread(QThread):
    """Fetches logos, several sites at once."""
    got = pyqtSignal(str, object)  # domain, bytes | None

    def __init__(self, domains: list[str]) -> None:
        super().__init__()
        self._domains = domains
        self._stop = False

    def stop(self) -> None:
        self._stop = True

    def run(self) -> None:
        with ThreadPoolExecutor(max_workers=6) as pool:
            futures = {pool.submit(logos.logo_for, d): d for d in self._domains}
            for future in as_completed(futures):
                if self._stop:
                    continue
                try:
                    data = future.result()
                except Exception:  # one site's trouble mustn't stop the rest
                    data = None
                self.got.emit(futures[future], data)


class LogoStore(QObject):
    """Logos by website: from memory, the cache folder, or fetched in the
    background; `loaded` says when one arrives."""
    loaded = pyqtSignal(str)

    def __init__(self, parent: QObject | None = None) -> None:
        super().__init__(parent)
        self._pixmaps: dict[str, QPixmap | None] = {}
        self._waiting: list[str] = []
        self._thread: LogoThread | None = None

    def pixmap(self, domain: str) -> QPixmap | None:
        return self._pixmaps.get(domain)

    def request(self, domain: str) -> bool:
        """Start getting a logo; True if it will come later via `loaded`."""
        if domain in self._pixmaps:
            return False
        if domain in self._waiting:
            return True
        known, data = logos.cached(domain)
        if known:
            self._pixmaps[domain] = decode_logo(data)
            return False
        self._waiting.append(domain)
        if self._thread is None:
            QTimer.singleShot(0, self._start)  # one batch for all asked at once
        return True

    def _start(self) -> None:
        if self._thread is not None or not self._waiting:
            return
        batch = [d for d in self._waiting if d not in self._pixmaps]
        self._thread = track(LogoThread(batch))
        self._thread.got.connect(self._got)
        self._thread.finished.connect(self._finished)
        self._thread.start()

    def _got(self, domain: str, data) -> None:
        self._pixmaps[domain] = decode_logo(data)
        if domain in self._waiting:
            self._waiting.remove(domain)
        if self._pixmaps[domain] is not None:
            self.loaded.emit(domain)

    def _finished(self) -> None:
        self._thread = None
        if self._waiting:
            self._start()

    def shutdown(self) -> None:
        if self._thread is not None:
            self._thread.got.disconnect()
            self._thread.finished.disconnect(self._finished)
            self._thread.stop()
            retire(self._thread)
            self._thread = None
