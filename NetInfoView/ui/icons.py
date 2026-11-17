"""The green/red/grey status dots in the table's first column, drawn at
runtime rather than shipped as image files."""

from __future__ import annotations

from PyQt6.QtCore import QRectF, Qt
from PyQt6.QtGui import QBrush, QColor, QIcon, QPainter, QPen, QPixmap

from ..ping.result import PingStatus

_CACHE: dict[str, QIcon] = {}

_COLOURS = {
    "succeeded": (QColor(60, 190, 60), QColor(30, 120, 30)),
    "failed": (QColor(225, 55, 45), QColor(140, 25, 20)),
    # Darker than "unknown": nothing answers at that address (e.g. no device
    # on the LAN), which is a different story from a host that went down.
    "unreachable": (QColor(130, 130, 130), QColor(80, 80, 80)),
    "unknown": (QColor(190, 190, 190), QColor(120, 120, 120)),
    "disabled": (QColor(225, 225, 225), QColor(160, 160, 160)),
}


def status_icon(name: str) -> QIcon:
    """A 16px dot: filled with the status colour, with a darker rim."""
    cached = _CACHE.get(name)
    if cached is not None:
        return cached

    fill, rim = _COLOURS.get(name, _COLOURS["unknown"])
    pixmap = QPixmap(16, 16)
    pixmap.fill(Qt.GlobalColor.transparent)
    painter = QPainter(pixmap)
    painter.setRenderHint(QPainter.RenderHint.Antialiasing)
    painter.setBrush(QBrush(fill))
    painter.setPen(QPen(rim, 1.2))
    painter.drawEllipse(QRectF(3.0, 3.0, 10.0, 10.0))
    painter.end()

    icon = QIcon(pixmap)
    _CACHE[name] = icon
    return icon


def icon_name_for(entry) -> str:
    if not entry.enabled:
        return "disabled"
    if entry.last_status is None:
        return "unknown"
    if entry.last_status.succeeded:
        return "succeeded"
    if entry.last_status is PingStatus.HOST_UNREACHABLE:
        return "unreachable"
    return "failed"
