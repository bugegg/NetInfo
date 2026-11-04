"""The green/red/grey status dots from PingInfoView's first column, plus the
toolbar's gear icon — all drawn at runtime rather than shipped as image
files, since Qt has no built-in gear glyph to fall back on."""

from __future__ import annotations

import math

from PyQt6.QtCore import QPointF, QRectF, Qt
from PyQt6.QtGui import QBrush, QColor, QIcon, QPainter, QPainterPath, QPen, QPixmap

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


def gear_icon(size: int = 22, teeth: int = 8, colour: QColor | None = None) -> QIcon:
    """A simple cog/gear glyph for the toolbar's settings button: a ring of
    teeth around a solid body, with a hole punched through the centre.

    Built as one closed polygon (the teeth' own inner vertices already trace
    the body between them, so no separate hub shape is needed) and then the
    centre hole is cut with QPainterPath.subtracted() — path boolean
    subtraction, rather than drawing an overlapping circle under
    OddEvenFill, which XORs overlapping fills into a hole exactly where the
    teeth and a separate hub shape coincide.
    """
    colour = colour or QColor(70, 70, 70)
    pixmap = QPixmap(size, size)
    pixmap.fill(Qt.GlobalColor.transparent)
    painter = QPainter(pixmap)
    painter.setRenderHint(QPainter.RenderHint.Antialiasing)

    centre = QPointF(size / 2, size / 2)
    outer_r = size * 0.46
    inner_r = size * 0.30  # the body the teeth sit on top of
    hole_r = size * 0.13
    tooth_half_width = math.pi / teeth * 0.42  # radians

    body = QPainterPath()
    for i in range(teeth):
        mid = 2 * math.pi * i / teeth
        a0, a1 = mid - tooth_half_width, mid + tooth_half_width
        p_out0 = centre + QPointF(outer_r * math.cos(a0), outer_r * math.sin(a0))
        p_out1 = centre + QPointF(outer_r * math.cos(a1), outer_r * math.sin(a1))
        p_in1 = centre + QPointF(inner_r * math.cos(a1), inner_r * math.sin(a1))
        next_mid = 2 * math.pi * (i + 1) / teeth
        p_in_next = centre + QPointF(
            inner_r * math.cos(next_mid - tooth_half_width),
            inner_r * math.sin(next_mid - tooth_half_width),
        )
        if i == 0:
            body.moveTo(p_out0)
        else:
            body.lineTo(p_out0)
        body.lineTo(p_out1)
        body.lineTo(p_in1)
        body.lineTo(p_in_next)
    body.closeSubpath()

    hole = QPainterPath()
    hole.addEllipse(centre, hole_r, hole_r)

    painter.setBrush(QBrush(colour))
    painter.setPen(Qt.PenStyle.NoPen)
    painter.drawPath(body.subtracted(hole))
    painter.end()
    return QIcon(pixmap)


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
