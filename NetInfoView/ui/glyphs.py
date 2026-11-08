"""Line icons for the main window, drawn from inline SVG so they stay crisp
at any scale and can be recoloured for the light and dark themes."""

from __future__ import annotations

from PyQt6.QtCore import QByteArray, QRectF, Qt
from PyQt6.QtGui import QIcon, QPainter, QPixmap
from PyQt6.QtSvg import QSvgRenderer

#: 24×24 outlines (the shapes follow the common open-source "Lucide" style).
_PATHS = {
    "overview": '<rect x="3" y="3" width="7" height="7" rx="1"/><rect x="14" y="3" width="7" height="7" rx="1"/>'
                '<rect x="14" y="14" width="7" height="7" rx="1"/><rect x="3" y="14" width="7" height="7" rx="1"/>',
    "devices": '<rect x="2" y="3" width="20" height="14" rx="2"/><path d="M8 21h8M12 17v4"/>',
    "ping": '<circle cx="12" cy="12" r="2"/><path d="M16.24 7.76a6 6 0 0 1 0 8.49M7.76 16.24a6 6 0 0 1 0-8.49'
            'M19.07 4.93a10 10 0 0 1 0 14.14M4.93 19.07a10 10 0 0 1 0-14.14"/>',
    "discovery": '<circle cx="12" cy="12" r="10"/><circle cx="12" cy="12" r="2.5"/>',
    "netpath": '<circle cx="5" cy="12" r="2.5"/><circle cx="19" cy="5" r="2.5"/>'
               '<circle cx="19" cy="19" r="2.5"/><path d="M7.5 12h2.5l6.5-6M10 12l6.5 6"/>',
    "mtu": '<path d="M3 6h18M3 12h12M3 18h7"/><path d="m17 15 3 3-3 3"/>',
    "repeatping": '<path d="M3 12h4l2-5 3 10 2-5h7"/><path d="m18 9 3 3-3 3"/>',
    "portscan": '<rect x="3" y="4" width="18" height="12" rx="2"/><path d="M7 20h10M12 16v4"/>'
                '<path d="M7 8v4M10 8v4M14 8v4M17 8v4"/>',
    "speed": '<path d="M3.34 19a10 10 0 1 1 17.32 0"/><path d="m12 14 4-4"/>',
    "download": '<path d="M12 4v15M6 13l6 6 6-6"/>',
    "upload": '<path d="M12 20V5M6 11l6-6 6 6"/>',
    "copy": '<rect x="8" y="8" width="13" height="13" rx="2"/><path d="M16 8V5a2 2 0 0 0-2-2H5a2 2 0 0 0-2 2v9a2 2 0 0 0 2 2h3"/>',
    "info": '<circle cx="12" cy="12" r="10"/><path d="M12 16v-4M12 8h.01"/>',
    "check": '<circle cx="12" cy="12" r="10" fill="{c}"/><path d="m8 12 3 3 5-6" stroke="#ffffff"/>',
    "globe": '<circle cx="12" cy="12" r="10"/><path d="M2 12h20M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"/>',
    "link": '<path d="M10 13a5 5 0 0 0 7.54.54l3-3a5 5 0 0 0-7.07-7.07l-1.72 1.71"/><path d="M14 11a5 5 0 0 0-7.54-.54l-3 3a5 5 0 0 0 7.07 7.07l1.71-1.71"/>',
    "close": '<path d="M18 6 6 18M6 6l12 12"/>',
    "laptop": '<rect x="4" y="4" width="16" height="11" rx="1.5"/><path d="M2 19h20l-1.5-2.5h-17z"/>',
    "wifi": '<path d="M2 8.8a15 15 0 0 1 20 0M5 12.4a10 10 0 0 1 14 0M8.5 15.9a5 5 0 0 1 7 0"/>'
            '<circle cx="12" cy="19.2" r="1.3" fill="{c}"/>',
    "ethernet": '<rect x="3" y="7" width="18" height="12" rx="2"/><path d="M8 7V4h8v3M7 12v3M10 12v3M14 12v3M17 12v3"/>',
    "rj45": '<rect x="3" y="5" width="18" height="12" rx="1.5"/><path d="M7 17v2h10v-2M7 9v3M10 9v3M14 9v3M17 9v3"/>',
    "cable": '<rect x="2" y="9" width="20" height="6" rx="3"/><path d="M6 12h12"/>',
    "dot": '<circle cx="12" cy="12" r="6" fill="{c}" stroke="none"/>',
    "eye": '<path d="M2 12s3.6-7 10-7 10 7 10 7-3.6 7-10 7S2 12 2 12z"/><circle cx="12" cy="12" r="3"/>',
    "eyeoff": '<path d="M3 3l18 18M10.6 5.1A10.7 10.7 0 0 1 12 5c6.4 0 10 7 10 7a17 17 0 0 1-3.2 4.1'
              'M6.6 6.6C3.9 8.4 2 12 2 12s3.6 7 10 7a9.6 9.6 0 0 0 5.4-1.6M9.9 9.9a3 3 0 0 0 4.2 4.2"/>',
    "settings": '<path d="M12.22 2h-.44a2 2 0 0 0-2 2v.18a2 2 0 0 1-1 1.73l-.43.25a2 2 0 0 1-2 0l-.15-.08'
                'a2 2 0 0 0-2.73.73l-.22.38a2 2 0 0 0 .73 2.73l.15.1a2 2 0 0 1 1 1.72v.51a2 2 0 0 1-1 1.74'
                'l-.15.09a2 2 0 0 0-.73 2.73l.22.38a2 2 0 0 0 2.73.73l.15-.08a2 2 0 0 1 2 0l.43.25a2 2 0 0 1 1 1.73'
                'V20a2 2 0 0 0 2 2h.44a2 2 0 0 0 2-2v-.18a2 2 0 0 1 1-1.73l.43-.25a2 2 0 0 1 2 0l.15.08'
                'a2 2 0 0 0 2.73-.73l.22-.39a2 2 0 0 0-.73-2.73l-.15-.08a2 2 0 0 1-1-1.74v-.5a2 2 0 0 1 1-1.74'
                'l.15-.09a2 2 0 0 0 .73-2.73l-.22-.38a2 2 0 0 0-2.73-.73l-.15.08a2 2 0 0 1-2 0l-.43-.25'
                'a2 2 0 0 1-1-1.73V4a2 2 0 0 0-2-2z"/><circle cx="12" cy="12" r="3"/>',
    "update": '<circle cx="12" cy="12" r="10"/><path d="m16 12-4-4-4 4M12 16V8"/>',
    "play": '<path d="M6 3l14 9-14 9z" fill="{c}"/>',
    "stop": '<rect x="5" y="5" width="14" height="14" rx="2" fill="{c}"/>',
    "export": '<path d="M4 12v8a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2v-8M16 6l-4-4-4 4M12 2v13"/>',
    "search": '<circle cx="11" cy="11" r="7"/><path d="m21 21-4.35-4.35"/>',
    "filter": '<path d="M22 3H2l8 9.46V19l4 2v-8.54z"/>',
    "columns": '<rect x="3" y="3" width="18" height="18" rx="2"/><path d="M9 3v18M15 3v18"/>',
    "chevron": '<path d="m6 9 6 6 6-6"/>',
    "activity": '<path d="M22 12h-4l-3 9L9 3l-3 9H2"/>',
    "brand": '<rect x="0.5" y="0.5" width="23" height="23" rx="6" fill="#087dff" stroke="none"/>'
             '<g stroke="#ffffff" stroke-width="1.6"><path d="M12 5v14M5.5 8.25l13 7.5M5.5 15.75l13-7.5"/>'
             '<circle cx="12" cy="12" r="2.2" fill="#087dff"/></g>',
}


def svg(name: str, color: str, width: float = 1.8) -> bytes:
    body = _PATHS[name].replace("{c}", color)
    return (
        '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" '
        f'stroke="{color}" stroke-width="{width}" stroke-linecap="round" '
        f'stroke-linejoin="round">{body}</svg>'
    ).encode()


def pixmap(name: str, color: str, size: int = 18, pad: int = 0, ratio: float = 2.0) -> QPixmap:
    """The glyph at ``size`` px, with ``pad`` px of empty space to its right
    (a button has no setting for the gap between its icon and text)."""
    px = QPixmap(int((size + pad) * ratio), int(size * ratio))
    px.fill(Qt.GlobalColor.transparent)
    painter = QPainter(px)
    QSvgRenderer(QByteArray(svg(name, color))).render(
        painter, QRectF(0, 0, size * ratio, size * ratio))
    painter.end()
    px.setDevicePixelRatio(ratio)
    return px


def icon(name: str, color: str, size: int = 18, pad: int = 0) -> QIcon:
    return QIcon(pixmap(name, color, size, pad))
