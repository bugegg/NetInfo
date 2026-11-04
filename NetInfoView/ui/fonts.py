"""The fonts NetInfoView ships with, so it reads the same on macOS and Windows
instead of in each system's own UI font (SF Pro / Segoe UI) and monospace
font (Menlo / Consolas), whose different widths made the same layout look
different.

Inter for text and JetBrains Mono for addresses, both under the SIL Open
Font License (see the -OFL.txt files next to them in NetInfoView/fonts/).
"""

from __future__ import annotations

from pathlib import Path

from PyQt6.QtGui import QFont, QFontDatabase
from PyQt6.QtWidgets import QApplication

FONT_DIR = Path(__file__).resolve().parent.parent / "fonts"
UI_FAMILY = "Inter"
MONO_FAMILY = "JetBrains Mono"

_loaded: bool | None = None


def load() -> bool:
    """Register the bundled fonts with Qt (once) and make Inter the
    application's default. False if they couldn't be loaded, in which
    case the system fonts are used as before."""
    global _loaded
    if _loaded is not None:
        return _loaded
    families: set[str] = set()
    for path in sorted(FONT_DIR.glob("*.ttf")):
        font_id = QFontDatabase.addApplicationFont(str(path))
        if font_id >= 0:
            families.update(QFontDatabase.applicationFontFamilies(font_id))
    _loaded = UI_FAMILY in families
    if _loaded:
        font = QFont(UI_FAMILY)
        font.setPixelSize(12)
        # Same hinting on both systems, so glyphs keep the same widths.
        font.setHintingPreference(QFont.HintingPreference.PreferNoHinting)
        # QApplication's, not QGuiApplication's: only it also replaces the
        # per-widget-class fonts macOS sets up (labels, buttons, ...).
        QApplication.setFont(font)
    return _loaded


#: mono() results by size: the grid asks for one for every IP and MAC cell
#: it paints, and building a font (and listing the families) each time
#: shows up in profiles.
_mono_cache: dict[tuple[int, float], QFont] = {}


def mono(size_like: QFont | None = None) -> QFont:
    """The monospaced font for IPs, MACs and raw output, at the pixel size
    of `size_like` if given."""
    size = (0, 0.0) if size_like is None else (size_like.pixelSize(), size_like.pointSizeF())
    cached = _mono_cache.get(size)
    if cached is None:
        cached = _mono_cache[size] = _build_mono(size_like)
    return QFont(cached)


def _build_mono(size_like: QFont | None) -> QFont:
    if load() and MONO_FAMILY in QFontDatabase.families():
        font = QFont(MONO_FAMILY)
        font.setHintingPreference(QFont.HintingPreference.PreferNoHinting)
    else:
        font = QFontDatabase.systemFont(QFontDatabase.SystemFont.FixedFont)
    if size_like is not None:
        if size_like.pixelSize() > 0:
            font.setPixelSize(size_like.pixelSize())
        elif size_like.pointSizeF() > 0:
            font.setPointSizeF(size_like.pointSizeF())
    return font
