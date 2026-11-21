"""Windows: no icon in the title bar of NetInfoView's windows.

Qt registers its window class with the system's generic application icon,
and Windows draws a window's small icon at the left of its caption. A window
with ``WS_EX_DLGMODALFRAME`` and no icon of its own — none sent with
``WM_SETICON`` and none on its class — gets no caption icon at all. The
taskbar and Alt+Tab take the icon from the .exe itself, so they keep it.

The class is shared by every Qt top-level window, so clearing its icons once
is enough; the extended style and the frame refresh are per window, applied
as each one is first shown. Everything here is a no-op off Windows.
"""

from __future__ import annotations

import ctypes
import sys

from PyQt6.QtCore import QEvent, QObject, Qt
from PyQt6.QtWidgets import QApplication, QWidget

GWL_EXSTYLE = -20
GCLP_HICON = -14
GCLP_HICONSM = -34
WS_EX_DLGMODALFRAME = 0x0001
WM_SETICON = 0x0080
ICON_SMALL, ICON_BIG = 0, 1
# SWP_NOSIZE | SWP_NOMOVE | SWP_NOZORDER | SWP_FRAMECHANGED: redraw the frame only.
SWP_REFRESH_FRAME = 0x0001 | 0x0002 | 0x0004 | 0x0020

#: Window types that have a caption; popups, tooltips and the like do not.
_CAPTIONED = (Qt.WindowType.Window, Qt.WindowType.Dialog)


def _user32():
    user32 = ctypes.windll.user32
    ptr = ctypes.c_ssize_t
    hwnd = ctypes.c_void_p
    user32.GetWindowLongPtrW.argtypes = [hwnd, ctypes.c_int]
    user32.GetWindowLongPtrW.restype = ptr
    user32.SetWindowLongPtrW.argtypes = [hwnd, ctypes.c_int, ptr]
    user32.SetWindowLongPtrW.restype = ptr
    user32.SetClassLongPtrW.argtypes = [hwnd, ctypes.c_int, ptr]
    user32.SetClassLongPtrW.restype = ptr
    user32.SendMessageW.argtypes = [hwnd, ctypes.c_uint, ptr, ptr]
    user32.SendMessageW.restype = ptr
    user32.SetWindowPos.argtypes = [hwnd, hwnd, ctypes.c_int, ctypes.c_int,
                                    ctypes.c_int, ctypes.c_int, ctypes.c_uint]
    return user32


def hide_icon(hwnd: int) -> None:
    """Take the caption icon off one native window."""
    user32 = _user32()
    style = user32.GetWindowLongPtrW(hwnd, GWL_EXSTYLE)
    user32.SetWindowLongPtrW(hwnd, GWL_EXSTYLE, style | WS_EX_DLGMODALFRAME)
    user32.SendMessageW(hwnd, WM_SETICON, ICON_SMALL, 0)
    user32.SendMessageW(hwnd, WM_SETICON, ICON_BIG, 0)
    user32.SetClassLongPtrW(hwnd, GCLP_HICONSM, 0)
    user32.SetClassLongPtrW(hwnd, GCLP_HICON, 0)
    user32.SetWindowPos(hwnd, None, 0, 0, 0, 0, SWP_REFRESH_FRAME)


class _HideIcons(QObject):
    """Strips the caption icon from each captioned window as it is shown."""

    def eventFilter(self, obj: QObject, event: QEvent) -> bool:  # noqa: N802 (Qt API)
        if (event.type() == QEvent.Type.Show and isinstance(obj, QWidget)
                and obj.isWindow() and obj.windowType() in _CAPTIONED
                and not obj.property("_niv_no_icon")):
            obj.setProperty("_niv_no_icon", True)
            try:
                hide_icon(int(obj.winId()))
            except (AttributeError, OSError):
                pass  # cosmetic only: never let it break a window
        return False


def install(app: QApplication) -> None:
    if sys.platform != "win32":
        return
    hider = _HideIcons(app)
    app.installEventFilter(hider)
