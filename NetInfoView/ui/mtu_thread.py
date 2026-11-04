"""Runs ping.mtu.find_many off the GUI thread for Check MTU, shaped like
ui/device_info_thread.py: one sweep, then done."""

from __future__ import annotations

from PyQt6.QtCore import QThread, pyqtSignal

from ..ping.mtu import find_many


class MtuThread(QThread):
    #: (host key, MTU in bytes or None when the host didn't answer), per host
    #: as soon as it's known.
    result_ready = pyqtSignal(int, object)

    def __init__(self, targets: list[tuple[int, str]]) -> None:
        super().__init__()
        self._targets = targets

    def run(self) -> None:  # noqa: D102 - QThread entry point
        find_many(self._targets, self.result_ready.emit)
