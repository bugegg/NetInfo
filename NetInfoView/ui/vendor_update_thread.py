"""Runs the IEEE OUI registry fetch off the GUI thread.

One fetch-and-done job, unlike EngineThread's repeating ping loop, so this is
a plain QThread.run() rather than an asyncio loop with a stop() method.
"""

from __future__ import annotations

from PyQt6.QtCore import QThread, pyqtSignal

from ..fileio.vendor_db import VendorDB
from ..ping.vendor_update import VendorUpdateError, run_update


class VendorUpdateThread(QThread):
    succeeded = pyqtSignal(int)  # entry count stored
    failed = pyqtSignal(str)  # error message

    def __init__(self, vendor_db: VendorDB) -> None:
        super().__init__()
        self._vendor_db = vendor_db

    def run(self) -> None:  # noqa: D102 - QThread entry point
        try:
            count = run_update(self._vendor_db)
        except VendorUpdateError as exc:
            self.failed.emit(str(exc))
        except Exception as exc:  # defensive: never let an update silently vanish
            self.failed.emit(f"Unexpected error: {exc}")
        else:
            self.succeeded.emit(count)
