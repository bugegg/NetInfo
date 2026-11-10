"""Runs a MAC vendor database update off the GUI thread.

One fetch-and-done job, unlike EngineThread's repeating ping loop, so this is
a plain QThread.run() rather than an asyncio loop with a stop() method.
"""

from __future__ import annotations

from PyQt6.QtCore import QThread, pyqtSignal

from ..fileio.vendor_db import VendorDB
from ..ping.vendor_update import VendorUpdateError, mark_checked, update


class VendorUpdateThread(QThread):
    succeeded = pyqtSignal(int)  # entry count now held; 0 when already up to date
    failed = pyqtSignal(str)  # error message

    def __init__(self, vendor_db: VendorDB, auto: bool = False) -> None:
        super().__init__()
        self._vendor_db = vendor_db
        #: The monthly check tries GitHub's ready-made copy first; the menu
        #: item goes straight to IEEE for the very latest.
        self.auto = auto

    def run(self) -> None:  # noqa: D102 - QThread entry point
        try:
            count = update(self._vendor_db, prefer_github=self.auto)
            if self.auto:
                mark_checked(self._vendor_db)
        except VendorUpdateError as exc:
            self.failed.emit(str(exc))
        except Exception as exc:  # defensive: never let an update silently vanish
            self.failed.emit(f"Unexpected error: {exc}")
        else:
            self.succeeded.emit(count)
