"""Runs the GitHub Releases check, and then the download, off the GUI thread."""

from __future__ import annotations

from pathlib import Path

from PyQt6.QtCore import QThread, pyqtSignal

from ..app_update import AppUpdateError, Release, download_and_extract, fetch_latest_release


class UpdateCheckThread(QThread):
    found = pyqtSignal(object)  # Release
    failed = pyqtSignal(str)

    def run(self) -> None:  # noqa: D102 - QThread entry point
        try:
            release = fetch_latest_release()
        except AppUpdateError as exc:
            self.failed.emit(str(exc))
        except Exception as exc:  # defensive: never let a check silently vanish
            self.failed.emit(f"Unexpected error: {exc}")
        else:
            self.found.emit(release)


class UpdateDownloadThread(QThread):
    downloaded = pyqtSignal(object)  # Path of the new .app
    failed = pyqtSignal(str)

    def __init__(self, release: Release) -> None:
        super().__init__()
        self._release = release

    def run(self) -> None:  # noqa: D102 - QThread entry point
        try:
            new_app: Path = download_and_extract(self._release)  # .app or installer
        except AppUpdateError as exc:
            self.failed.emit(str(exc))
        except Exception as exc:
            self.failed.emit(f"Unexpected error: {exc}")
        else:
            self.downloaded.emit(new_app)
