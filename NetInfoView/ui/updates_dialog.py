"""Updates: one window for both kinds of update — the app itself, and the
MAC vendor database it names devices with. The main window runs the
checks and downloads and reports their progress here."""

from __future__ import annotations

import html

from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import (
    QDialog,
    QFrame,
    QGridLayout,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QVBoxLayout,
)

from .. import __version__


def _label(text: str = "", name: str = "") -> QLabel:
    label = QLabel(text)
    if name:
        label.setObjectName(name)
    label.setWordWrap(True)
    label.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
    return label


class UpdatesDialog(QDialog):
    """``window`` is the MainWindow: its check_for_updates,
    install_release and update_vendor_database do the work and call back
    the set_* methods below."""

    def __init__(self, window) -> None:
        super().__init__(window)
        self.window = window
        self._release = None
        self.setWindowTitle("Updates")
        self.setMinimumWidth(440)

        grid = QGridLayout()
        grid.setHorizontalSpacing(16)
        grid.setVerticalSpacing(4)
        grid.setColumnStretch(0, 1)

        # NetInfoView itself.
        grid.addWidget(_label(f"<b>NetInfoView</b> &nbsp;v{__version__}"), 0, 0)
        self.app_status = _label("", "muted")
        grid.addWidget(self.app_status, 1, 0)
        self.app_button = QPushButton("Check Again")
        self.app_button.clicked.connect(self._app_clicked)
        grid.addWidget(self.app_button, 0, 1, 2, 1, Qt.AlignmentFlag.AlignVCenter)

        rule = QFrame()
        rule.setObjectName("rule")
        rule.setFixedHeight(1)
        grid.addWidget(rule, 2, 0, 1, 2)
        grid.setRowMinimumHeight(2, 20)

        # The MAC vendor database.
        grid.addWidget(_label("<b>MAC vendor database</b>"), 3, 0)
        self.vendor_status = _label("", "muted")
        grid.addWidget(self.vendor_status, 4, 0)
        self.vendor_button = QPushButton("Update Now")
        self.vendor_button.clicked.connect(self._vendor_clicked)
        grid.addWidget(self.vendor_button, 3, 1, 2, 1, Qt.AlignmentFlag.AlignVCenter)

        close = QPushButton("Close")
        close.setDefault(True)
        close.clicked.connect(self.close)
        buttons = QHBoxLayout()
        buttons.addStretch()
        buttons.addWidget(close)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 18, 20, 16)
        layout.setSpacing(18)
        layout.addLayout(grid)
        layout.addLayout(buttons)

        self.show_vendor_info()

    # -- the app -----------------------------------------------------------

    def _app_clicked(self) -> None:
        if self._release is not None:
            self.window.install_release(self._release)
        else:
            self.window.check_for_updates()

    def set_app_checking(self) -> None:
        self._release = None
        self.app_status.setText("Checking for updates…")
        self.app_button.setText("Check Again")
        self.app_button.setEnabled(False)

    def set_app_latest(self) -> None:
        self._release = None
        self.app_status.setText("✓ Up to date: this is the latest version.")
        self.app_button.setText("Check Again")
        self.app_button.setEnabled(True)

    def set_app_available(self, release, can_install: bool) -> None:
        self._release = release
        self.app_status.setText(
            f"<b style='color:#087dff'>Version {html.escape(release.version)} is available.</b> "
            + ("Installing restarts NetInfoView; your settings are kept."
               if can_install else "Download it from the release page."))
        self.app_status.setToolTip(release.notes or "")
        self.app_button.setText("Install and Restart" if can_install else "Open Download Page")
        self.app_button.setEnabled(True)

    def set_app_downloading(self, version: str) -> None:
        self.app_status.setText(html.escape(f"Downloading version {version}…"))
        self.app_button.setEnabled(False)

    def set_app_error(self, message: str) -> None:
        self._release = None
        self.app_status.setText(f"<span style='color:#e5484d'>✗ {html.escape(message)}</span>")
        self.app_button.setText("Check Again")
        self.app_button.setEnabled(True)

    # -- the vendor database -----------------------------------------------

    def _vendor_clicked(self) -> None:
        self.window.update_vendor_database()

    def show_vendor_info(self, note: str = "") -> None:
        db = self.window._vendor_db
        last = db.last_updated()
        info = (html.escape(f"{db.entry_count():,} entries, last updated {last}.") if last
                else "Not downloaded yet.")
        self.vendor_status.setText(f"{note}<br>{info}" if note else info)
        self.vendor_button.setEnabled(self.window._vendor_update_thread is None)

    def set_vendor_busy(self) -> None:
        self.vendor_status.setText("Downloading the IEEE MAC vendor registry…")
        self.vendor_button.setEnabled(False)

    def set_vendor_done(self, count: int) -> None:
        self.show_vendor_info("✓ Already up to date." if not count
                              else f"✓ Updated: {count:,} entries.")

    def set_vendor_error(self, message: str) -> None:
        self.show_vendor_info(f"<span style='color:#e5484d'>✗ {html.escape(message)}</span>")
