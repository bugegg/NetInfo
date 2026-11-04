"""The main window: toolbar, host grid, ping-history pane and status bar."""

from __future__ import annotations

import itertools
import time

from PyQt6.QtCore import QCoreApplication, QItemSelectionModel, Qt, QTimer, QUrl
from PyQt6.QtGui import (
    QAction,
    QActionGroup,
    QDesktopServices,
    QFont,
    QGuiApplication,
    QKeySequence,
)
from PyQt6.QtWidgets import (
    QAbstractItemView,
    QDialog,
    QFileDialog,
    QFontDialog,
    QHeaderView,
    QLabel,
    QMainWindow,
    QMenu,
    QMessageBox,
    QSplitter,
    QStyle,
    QTableView,
)

from .. import __version__
from ..osinfo import IS_WINDOWS
from ..app_update import AppUpdateError, Release, install_update, is_newer, self_update_supported
from ..fileio import export, hostfile
from ..fileio.vendor_db import VendorDB
from ..model.columns import COLUMNS
from ..model.history import HistoryFilterProxy, HistoryModel, HistoryRecord
from ..model.host import HostEntry
from ..model.samples import SampleStore
from ..model.table_model import HostFilterProxy, HostTableModel
from ..ping import port_scan, snmp_arp
from ..ping.device_info import DeviceInfoJob
from ..ping.engine import EngineOptions
from ..ping.icmp import _IP_DONTFRAG
from ..ping.network_interfaces import list_interfaces as list_network_interfaces
from ..settings import DisplayMode, HistoryMode, Settings
from . import fonts
from .dashboard import Dashboard, apply_theme
from .add_hosts_dialog import AddHostsDialog
from .app_update_thread import UpdateCheckThread, UpdateDownloadThread
from .device_info_thread import DeviceInfoThread
from .lldp_cdp_window import LldpCdpThread, LldpCdpWindow
from .mtu_thread import MtuThread
from .engine_thread import EngineThread
from .network_select_dialog import NetworkSelectDialog
from .options_dialog import OptionsDialog
from .tracepath_window import TracepathThread, TracepathWindow
from .ping_graph import PingGraphWindow
from .vendor_update_thread import VendorUpdateThread

#: How often a host with unresolved MAC/hostname/vendor is tried again. This
#: doubles as the retry delay below, since each attempt lands on a tick.
DEVICE_INFO_REFRESH_MS = 10000
#: One initial attempt plus this many retries (10s apart) before a host that
#: still won't resolve is left alone for the rest of the session.
DEVICE_INFO_MAX_RETRIES = 5
DEVICE_INFO_MAX_ATTEMPTS = DEVICE_INFO_MAX_RETRIES + 1
#: Wait this long after launch before the automatic update check, so it
#: never competes with the window opening and the first pings.
UPDATE_CHECK_DELAY_MS = 3000


class MainWindow(QMainWindow):
    def __init__(self, settings: Settings) -> None:
        # Before any widget exists, so every one starts out in the bundled
        # font (ui/fonts.py), not the system's.
        fonts.load()
        super().__init__()
        self.settings = settings
        self._keys = itertools.count(1)
        self._engine: EngineThread | None = None
        self._dont_fragment_supported = self._probe_dont_fragment_support()
        self._current_file = ""
        self._vendor_db = VendorDB()
        self._vendor_update_thread: VendorUpdateThread | None = None
        self._update_check_thread: UpdateCheckThread | None = None
        self._update_download_thread: UpdateDownloadThread | None = None
        #: The automatic check at launch only speaks up when there's an update.
        self._update_check_silent = True
        self._device_info_thread: DeviceInfoThread | None = None
        self._mtu_thread: MtuThread | None = None
        self._mtu_pending = 0
        #: Hosts the automatic MTU check has already tried, so each is
        #: checked once (Check MTU in the menu re-checks on demand).
        self._mtu_tried: set[int] = set()
        self._lldp_cdp_window: LldpCdpWindow | None = None
        #: Attempts made so far per host key, capped at DEVICE_INFO_MAX_ATTEMPTS.
        self._device_info_attempts: dict[int, int] = {}

        self.setWindowTitle("NetInfoView")
        self.resize(1440, 900)
        self.setMinimumSize(1050, 680)

        self._model = HostTableModel()
        self._model.mark_odd_even = settings.mark_odd_even_rows
        self._model.dark_background = settings.dark_background
        self._proxy = HostFilterProxy()
        self._proxy.setSourceModel(self._model)
        self._proxy.set_display_mode(settings.display_mode)
        self._proxy.set_hide_disabled(settings.hide_disabled)

        self._history = HistoryModel(settings.max_accumulated_pings)
        self._history.mode = settings.history_mode
        self._history_proxy = HistoryFilterProxy()
        self._history_proxy.setSourceModel(self._history)

        #: Every ping per host, for the graph windows (unlike the lower pane,
        #: unaffected by its recording filter).
        self._samples = SampleStore()
        #: The one Ping Graph window: every host graphed while it is open is
        #: overlaid in it, so their latency can be compared over the same time.
        self._graph_window: PingGraphWindow | None = None
        #: When pinging last stopped (None while pinging), so graph windows
        #: freeze on Stop rather than scrolling on with nothing to show.
        self._stopped_at: float | None = time.time()

        self._build_views()
        self._build_actions()
        self._build_context_menu()
        self._register_shortcuts()
        self._last_scan_label = QLabel()
        self.statusBar().addPermanentWidget(self._last_scan_label)
        self.takeCentralWidget()
        self._dashboard = Dashboard(self, list_network_interfaces())
        self.setCentralWidget(self._dashboard)

        self.statusBar().showMessage("0 devices")
        self._apply_view_settings()

        self._device_info_timer = QTimer(self)
        self._device_info_timer.timeout.connect(self._refresh_device_info)
        self._device_info_timer.timeout.connect(self._auto_check_mtu)
        self._device_info_timer.start(DEVICE_INFO_REFRESH_MS)

        # Only the packaged app can replace itself; running from source, the
        # check is left to the Check for Updates toolbar button.
        if self_update_supported():
            QTimer.singleShot(
                UPDATE_CHECK_DELAY_MS, lambda: self.check_for_updates(silent=True)
            )

    # -- construction ------------------------------------------------------

    def _build_views(self) -> None:
        self._table = QTableView()
        self._table.setModel(self._proxy)
        self._table.setSortingEnabled(True)
        self._table.setAlternatingRowColors(False)
        self._table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self._table.setSelectionMode(QAbstractItemView.SelectionMode.ExtendedSelection)
        self._table.setContextMenuPolicy(Qt.ContextMenuPolicy.ActionsContextMenu)
        self._table.verticalHeader().setVisible(False)
        self._table.verticalHeader().setDefaultSectionSize(20)
        header = self._table.horizontalHeader()
        header.setSectionsMovable(True)
        header.setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
        for index, column in enumerate(COLUMNS):
            self._table.setColumnWidth(index, column.width)
        # Sorted by IP Address ascending out of the box.
        ip_address_column = next(i for i, c in enumerate(COLUMNS) if c.key == "ip_address")
        self._table.sortByColumn(ip_address_column, Qt.SortOrder.AscendingOrder)
        self._table.selectionModel().selectionChanged.connect(self._update_status_bar)
        self._table.doubleClicked.connect(self._on_table_double_clicked)

        self._history_view = QTableView()
        self._history_view.setModel(self._history_proxy)
        self._history_view.setSelectionBehavior(
            QAbstractItemView.SelectionBehavior.SelectRows
        )
        self._history_view.verticalHeader().setVisible(False)
        self._history_view.verticalHeader().setDefaultSectionSize(20)
        self._history_view.horizontalHeader().setStretchLastSection(True)
        for index, width in enumerate((150, 170, 130, 180, 110, 60)):
            self._history_view.setColumnWidth(index, width)

        self._splitter = QSplitter(Qt.Orientation.Vertical)
        self._splitter.addWidget(self._table)
        self._splitter.addWidget(self._history_view)
        self._splitter.setStretchFactor(0, 3)
        self._splitter.setStretchFactor(1, 1)
        self._splitter.setSizes([420, 180])
        self.setCentralWidget(self._splitter)

    @staticmethod
    def _probe_dont_fragment_support() -> bool:
        """A throwaway socket, synchronous and closed immediately, to size the
        Options dialog before any asyncio loop (and the real pinger) exists."""
        import socket

        if IS_WINDOWS:
            return True  # IcmpSendEcho always takes the DF flag
        try:
            probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_ICMP)
        except OSError:
            return False
        try:
            probe.setsockopt(socket.IPPROTO_IP, _IP_DONTFRAG, 0)
            return True
        except OSError:
            return False
        finally:
            probe.close()

    def _icon(self, standard: QStyle.StandardPixmap):
        return self.style().standardIcon(standard)

    def _build_actions(self) -> None:
        sp = QStyle.StandardPixmap

        self.action_start = QAction(self._icon(sp.SP_MediaPlay), "&Start Pinging", self)
        self.action_start.setShortcut(QKeySequence("F5"))
        self.action_start.triggered.connect(self.start_pinging)

        self.action_stop = QAction(self._icon(sp.SP_MediaStop), "S&top Pinging", self)
        self.action_stop.setShortcut(QKeySequence("F6"))
        self.action_stop.setEnabled(False)
        self.action_stop.triggered.connect(self.stop_pinging)

        self.action_load = QAction("&Load Host List...", self)
        self.action_load.setShortcut(QKeySequence.StandardKey.Open)
        self.action_load.triggered.connect(self.load_host_list)

        self.action_save_hosts = QAction("Sa&ve Host List...", self)
        self.action_save_hosts.setShortcut(QKeySequence.StandardKey.Save)
        self.action_save_hosts.triggered.connect(self.save_host_list)

        self.action_export = QAction(
            self._icon(sp.SP_DialogSaveButton), "Save &Results...", self
        )
        self.action_export.setShortcut(QKeySequence("Ctrl+Shift+S"))
        self.action_export.triggered.connect(self.export_results)

        self.action_quit = QAction("E&xit", self)
        self.action_quit.setShortcut(QKeySequence.StandardKey.Quit)
        self.action_quit.triggered.connect(self.close)

        self.action_add = QAction(self._icon(sp.SP_FileDialogNewFolder), "&Add Hosts...", self)
        self.action_add.setShortcut(QKeySequence("Ctrl+N"))
        self.action_add.triggered.connect(self.add_hosts)

        self.action_remove = QAction(self._icon(sp.SP_TrashIcon), "&Remove Selected", self)
        self.action_remove.setShortcut(QKeySequence.StandardKey.Delete)
        self.action_remove.triggered.connect(self.remove_selected)

        self.action_clear_all = QAction(self._icon(sp.SP_TrashIcon), "&Clear All Hosts", self)
        self.action_clear_all.setToolTip("Remove every host from the list")
        self.action_clear_all.triggered.connect(self.clear_all_hosts)

        self.action_enable = QAction("&Enable Selected", self)
        self.action_enable.triggered.connect(lambda: self.set_selected_enabled(True))

        self.action_disable = QAction("&Disable Selected", self)
        self.action_disable.triggered.connect(lambda: self.set_selected_enabled(False))

        self.action_copy = QAction(self._icon(sp.SP_FileDialogDetailedView), "&Copy", self)
        self.action_copy.setShortcut(QKeySequence.StandardKey.Copy)
        self.action_copy.triggered.connect(self.copy_selected)

        self.action_select_all = QAction("Select &All", self)
        self.action_select_all.setShortcut(QKeySequence.StandardKey.SelectAll)
        self.action_select_all.triggered.connect(self._table.selectAll)

        self.action_clear_stats = QAction("Clear &Statistics", self)
        self.action_clear_stats.triggered.connect(self.clear_statistics)

        self.action_properties = QAction(
            self._icon(sp.SP_FileDialogInfoView), "&Properties", self
        )
        self.action_properties.setShortcut(QKeySequence("Ctrl+I"))
        self.action_properties.triggered.connect(self.show_properties)

        self.action_graph = QAction("Show Ping &Graph", self)
        self.action_graph.setShortcut(QKeySequence("Ctrl+G"))
        self.action_graph.triggered.connect(self.show_graph)

        self.action_check_mtu = QAction("Check &MTU", self)
        self.action_check_mtu.setToolTip(
            "Find the largest packet that reaches each selected host unfragmented"
        )
        self.action_check_mtu.triggered.connect(self.check_mtu)

        self.action_trace_mtu = QAction("&Trace Path MTU", self)
        self.action_trace_mtu.setToolTip(
            "Show the path MTU to each hop on the way to the selected host, "
            "to find where it drops"
        )
        self.action_trace_mtu.triggered.connect(self.trace_path_mtu)

        self.action_lldp_cdp = QAction(
            self._icon(sp.SP_DriveNetIcon), "Check &LLDP/CDP", self
        )
        self.action_lldp_cdp.setIconText("LLDP/CDP")
        self.action_lldp_cdp.setShortcut(QKeySequence("Ctrl+L"))
        self.action_lldp_cdp.setToolTip(
            "Pick a network interface and listen on it for LLDP/CDP "
            "announcements: which switch, port and VLAN it's plugged into"
        )
        self.action_lldp_cdp.triggered.connect(self.check_lldp_cdp)

        self.action_options = QAction(self._icon(sp.SP_FileDialogListView), "&Options...", self)
        self.action_options.setShortcut(QKeySequence("Ctrl+,"))
        self.action_options.triggered.connect(self.show_options)

        self.action_update_vendor_db = QAction(
            self._icon(sp.SP_BrowserReload), "&Update MAC Vendor Database...", self
        )
        self.action_update_vendor_db.setToolTip(
            "Download the IEEE MAC vendor registry and store it locally"
        )
        self.action_update_vendor_db.triggered.connect(self.update_vendor_database)

        self.action_autosize = QAction("&Auto Size Columns", self)
        self.action_autosize.setShortcut(QKeySequence("Ctrl+Plus"))
        self.action_autosize.triggered.connect(self.auto_size_columns)

        self.action_font = QAction("Choose &Font...", self)
        self.action_font.triggered.connect(self.choose_font)

        self.action_always_on_top = self._checkable(
            "Always On &Top", self.settings.always_on_top, self._toggle_always_on_top
        )
        self.action_dark = self._checkable(
            "&Black Background", self.settings.dark_background, self._toggle_dark
        )
        self.action_odd_even = self._checkable(
            "&Mark Odd/Even Rows", self.settings.mark_odd_even_rows, self._toggle_odd_even
        )
        self.action_hide_disabled = self._checkable(
            "&Hide Disabled Items", self.settings.hide_disabled, self._toggle_hide_disabled
        )
        self.action_show_history = self._checkable(
            "Show &Lower Pane", self.settings.show_history_pane, self._toggle_history_pane
        )
        self.action_auto_scroll = self._checkable(
            "Auto &Scroll Lower Pane", self.settings.auto_scroll_history,
            self._toggle_auto_scroll,
        )
        self.action_clear_history = QAction("&Clear Lower Pane", self)
        self.action_clear_history.triggered.connect(self._history.clear)

        self.action_check_updates = QAction(
            self._icon(sp.SP_ArrowUp), "Check for &Updates...", self
        )
        self.action_check_updates.setToolTip(
            "Check GitHub for a newer version of NetInfoView and install it"
        )
        self.action_check_updates.triggered.connect(lambda: self.check_for_updates())

        self.action_about = QAction("&About", self)
        self.action_about.triggered.connect(self.show_about)

    def _checkable(self, title: str, checked: bool, slot) -> QAction:
        action = QAction(title, self)
        action.setCheckable(True)
        action.setChecked(checked)
        action.toggled.connect(slot)
        return action

    def _add_table_separator(self) -> None:
        """QTableView (unlike QMenu) has no addSeparator() of its own, so
        build the separator QAction by hand for its right-click menu."""
        separator = QAction(self)
        separator.setSeparator(True)
        self._table.addAction(separator)

    def _build_context_menu(self) -> None:
        """The table's right-click menu: what acts on the selected hosts.
        Adding hosts, filtering, exporting and settings live in the sidebar
        and header (ui/dashboard.py), Check LLDP/CDP behind the sidebar's
        Discovery button, and MTU is checked automatically; Enable/Disable, Clear Statistics, Mark Odd/Even Rows, Always
        On Top, Choose Font and the Lower Pane options were dropped
        from the menu (their actions, and any shortcuts, still exist).
        """
        self._table.addAction(self.action_properties)
        self._table.addAction(self.action_graph)
        self._table.addAction(self.action_trace_mtu)
        self._add_table_separator()

        self._table.addAction(self.action_remove)
        self._table.addAction(self.action_clear_all)
        self._add_table_separator()

        # Not on the menu any more (the All/Online/Offline buttons replace
        # them), but _set_display_mode keeps their checks in step.
        display_group = QActionGroup(self)
        self._display_actions: dict[DisplayMode, QAction] = {}
        for mode, title in (
            (DisplayMode.ALL, "Show &All Hosts"),
            (DisplayMode.SUCCEEDED, "Show Only &Succeeded"),
            (DisplayMode.FAILED, "Show Only &Failed"),
        ):
            action = QAction(title, self, checkable=True)
            action.setChecked(self.settings.display_mode is mode)
            action.triggered.connect(lambda _, m=mode: self._set_display_mode(m))
            display_group.addAction(action)
            self._display_actions[mode] = action

        self._table.addAction(self.action_dark)
        self._add_table_separator()
        self._table.addAction(self.action_autosize)

        history_group = QActionGroup(self)
        for mode, title in (
            (HistoryMode.ALL, "Record &Every Ping"),
            (HistoryMode.STATUS_CHANGES, "Record Status &Changes Only"),
            (HistoryMode.FAILED_ONLY, "Record &Failed Pings Only"),
        ):
            action = QAction(title, self, checkable=True)
            action.setChecked(self.settings.history_mode is mode)
            action.triggered.connect(lambda _, m=mode: self._set_history_mode(m))
            history_group.addAction(action)

        self._add_table_separator()
        self._table.addAction(self.action_about)

    def _register_shortcuts(self) -> None:
        """The sidebar and header buttons show these actions, but a shortcut
        only fires for an action on a visible widget: put them all on the
        window itself so F5, Ctrl+N and the rest work wherever focus is."""
        for action in self.findChildren(QAction):
            if not action.shortcut().isEmpty():
                self.addAction(action)

    # -- host list ---------------------------------------------------------

    def _entries_from_parsed(self, parsed) -> list[HostEntry]:
        start = self._model.rowCount()
        return [
            HostEntry(
                key=next(self._keys),
                host=host.host,
                port=host.port,
                description=host.description,
                group=host.group,
                enabled=host.enabled,
                order=start + offset + 1,
            )
            for offset, host in enumerate(parsed)
        ]

    def add_hosts(self) -> None:
        # Start straight away on OK. A running engine already picked the new
        # hosts up through _push_targets. This lives here rather than in
        # _run_add_hosts_dialog, which start_pinging itself calls (via
        # _offer_network_scan) and would otherwise start a second engine.
        if self._run_add_hosts_dialog():
            self.start_pinging()

    def _run_add_hosts_dialog(self) -> bool:
        """Shows Add Hosts, pre-filled with what was entered last time, and
        adds whatever was entered. Returns whether anything was actually
        added, so callers like _offer_network_scan() know whether
        start_pinging() now has something to work with."""
        dialog = AddHostsDialog(
            self,
            self.settings.last_added_hosts,
            skip_first=self.settings.add_hosts_skip_first,
            skip_last=self.settings.add_hosts_skip_last,
            replace=self.settings.add_hosts_replace,
        )
        if dialog.exec() != QDialog.DialogCode.Accepted:
            return False
        self.settings.last_added_hosts = dialog.text()
        self.settings.add_hosts_skip_first = dialog.skip_first()
        self.settings.add_hosts_skip_last = dialog.skip_last()
        self.settings.add_hosts_replace = dialog.replace()
        entries = self._entries_from_parsed(dialog.hosts())
        if not entries:
            return False
        if dialog.replace():
            self._clear_hosts()
        self._model.add_entries(entries)
        self._show_new_hosts()
        self._push_targets()
        self._update_status_bar()
        return True

    def load_host_list(self) -> None:
        path, _ = QFileDialog.getOpenFileName(
            self, "Load Host List", "", "Text files (*.txt);;All files (*)"
        )
        if not path:
            return
        try:
            with open(path, encoding="utf-8", errors="replace") as handle:
                text = handle.read()
        except OSError as exc:
            QMessageBox.warning(self, "Load Host List", f"Could not read the file:\n{exc}")
            return
        try:
            parsed = hostfile.parse_host_list(text)
        except hostfile.HostListError as exc:
            QMessageBox.warning(self, "Load Host List", str(exc))
            return
        self._model.set_entries(self._entries_from_parsed(parsed))
        self._show_new_hosts()
        self._history.clear()
        self._forget_removed_hosts()
        self._current_file = path
        self._push_targets()
        self._update_status_bar()

    def save_host_list(self) -> None:
        path, _ = QFileDialog.getSaveFileName(
            self, "Save Host List", self._current_file or "hosts.txt",
            "Text files (*.txt);;All files (*)",
        )
        if not path:
            return
        try:
            with open(path, "w", encoding="utf-8") as handle:
                handle.write(hostfile.format_host_list(self._model.entries()))
        except OSError as exc:
            QMessageBox.warning(self, "Save Host List", f"Could not write the file:\n{exc}")
            return
        self._current_file = path

    def export_results(self) -> None:
        filters = ";;".join(f"{f.label} (*.{f.extension})" for f in export.ExportFormat)
        path, chosen = QFileDialog.getSaveFileName(self, "Save Results", "", filters)
        if not path:
            return
        fmt = next(
            (f for f in export.ExportFormat if f.label == chosen.rsplit(" (", 1)[0]),
            export.ExportFormat.TEXT,
        )
        entries = self._selected_entries() or self._visible_entries()
        try:
            export.save(path, entries, fmt)
        except OSError as exc:
            QMessageBox.warning(self, "Save Results", f"Could not write the file:\n{exc}")
            return
        self.statusBar().showMessage(f"Saved {len(entries)} item(s) to {path}", 5000)

    # -- selection helpers -------------------------------------------------

    def _selected_rows(self) -> list[int]:
        return sorted(
            {
                self._proxy.mapToSource(index).row()
                for index in self._table.selectionModel().selectedRows()
            }
        )

    def _selected_entries(self) -> list[HostEntry]:
        return [
            entry
            for entry in (self._model.entry_at(row) for row in self._selected_rows())
            if entry is not None
        ]

    def _visible_entries(self) -> list[HostEntry]:
        entries = []
        for row in range(self._proxy.rowCount()):
            entry = self._model.entry_at(self._proxy.mapToSource(self._proxy.index(row, 0)).row())
            if entry is not None:
                entries.append(entry)
        return entries

    def remove_selected(self) -> None:
        rows = self._selected_rows()
        if not rows:
            return
        self._model.remove_rows(rows)
        self._forget_removed_hosts()
        self._push_targets()
        self._update_status_bar()

    def clear_all_hosts(self) -> None:
        """The toolbar trash button: wipes the whole host list, regardless
        of selection — distinct from Remove Selected (right-click menu),
        which only drops the rows you've picked."""
        total = self._model.rowCount()
        if not total:
            return
        answer = QMessageBox.question(
            self,
            "Clear All Hosts",
            f"Remove all {total} host(s) from the list?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No,
        )
        if answer != QMessageBox.StandardButton.Yes:
            return
        self._clear_hosts()
        self._push_targets()
        self._update_status_bar()

    def _clear_hosts(self) -> None:
        """Empty the host list along with everything kept per host."""
        self._model.set_entries([])
        self._history.clear()
        self._forget_removed_hosts()
        self._device_info_attempts.clear()
        self._mtu_tried.clear()

    def set_selected_enabled(self, enabled: bool) -> None:
        for entry in self._selected_entries():
            entry.enabled = enabled
            self._model.refresh_row_for_key(entry.key)
        self._proxy.invalidateFilter()
        self._push_targets()

    def clear_statistics(self) -> None:
        for entry in self._selected_entries() or self._model.entries():
            entry.reset_statistics()
            self._samples.discard(entry.key)
            self._model.refresh_row_for_key(entry.key)

    def copy_selected(self) -> None:
        entries = self._selected_entries() or self._visible_entries()
        if not entries:
            return
        text = export.render(entries, export.ExportFormat.TAB)
        QGuiApplication.clipboard().setText(text)
        self.statusBar().showMessage(f"Copied {len(entries)} item(s)", 3000)

    def show_properties(self) -> None:
        entries = self._selected_entries()
        if not entries:
            return
        body = "\n".join(
            f"{column.title}: {column.display(entries[0])}" for column in COLUMNS
        )
        QMessageBox.information(self, entries[0].display_name, body)

    def _on_table_double_clicked(self, index) -> None:
        entry = self._model.entry_at(self._proxy.mapToSource(index).row())
        if entry is not None:
            self.open_graph(entry.key)

    def show_graph(self) -> None:
        """Graph the selected hosts, overlaid in one window to compare them."""
        keys = [entry.key for entry in self._selected_entries()]
        if keys:
            self.open_graph(*keys)

    def open_graph(self, *keys: int) -> PingGraphWindow:
        """Graph these hosts, overlaid on the graph window if one is already
        open; closing that window starts the next graph afresh."""
        window = self._graph_window
        # A just-closed window lingers until Qt deletes it; don't reuse it.
        if window is None or not window.isVisible():
            window = PingGraphWindow(list(keys), self._samples, self._describe_host, self)
            window.destroyed.connect(self._on_graph_window_destroyed)
            self._graph_window = window
            window.freeze(self._stopped_at)
        else:
            window.add_hosts(list(keys))
        window.show()
        window.raise_()
        window.activateWindow()
        return window

    def _on_graph_window_destroyed(self) -> None:
        self._graph_window = None

    def check_mtu(self) -> None:
        """Path MTU discovery for the selected hosts, in the MTU column."""
        if self._mtu_thread is not None:
            self.statusBar().showMessage("An MTU check is already running", 3000)
            return
        targets = [(e.key, e.ip_address) for e in self._selected_entries() if e.ip_address]
        if not targets:
            self.statusBar().showMessage("Select hosts with an IP address to check MTU", 3000)
            return
        self._start_mtu_check(targets)

    def trace_path_mtu(self) -> TracepathWindow | None:
        """Trace Path MTU to the first selected host, in a window of its own."""
        entry = next((e for e in self._selected_entries() if e.ip_address), None)
        if entry is None:
            self.statusBar().showMessage("Select a host with an IP address to trace", 3000)
            return None
        window = TracepathWindow(entry.display_name, entry.ip_address, self)
        window.show()
        window.raise_()
        window.activateWindow()
        return window

    def check_lldp_cdp(self) -> LldpCdpWindow:
        """Open the LLDP/CDP Status window to pick an interface and check
        it; it's about this Mac's own ports, so the host selection doesn't
        matter. If it's open already, its interface list is refreshed."""
        window = self._lldp_cdp_window
        # A just-closed window lingers until Qt deletes it; don't reuse it.
        if window is not None and window.isVisible():
            window.refresh_interfaces()  # a no-op while it's listening
        else:
            window = LldpCdpWindow(self)
            window.destroyed.connect(self._on_lldp_cdp_window_destroyed)
            self._lldp_cdp_window = window
        window.show()
        window.raise_()
        window.activateWindow()
        return window

    def _on_lldp_cdp_window_destroyed(self) -> None:
        self._lldp_cdp_window = None

    def _auto_check_mtu(self) -> None:
        """Check the MTU of each host once, as soon as it has answered a
        ping, alongside the device-info sweep's timer."""
        if self._mtu_thread is not None:
            return  # still busy; the next tick picks up the rest
        targets = [
            (e.key, e.ip_address)
            for e in self._model.entries()
            if e.enabled
            and e.ip_address
            and e.last_status is not None
            and e.last_status.succeeded
            and e.key not in self._mtu_tried
        ]
        if targets:
            self._start_mtu_check(targets)

    def _start_mtu_check(self, targets: list[tuple[int, str]]) -> None:
        self._mtu_tried.update(key for key, _ in targets)
        self._mtu_pending = len(targets)
        self.statusBar().showMessage(f"Checking MTU of {len(targets)} host(s)...")
        thread = MtuThread(targets)
        thread.result_ready.connect(self._on_mtu_result)
        thread.finished.connect(self._on_mtu_finished)
        self._mtu_thread = thread
        thread.start()

    def _on_mtu_result(self, key: int, mtu: int | None) -> None:
        self._mtu_pending -= 1
        entry = self._model.entry_for_key(key)
        if entry is not None:  # it may have been removed meanwhile
            entry.mtu = mtu
            entry.mtu_no_reply = mtu is None
            self._model.refresh_row_for_key(key)
        if self._mtu_pending:
            self.statusBar().showMessage(f"Checking MTU... {self._mtu_pending} left")

    def _on_mtu_finished(self) -> None:
        thread, self._mtu_thread = self._mtu_thread, None
        if thread is not None:
            thread.wait()
        self.statusBar().showMessage("MTU check finished", 5000)

    def _describe_host(self, key: int) -> tuple[str, str] | None:
        entry = self._model.entry_for_key(key)
        return None if entry is None else (entry.display_name, entry.ip_address)

    def _forget_removed_hosts(self) -> None:
        self._samples.retain({e.key for e in self._model.entries()})

    # -- pinging -----------------------------------------------------------

    def _engine_options(self) -> EngineOptions:
        return EngineOptions.from_settings(self.settings)

    def _push_targets(self) -> None:
        if self._engine is not None:
            self._engine.update_targets([e.to_target() for e in self._model.entries()])

    def start_pinging(self) -> None:
        if self._engine is not None:
            return
        if not self._model.entries() and not self._offer_network_scan():
            return
        targets = [entry.to_target() for entry in self._model.entries()]
        self._engine = EngineThread(targets, self._engine_options())
        self._engine.results_ready.connect(self._on_results)
        self._engine.finished_pinging.connect(self._on_engine_finished)
        self._engine.start()
        self._freeze_graphs(None)
        self.action_start.setEnabled(False)
        self.action_stop.setEnabled(True)
        self._update_status_bar()

    def _offer_network_scan(self) -> bool:
        """No hosts yet: offer to scan a whole connected network, or to type
        hosts/IPs in by hand (the same Add Hosts dialog Edit > Add Hosts uses).

        Returns True once the host list has been populated and start_pinging
        should proceed, False if there was nothing to offer or the user
        cancelled outright.
        """
        interfaces = list_network_interfaces()
        if not interfaces:
            # Nothing to scan, but manual entry is always available.
            return self._run_add_hosts_dialog()

        dialog = NetworkSelectDialog(interfaces, self)
        if dialog.exec() != QDialog.DialogCode.Accepted:
            if dialog.manual_entry_requested:
                return self._run_add_hosts_dialog()
            return False
        iface = dialog.selected_interface()
        if iface is None:
            return False

        try:
            parsed = hostfile.parse_host_list(iface.cidr)
        except hostfile.HostListError as exc:
            # A corporate /8 or the like: too big to scan whole.
            QMessageBox.warning(self, "Scan a Network", str(exc))
            return False
        entries = self._entries_from_parsed(parsed)
        self._model.set_entries(entries)
        self._forget_removed_hosts()
        self._show_new_hosts()
        self._update_status_bar()
        return True

    def stop_pinging(self) -> None:
        if self._engine is not None:
            self._engine.stop_pinging()
            self._freeze_graphs(time.time())

    def _freeze_graphs(self, at: float | None) -> None:
        self._stopped_at = at
        if self._graph_window is not None:
            self._graph_window.freeze(at)

    def _on_engine_finished(self) -> None:
        if self._stopped_at is None:
            self._freeze_graphs(time.time())
        engine, self._engine = self._engine, None
        if engine is not None:
            engine.wait(2000)
        self.action_start.setEnabled(True)
        self.action_stop.setEnabled(False)
        self._update_status_bar()

    def _on_results(self, batch) -> None:
        records: list[HistoryRecord] = []
        for key, result in batch:
            entry = self._model.entry_for_key(key)
            if entry is None:
                continue
            self._samples.add(key, result)
            if self._history.should_record(result, entry.last_status):
                records.append(
                    HistoryRecord(
                        timestamp=result.timestamp,
                        host=entry.display_name,
                        ip=result.destination_ip or entry.ip_address,
                        status=result.status,
                        rtt_ms=result.rtt_ms,
                        ttl=result.ttl,
                        key=key,
                    )
                )
        self._model.apply_results(batch)
        self._history.append_many(records)
        if records and self.settings.auto_scroll_history:
            self._history_view.scrollToBottom()
        if self._proxy.display_mode is not DisplayMode.ALL:
            # The proxy already re-filtered the rows apply_results reported
            # changed (it does for every dataChanged); only the count is new.
            self._update_status_bar()

    def _refresh_device_info(self) -> None:
        """Kick off a background sweep to fill in MAC, hostname, vendor, a
        port-based device-type guess (if enabled) and — for a host entered
        as a name rather than a literal IP — every IP that name resolves to.

        Only hosts whose most recent ping succeeded are considered — a host
        that's down or unreachable has nothing useful to look up. Once a host
        is fully resolved it's left alone for good (resolved once, not
        re-queried); if it still isn't after an attempt, it gets up to
        DEVICE_INFO_MAX_RETRIES more tries, DEVICE_INFO_REFRESH_MS apart,
        then is left alone too rather than retried forever.

        MAC comes from the ARP table (LAN hosts only, plus the routers in
        Options read over SNMP for hosts beyond it), hostname from reverse
        DNS/mDNS, vendor from the local IEEE OUI database keyed off the MAC,
        and the device-type guess from probing a configurable list of common
        ports (ping.port_scan), run for every host that opted into it —
        useful across the board, not just for a host with a locally
        administered MAC (ping.arp.is_locally_administered) that has no
        vendor to find, though that's the case it matters most for.
        All of this is blocking I/O — subprocess calls, DNS queries, TCP
        connects — so it runs on a DeviceInfoThread rather than this (GUI)
        thread: doing it here once scanned a few hundred hosts made the
        whole app freeze every tick waiting on reverse-DNS timeouts.
        """
        if self._device_info_thread is not None:
            return  # previous sweep still running; skip this tick, don't pile up

        custom_ports = port_scan.parse_ports(self.settings.port_scan_ports)
        scan_ports = bool(custom_ports)
        jobs: list[DeviceInfoJob] = []
        for entry in self._model.entries():
            if not entry.ip_address:
                continue
            if entry.last_status is None or not entry.last_status.succeeded:
                continue
            fully_resolved = (
                entry.mac_address and entry.hostname and entry.dns_name and entry.vendor
                and (entry.ports_scanned or not scan_ports)
                and entry.all_ips_resolved
            )
            if fully_resolved:
                continue  # done for good
            attempts = self._device_info_attempts.get(entry.key, 0)
            if attempts >= DEVICE_INFO_MAX_ATTEMPTS:
                continue  # exhausted its retries; leave it alone
            self._device_info_attempts[entry.key] = attempts + 1
            jobs.append(
                DeviceInfoJob(
                    key=entry.key,
                    ip=entry.ip_address,
                    host=entry.host,
                    known_mac=entry.mac_address,
                    needs_hostname=not entry.hostname,
                    needs_dns_name=not entry.dns_name,
                    needs_ports=scan_ports and not entry.ports_scanned,
                    needs_all_ips=not entry.all_ips_resolved,
                )
            )

        if not jobs:
            return

        thread = DeviceInfoThread(
            jobs, self._vendor_db, ports=custom_ports,
            snmp_routers=snmp_arp.parse_routers(self.settings.snmp_arp_routers),
            snmp_community=self.settings.snmp_community,
            snmp_auto=self.settings.snmp_arp_auto,
        )
        thread.results_ready.connect(self._on_device_info_ready)
        thread.finished.connect(self._on_device_info_finished)
        self._device_info_thread = thread
        thread.start()

    def _on_device_info_ready(self, results: list) -> None:
        for result in results:
            entry = self._model.entry_for_key(result.key)
            if entry is None:
                continue
            touched = False
            if result.mac and not entry.mac_address:
                entry.mac_address = result.mac
                touched = True
            if result.hostname and not entry.hostname:
                entry.hostname = result.hostname
                touched = True
            if result.dns_name and not entry.dns_name:
                entry.dns_name = result.dns_name
                touched = True
            if result.vendor and not entry.vendor:
                entry.vendor = result.vendor
                touched = True
            if result.ports_scanned and not entry.ports_scanned:
                entry.ports_scanned = True
                entry.open_ports = result.open_ports
                entry.device_type_guess = result.device_type
                touched = True
            if result.all_ips_looked_up and not entry.all_ips_resolved:
                entry.all_ips_resolved = True
                entry.all_resolved_ips = result.all_ips
                touched = True
            if touched:
                self._model.refresh_row_for_key(entry.key)

    def _on_device_info_finished(self) -> None:
        thread, self._device_info_thread = self._device_info_thread, None
        if thread is not None:
            thread.wait(2000)

    # -- view options ------------------------------------------------------

    def _apply_view_settings(self) -> None:
        self._dashboard.inspector.setVisible(self.settings.show_history_pane)
        self._toggle_always_on_top(self.settings.always_on_top)
        self._apply_palette()
        if self.settings.font_family:
            self._apply_font(QFont(self.settings.font_family, self.settings.font_size or -1))

    def _apply_palette(self) -> None:
        apply_theme(self)

    def _apply_font(self, font: QFont) -> None:
        self._table.setFont(font)
        self._history_view.setFont(font)
        self._table.verticalHeader().setDefaultSectionSize(max(24, font.pointSize() + 12))
        self._history_view.verticalHeader().setDefaultSectionSize(max(24, font.pointSize() + 12))

    def choose_font(self) -> None:
        font, ok = QFontDialog.getFont(self._table.font(), self, "Choose Font")
        if not ok:
            return
        self.settings.font_family = font.family()
        self.settings.font_size = font.pointSize()
        self._apply_font(font)

    def auto_size_columns(self) -> None:
        self._table.resizeColumnsToContents()
        self._history_view.resizeColumnsToContents()

    def _show_new_hosts(self) -> None:
        """Hosts that were just added have never been pinged, so Show Only
        Succeeded/Failed hides every one of them — and since display_mode is
        saved between sessions, adding hosts looked like it did nothing.
        Switch back to Show All Hosts so they're visible."""
        self._dashboard.search.clear()
        if self._proxy.display_mode is not DisplayMode.ALL:
            self._set_display_mode(DisplayMode.ALL)

    def _set_display_mode(self, mode: DisplayMode) -> None:
        self._display_actions[mode].setChecked(True)
        self.settings.display_mode = mode
        self._proxy.set_display_mode(mode)
        self._update_status_bar()

    def _set_history_mode(self, mode: HistoryMode) -> None:
        self.settings.history_mode = mode
        self._history.mode = mode

    def _toggle_hide_disabled(self, checked: bool) -> None:
        self.settings.hide_disabled = checked
        self._proxy.set_hide_disabled(checked)
        self._update_status_bar()

    def _toggle_history_pane(self, checked: bool) -> None:
        self.settings.show_history_pane = checked
        self._dashboard.inspector.setVisible(checked)

    def _toggle_auto_scroll(self, checked: bool) -> None:
        self.settings.auto_scroll_history = checked

    def _toggle_odd_even(self, checked: bool) -> None:
        self.settings.mark_odd_even_rows = checked
        self._model.mark_odd_even = checked
        self._table.viewport().update()

    def _toggle_dark(self, checked: bool) -> None:
        self.settings.dark_background = checked
        self._model.dark_background = checked
        self._apply_palette()

    def _toggle_always_on_top(self, checked: bool) -> None:
        self.settings.always_on_top = checked
        was_visible = self.isVisible()
        self.setWindowFlag(Qt.WindowType.WindowStaysOnTopHint, checked)
        if was_visible:
            self.show()

    def show_options(self) -> None:
        dialog = OptionsDialog(self.settings, self, self._dont_fragment_supported)
        if dialog.exec() != QDialog.DialogCode.Accepted:
            return
        previous, self.settings = self.settings, dialog.result_settings()
        snmp_options = ("snmp_arp_routers", "snmp_community", "snmp_arp_auto")
        if any(getattr(previous, name) != getattr(self.settings, name) for name in snmp_options):
            # New routers to ask may find MACs for hosts that ran out of tries.
            self._device_info_attempts.clear()
        self._history.set_capacity(self.settings.max_accumulated_pings)
        if self._engine is not None:
            self._engine.update_options(self._engine_options())

    def update_vendor_database(self) -> None:
        """Download the IEEE OUI registry and replace the local vendor table."""
        if self._vendor_update_thread is not None:
            return
        self.action_update_vendor_db.setEnabled(False)
        self.statusBar().showMessage("Downloading the IEEE MAC vendor registry...")

        thread = VendorUpdateThread(self._vendor_db)
        thread.succeeded.connect(self._on_vendor_update_succeeded)
        thread.failed.connect(self._on_vendor_update_failed)
        thread.finished.connect(self._on_vendor_update_finished)
        self._vendor_update_thread = thread
        thread.start()

    def _on_vendor_update_succeeded(self, count: int) -> None:
        self.statusBar().showMessage(
            f"MAC vendor database updated: {count:,} entries.", 6000
        )
        # Entries that were waiting on a vendor lookup can resolve immediately.
        for entry in self._model.entries():
            if entry.mac_address and not entry.vendor:
                vendor = self._vendor_db.lookup(entry.mac_address)
                if vendor:
                    entry.vendor = vendor
                    self._model.refresh_row_for_key(entry.key)

    def _on_vendor_update_failed(self, message: str) -> None:
        QMessageBox.warning(self, "Update MAC Vendor Database", message)
        self._update_status_bar()

    def _on_vendor_update_finished(self) -> None:
        thread, self._vendor_update_thread = self._vendor_update_thread, None
        if thread is not None:
            thread.wait(2000)
        self.action_update_vendor_db.setEnabled(True)

    # -- app updates -------------------------------------------------------

    def check_for_updates(self, silent: bool = False) -> None:
        """Ask GitHub Releases for a newer version; offer to install it.

        ``silent`` (the check at launch) stays quiet unless there is one.
        """
        if self._update_check_thread is not None or self._update_download_thread is not None:
            return
        self._update_check_silent = silent
        self.action_check_updates.setEnabled(False)
        if not silent:
            self.statusBar().showMessage("Checking for updates...")
        thread = UpdateCheckThread()
        thread.found.connect(self._on_update_check_found)
        thread.failed.connect(self._on_update_check_failed)
        thread.finished.connect(self._on_update_check_finished)
        self._update_check_thread = thread
        thread.start()

    def _on_update_check_found(self, release: Release) -> None:
        silent = self._update_check_silent
        if not silent:
            self._update_status_bar()
        if not is_newer(release.version):
            if not silent:
                QMessageBox.information(
                    self, "Check for Updates",
                    f"NetInfoView {__version__} is the latest version.",
                )
            return
        box = QMessageBox(self)
        box.setIcon(QMessageBox.Icon.Information)
        box.setWindowTitle("Update Available")
        box.setText(
            f"NetInfoView {release.version} is available "
            f"(you have {__version__})."
        )
        if release.notes:
            box.setDetailedText(release.notes)
        can_install = self_update_supported() and bool(release.asset_url)
        if can_install:
            box.setInformativeText(
                "Install it now? NetInfoView will restart; your settings are kept."
            )
            install = box.addButton("Install and Restart", QMessageBox.ButtonRole.AcceptRole)
        else:
            box.setInformativeText("Open the download page?")
            install = box.addButton("Open Download Page", QMessageBox.ButtonRole.AcceptRole)
        box.addButton("Later", QMessageBox.ButtonRole.RejectRole)
        box.exec()
        if box.clickedButton() is not install:
            return
        if not can_install:
            QDesktopServices.openUrl(QUrl(release.page_url))
            return
        self._start_update_download(release)

    def _on_update_check_failed(self, message: str) -> None:
        if self._update_check_silent:
            return  # offline at launch, say: not worth a dialog
        self._update_status_bar()
        QMessageBox.warning(self, "Check for Updates", message)

    def _on_update_check_finished(self) -> None:
        thread, self._update_check_thread = self._update_check_thread, None
        if thread is not None:
            thread.wait(2000)
        if self._update_download_thread is None:
            self.action_check_updates.setEnabled(True)

    def _start_update_download(self, release: Release) -> None:
        self.action_check_updates.setEnabled(False)
        self.statusBar().showMessage(f"Downloading NetInfoView {release.version}...")
        thread = UpdateDownloadThread(release)
        thread.downloaded.connect(self._on_update_downloaded)
        thread.failed.connect(self._on_update_download_failed)
        thread.finished.connect(self._on_update_download_finished)
        self._update_download_thread = thread
        thread.start()

    def _on_update_downloaded(self, downloaded) -> None:
        try:
            install_update(downloaded)
        except (AppUpdateError, OSError) as exc:
            QMessageBox.warning(self, "Update", f"Could not install the update: {exc}")
            self._update_status_bar()
            return
        self.close()
        QCoreApplication.quit()

    def _on_update_download_failed(self, message: str) -> None:
        QMessageBox.warning(self, "Update", message)
        self._update_status_bar()

    def _on_update_download_finished(self) -> None:
        thread, self._update_download_thread = self._update_download_thread, None
        if thread is not None:
            thread.wait(2000)
        self.action_check_updates.setEnabled(True)

    def show_about(self) -> None:
        last_updated = self._vendor_db.last_updated()
        if last_updated:
            vendor_line = (
                f"MAC vendor database: {self._vendor_db.entry_count():,} entries, "
                f"last updated {last_updated}."
            )
        else:
            vendor_line = (
                "MAC vendor database: not downloaded yet "
                "(Options > Update MAC Vendor Database)."
            )
        QMessageBox.about(
            self,
            "About NetInfoView",
            f"<b>NetInfoView {__version__}</b><br>A ping monitor for macOS.<br><br>"
            "Pings many hosts on an interval over ICMP or TCP and reports "
            "per-host statistics.<br><br>"
            "A clean-room reimplementation of NirSoft's PingInfoView for Windows.<br><br>"
            f"{vendor_line}",
        )

    # -- status bar --------------------------------------------------------

    def _update_status_bar(self, *_) -> None:
        total = self._proxy.rowCount()
        selected = len(self._table.selectionModel().selectedRows())
        state = "Pinging" if self._engine is not None else "Stopped"
        message = f"{total} devices · {state}"
        # Say when a filter is hiding rows, or newly added hosts (not yet
        # pinged) look as if they were never added under Show Only Succeeded.
        hidden = self._model.rowCount() - total
        if hidden:
            message += f" · {hidden} hidden by filter"
        if selected:
            message += f" · {selected} selected"
        self.statusBar().showMessage(message)
        self._history_proxy.set_filter_keys({e.key for e in self._selected_entries()})
        if hasattr(self, "_dashboard"):
            self._dashboard.refresh()

    # -- shutdown ----------------------------------------------------------

    def closeEvent(self, event) -> None:
        if self._engine is not None:
            self._engine.stop_pinging()
            self._engine.wait(3000)
        if self._vendor_update_thread is not None:
            self._vendor_update_thread.wait(3000)
        for thread in (self._update_check_thread, self._update_download_thread):
            if thread is not None:
                thread.wait(3000)
        if self._device_info_thread is not None:
            self._device_info_thread.wait(3000)
        if self._mtu_thread is not None:
            self._mtu_thread.wait(3000)
        for window in self.findChildren(TracepathWindow):
            window.close()
        for window in self.findChildren(LldpCdpWindow):
            window.close()
        for thread in QCoreApplication.instance().findChildren(TracepathThread):
            thread.wait(3000)
        for thread in QCoreApplication.instance().findChildren(LldpCdpThread):
            thread.wait(3000)
        self._vendor_db.close()
        self.settings.save()
        super().closeEvent(event)
