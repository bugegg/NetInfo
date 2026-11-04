"""Interaction coverage for the redesigned monitoring shell."""
from test_main_window import window, qapp, _entries_with_statuses
from NetInfoView.ping.result import PingResult, PingStatus
from NetInfoView.settings import DisplayMode
from NetInfoView.model.columns import COLUMNS


def test_search_combines_with_status_filter(window):
    entries = _entries_with_statuses(window, '10.0.0.1\n10.0.0.2\n10.0.0.3')
    entries[0].hostname = 'Office-Router'
    entries[1].hostname = 'Office-Printer'
    entries[0].apply(PingResult(PingStatus.SUCCEEDED, 4))
    entries[1].apply(PingResult(PingStatus.TIMEOUT))
    window._model.set_entries(entries)
    window._dashboard.search.setText('OFFICE')
    assert window._proxy.rowCount() == 2
    window._set_display_mode(DisplayMode.SUCCEEDED)
    assert window._proxy.rowCount() == 1
    window._dashboard.filter_buttons[DisplayMode.FAILED].click()
    assert window._proxy.rowCount() == 1
    assert window._proxy.mapToSource(window._proxy.index(0, 0)).row() == 1
    window._dashboard.search.clear()
    window._set_display_mode(DisplayMode.ALL)
    assert window._proxy.rowCount() == 3


def test_summary_uses_real_results_and_does_not_count_pending_as_offline(window):
    entries = _entries_with_statuses(window, '10.0.0.1\n10.0.0.2\n10.0.0.3')
    entries[0].apply(PingResult(PingStatus.SUCCEEDED, 4))
    entries[1].apply(PingResult(PingStatus.TIMEOUT))
    window._dashboard.refresh()
    assert [s.text() for s in window._dashboard.stats] == ['3', '1', '1', '4 ms']
    window._dashboard.search.setText('missing')
    assert window._proxy.rowCount() == 0
    assert window._dashboard.stats[0].text() == '3'


def test_inspector_tracks_selection_and_lower_pane_visibility(window):
    entries = _entries_with_statuses(window, '10.0.0.1\n10.0.0.2')
    entries[0].hostname = 'Router'
    window._table.selectRow(0)
    assert 'Router' in window._dashboard.selection_title.text()
    assert window._history_proxy.filter_keys == {entries[0].key}
    window._toggle_history_pane(False)
    assert window._dashboard.inspector.isHidden()
    window._toggle_history_pane(True)
    assert not window._dashboard.inspector.isHidden()
    window._table.clearSelection()
    assert window._dashboard.selection_title.text() == 'Select a device to inspect'


def test_columns_menu_retains_access_to_every_existing_column(window):
    from PyQt6.QtWidgets import QToolButton
    from NetInfoView.ui.dashboard import EXCLUDED_COLUMNS, grid_title
    button = next(b for b in window._dashboard.findChildren(QToolButton) if b.text() == 'Columns')
    offered = [c for c in COLUMNS if c.key not in EXCLUDED_COLUMNS]
    assert [a.text() for a in button.menu().actions()] == [grid_title(c) for c in offered]
    index = next(i for i, c in enumerate(COLUMNS) if c.key == 'open_ports')
    assert window._table.isColumnHidden(index)
    next(a for a in button.menu().actions() if a.text() == 'Open Ports').trigger()
    assert not window._table.isColumnHidden(index)


def test_latency_axis_ticks_are_whole_numbers_and_labels_fit():
    from NetInfoView.ui.dashboard import x_intervals, y_steps

    assert y_steps(250) == 5  # 0, 50, ... 250, not 62.5 steps
    assert all(float(c / y_steps(c)).is_integer() for c in (10, 12, 15, 20, 25, 30, 40, 60, 80))
    assert x_intervals(600, 70) == 6
    assert x_intervals(330, 70) == 4
    assert x_intervals(200, 70) == 2


def test_buttons_keep_their_own_label_when_the_action_changes(window):
    from PyQt6.QtWidgets import QToolButton

    button = window._dashboard.nav_settings
    icon_key = button.icon().cacheKey()
    window.action_options.setEnabled(False)
    assert not button.isEnabled()
    window.action_options.setEnabled(True)
    assert button.isEnabled() and button.text() == 'Settings'
    assert button.icon().cacheKey() == icon_key


def test_an_unnamed_host_is_not_titled_with_its_address_twice(window):
    entries = _entries_with_statuses(window, '10.0.0.1\n10.0.0.2')
    entries[0].ip_address = '10.0.0.1'
    entries[1].ip_address, entries[1].hostname = '10.0.0.2', 'Router'
    window._model.set_entries(entries)
    dashboard = window._dashboard
    window._table.selectRow(0)
    assert dashboard.selection_title.text() == '10.0.0.1'
    assert dashboard.selection_ip.isHidden()
    window._table.selectRow(1)
    assert dashboard.selection_title.text() == 'Router'
    assert not dashboard.selection_ip.isHidden() and dashboard.selection_ip.text() == '10.0.0.2'


def test_hostname_fills_spare_width_and_can_still_be_resized(window):
    from NetInfoView.ui.dashboard import STRETCH_MIN_WIDTH, column_index
    from PyQt6.QtWidgets import QHeaderView

    dashboard = window._dashboard
    header = window._table.horizontalHeader()
    host = column_index('hostname')
    window.resize(1900, 900)
    window.show()
    dashboard.fit_stretch_column()
    assert header.sectionResizeMode(host) == QHeaderView.ResizeMode.Interactive
    visible = [i for i in range(header.count()) if not header.isSectionHidden(i)]
    assert sum(header.sectionSize(i) for i in visible) == window._table.viewport().width()

    # Show every column: Hostname keeps a usable width instead of collapsing.
    for i in range(header.count()):
        dashboard.set_column_visible(i, True)
    assert header.sectionSize(host) >= STRETCH_MIN_WIDTH

    # Dragged by hand: it keeps that width from then on.
    header.resizeSection(host, 333)
    window.resize(1700, 900)
    dashboard.fit_stretch_column()
    assert header.sectionSize(host) == 333
    window.hide()



def test_the_added_host_column_is_not_offered(window):
    from PyQt6.QtWidgets import QToolButton
    from NetInfoView.ui.dashboard import column_index

    assert window._table.isColumnHidden(column_index('host_name'))
    button = next(b for b in window._dashboard.findChildren(QToolButton) if b.text() == 'Columns')
    names = [a.text() for a in button.menu().actions()]
    assert names.count('Hostname') == 1 and 'Host Name' not in names and 'Added as' not in names


def test_count_columns_have_short_titles(window):
    from PyQt6.QtCore import Qt
    from PyQt6.QtWidgets import QToolButton
    from NetInfoView.ui.dashboard import column_index

    def title(key):
        return window._proxy.headerData(column_index(key), Qt.Orientation.Horizontal,
                                        Qt.ItemDataRole.DisplayRole)

    assert (title('total_sent'), title('succeed_count'), title('failed_count')) == (
        'Total', 'Succeed', 'Failed')
    button = next(b for b in window._dashboard.findChildren(QToolButton) if b.text() == 'Columns')
    names = [a.text() for a in button.menu().actions()]
    assert 'Succeed' in names and 'Failed' in names and 'Succeed Count' not in names
    assert 'Total' in names and 'Total Sent Pings' not in names


def test_open_ports_are_listed_one_per_line(window):
    entries = _entries_with_statuses(window, '10.0.0.1')
    entries[0].ip_address = '10.0.0.1'
    entries[0].open_ports = ['53/udp', 139, 445]
    window._model.set_entries(entries)
    window._table.selectRow(0)
    from NetInfoView.ui.dashboard import open_ports_html

    shown = window._dashboard.overview_fields['Open ports'].text()
    assert shown == open_ports_html(['53/udp', 139, 445])
    assert shown.count('<tr>') == 3



def test_open_ports_are_named_by_their_service():
    from NetInfoView.ui.dashboard import open_ports_html, service_name

    assert service_name(22) == 'SSH'
    assert service_name('161/udp') == 'SNMP'
    assert service_name(443) == 'HTTPS'
    assert service_name(25) == 'SMTP'  # not a scanner default: the OS services database
    assert service_name(64999) == ''
    assert service_name('junk') == ''
    shown = open_ports_html([22, '161/udp', 64999])
    assert '<td style=\'padding-right:14px\'>SSH</td><td>22</td>' in shown
    assert '<td style=\'padding-right:14px\'>—</td><td>64999</td>' in shown


def test_settings_opens_the_options_dialog(window):
    opened = []
    window.action_options.triggered.disconnect()
    window.action_options.triggered.connect(lambda: opened.append(True))
    settings = window._dashboard.nav_settings
    assert settings.menu() is None  # no drop-down in the way
    settings.click()
    assert opened == [True]
    for action in (window.action_dark, window.action_about):
        assert action in window._table.actions()


def test_devices_opens_add_hosts(window):
    opened = []
    window.action_add.triggered.disconnect()
    window.action_add.triggered.connect(lambda: opened.append(True))
    devices = window._dashboard.nav_devices
    assert devices.menu() is None
    devices.click()
    assert opened == [True]
    for action in (window.action_remove, window.action_clear_all, window.action_properties):
        assert action in window._table.actions()



def test_right_click_menu_keeps_only_host_actions_and_view_toggles(window):
    names = [a.text() for a in window._table.actions() if not a.isSeparator()]
    assert names == [
        window.action_properties.text(), window.action_graph.text(),
        window.action_trace_mtu.text(), window.action_net_path.text(),
        window.action_remove.text(), window.action_clear_all.text(),
        window.action_dark.text(), window.action_autosize.text(), window.action_about.text(),
    ]
    # Dropped from the menu, still working through their shortcuts.
    for action in (window.action_copy, window.action_add, window.action_load):
        assert action not in window._table.actions() and action in window.actions()


def test_vendor_database_update_sits_with_check_for_updates(window):
    from PyQt6.QtWidgets import QToolButton

    assert window.action_update_vendor_db in window._dashboard.nav_updates.menu().actions()


def test_discovery_opens_lldp_cdp(window):
    opened = []
    window.action_lldp_cdp.triggered.disconnect()
    window.action_lldp_cdp.triggered.connect(lambda: opened.append(True))
    discovery = window._dashboard.nav_discovery
    assert discovery.menu() is None
    discovery.click()
    assert opened == [True]
    assert window.action_trace_mtu in window._table.actions()


def test_the_bundled_fonts_are_used_on_every_system(window):
    from PyQt6.QtGui import QFontDatabase, QFontInfo
    from PyQt6.QtWidgets import QApplication
    from NetInfoView.ui import fonts

    assert fonts.load()
    assert {fonts.UI_FAMILY, fonts.MONO_FAMILY} <= set(QFontDatabase.families())
    assert QApplication.font().family() == fonts.UI_FAMILY
    assert QFontInfo(window._dashboard.stats[0].font()).family() == fonts.UI_FAMILY
    assert fonts.mono().family() == fonts.MONO_FAMILY
    # The fonts' licences ship with them.
    assert (fonts.FONT_DIR / 'Inter-OFL.txt').exists()
    assert (fonts.FONT_DIR / 'JetBrainsMono-OFL.txt').exists()


def test_inspector_has_ping_history_and_details_tabs(window):
    tabs = window._dashboard.tabs
    assert [tabs.tabText(i) for i in range(tabs.count())] == ['Ping history', 'Details']
    assert tabs.currentIndex() == 0
    # Details holds the device's field grid (what used to be "Overview").
    assert tabs.widget(1).widget() is window._dashboard.overview


def test_default_column_order(window):
    from PyQt6.QtCore import Qt

    header = window._table.horizontalHeader()
    shown = [header.logicalIndex(v) for v in range(header.count())
             if not header.isSectionHidden(header.logicalIndex(v))]
    titles = [window._proxy.headerData(i, Qt.Orientation.Horizontal, Qt.ItemDataRole.DisplayRole)
              for i in shown]
    assert titles == ['Status', 'IP address', 'Hostname', 'DNS Name', 'MAC address', 'Vendor',
                      'MTU', 'Total', 'Succeed', 'Failed', 'Latency', 'Last Failed On']


def test_sidebar_footer_shows_live_computer_name_and_ip(window, monkeypatch):
    from NetInfoView.ui import dashboard
    monkeypatch.setattr(dashboard.QSysInfo, "machineHostName", lambda: "office-pc.corp.example")
    assert dashboard.computer_name() == "office-pc"
    d = window._dashboard
    monkeypatch.setattr(d, "_network_text", lambda: ("Local network", "10.0.0.5"))
    d.refresh()
    assert d.connection_state.text() == "Live"
    assert d.connection_ip.text() == "10.0.0.5"
    assert d.computer_name.text()
    monkeypatch.setattr(d, "_network_text", lambda: ("No network", ""))
    d.refresh()
    assert d.connection_state.text() == "Not connected"
