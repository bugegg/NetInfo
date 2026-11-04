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
    button = next(b for b in window._dashboard.findChildren(QToolButton) if b.text() == 'Columns')
    assert len(button.menu().actions()) == len(COLUMNS)
    index = next(i for i, c in enumerate(COLUMNS) if c.key == 'mtu')
    assert window._table.isColumnHidden(index)
    button.menu().actions()[index].trigger()
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

    button = next(b for b in window._dashboard.findChildren(QToolButton)
                  if b.text() == 'Check for updates')
    icon_key = button.icon().cacheKey()
    window.action_check_updates.setEnabled(False)
    assert not button.isEnabled()
    window.action_check_updates.setEnabled(True)
    assert button.isEnabled() and button.text() == 'Check for updates'
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
