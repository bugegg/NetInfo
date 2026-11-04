"""Qt-dependent tests for MainWindow. Needs a QApplication, created once below
(no display required — PyQt6 can build widgets headlessly for this)."""

import pytest
from PyQt6.QtWidgets import QApplication, QDialog, QMessageBox

from pinginfoview.fileio.hostfile import parse_host_list
from pinginfoview.ping import port_scan
from pinginfoview.ping.network_interfaces import NetworkInterface
from pinginfoview.ping.result import PingResult, PingStatus
from pinginfoview.settings import Settings
from pinginfoview.ui.add_hosts_dialog import AddHostsDialog
from pinginfoview.ui.main_window import MainWindow
from pinginfoview.ui.network_select_dialog import NetworkSelectDialog

#: Captured before the `window` fixture mocks port_scan.scan_many for speed,
#: so the one test that wants the genuine implementation can restore it.
_REAL_SCAN_MANY = port_scan.scan_many


@pytest.fixture(scope="session")
def qapp():
    app = QApplication.instance() or QApplication([])
    yield app


@pytest.fixture
def window(qapp, tmp_path, monkeypatch):
    # Keep the vendor DB test-local rather than touching the user's real one.
    monkeypatch.setattr(
        "pinginfoview.fileio.vendor_db.default_db_path",
        lambda: tmp_path / "vendor.sqlite",
    )
    # Port scanning does real (slow, 0.6s/call) TCP connects; tests that
    # don't specifically exercise it get an instant no-op so the suite that
    # drives several device-info sweeps per test stays fast and deterministic.
    monkeypatch.setattr(
        "pinginfoview.ping.device_info.port_scan.scan_many",
        lambda ip_by_key, ports=None, udp_ports=None: {key: [] for key in ip_by_key},
    )
    # Likewise DNS names: no real queries to whatever DNS this machine uses.
    monkeypatch.setattr("pinginfoview.ping.dns_ptr.system_nameservers", lambda: [])
    monkeypatch.setattr("pinginfoview.ping.dns_ptr.lookup", lambda ip, servers=None: "")
    # And no SNMP walks of the guessed gateways of the test networks.
    monkeypatch.setattr(
        "pinginfoview.ping.device_info.snmp_arp.lookup_many",
        lambda ips, routers, community: {},
    )
    win = MainWindow(Settings())
    yield win
    win._vendor_db.close()


def _entries_with_statuses(window, hosts_text):
    entries = window._entries_from_parsed(parse_host_list(hosts_text))
    window._model.set_entries(entries)
    return entries


def test_device_info_sweep_skips_hosts_without_a_successful_ping(window, monkeypatch):
    entries = _entries_with_statuses(
        window, "192.168.70.1 Alive\n192.168.70.2 Dead\n192.168.70.3 NeverPinged\n"
    )
    entries[0].apply(
        PingResult(PingStatus.SUCCEEDED, 5.0, "192.168.70.1", 64, "192.168.70.1")
    )
    entries[1].apply(PingResult(PingStatus.TIMEOUT, destination_ip="192.168.70.2"))
    # entries[2] stays completely unpinged.

    resolved_ips = []
    monkeypatch.setattr(
        "pinginfoview.ping.hostname.resolve",
        lambda ip: resolved_ips.append(ip) or "",
    )
    monkeypatch.setattr(
        "pinginfoview.ping.arp.lookup", lambda ip, force_refresh=False: ""
    )

    window._refresh_device_info()
    assert window._device_info_thread is not None, "the alive host should trigger a sweep"
    window._device_info_thread.wait(3000)

    assert resolved_ips == ["192.168.70.1"]


def test_device_info_sweep_does_nothing_when_nothing_has_succeeded(window, monkeypatch):
    entries = _entries_with_statuses(window, "192.168.70.9 Dead\n")
    entries[0].apply(PingResult(PingStatus.TIMEOUT, destination_ip="192.168.70.9"))

    def fail(*a, **k):
        raise AssertionError("hostname.resolve should not run for a dead-only sweep")
    monkeypatch.setattr("pinginfoview.ping.hostname.resolve", fail)

    window._refresh_device_info()
    assert window._device_info_thread is None


def _run_sweep_and_wait(window):
    """Dispatches one sweep and pumps the event loop until it's cleaned up.

    A bare QThread.wait() doesn't process the queued cross-thread signals
    that reset window._device_info_thread back to None — that needs the Qt
    event loop running, which processEvents() provides without a full
    app.exec().
    """
    window._refresh_device_info()
    thread = window._device_info_thread
    if thread is None:
        return False
    thread.wait(3000)
    for _ in range(50):
        QApplication.processEvents()
        if window._device_info_thread is None:
            break
    return True


def test_fully_resolved_host_is_never_queried_again(window, monkeypatch):
    entries = _entries_with_statuses(window, "192.168.81.1 Resolves\n")
    entries[0].apply(
        PingResult(PingStatus.SUCCEEDED, 5.0, "192.168.81.1", 64, "192.168.81.1")
    )
    call_count = [0]
    monkeypatch.setattr(
        "pinginfoview.ping.hostname.resolve",
        lambda ip: (call_count.__setitem__(0, call_count[0] + 1), "device.local")[1],
    )
    monkeypatch.setattr(
        "pinginfoview.ping.arp.lookup", lambda ip, force_refresh=False: "00:11:22:DD:EE:FF"
    )
    window._vendor_db.replace_all([("001122", "Example Co")], updated_at="now")

    for _ in range(3):
        _run_sweep_and_wait(window)

    entry = entries[0]
    assert (entry.hostname, entry.mac_address, entry.vendor) == (
        "device.local", "00:11:22:DD:EE:FF", "Example Co",
    )
    assert call_count[0] == 1, "a fully-resolved host must not be queried again"


def test_unresolvable_host_gets_exactly_six_attempts_then_stops(window, monkeypatch):
    entries = _entries_with_statuses(window, "192.168.82.1 NeverResolves\n")
    key = entries[0].key
    entries[0].apply(
        PingResult(PingStatus.SUCCEEDED, 5.0, "192.168.82.1", 64, "192.168.82.1")
    )
    call_count = [0]
    monkeypatch.setattr(
        "pinginfoview.ping.hostname.resolve",
        lambda ip: (call_count.__setitem__(0, call_count[0] + 1), "")[1],
    )
    monkeypatch.setattr("pinginfoview.ping.arp.lookup", lambda ip, force_refresh=False: "")

    for _ in range(9):  # more ticks than the retry budget allows
        _run_sweep_and_wait(window)

    assert call_count[0] == 6, "expected exactly 1 initial attempt + 5 retries"
    assert window._device_info_attempts[key] == 6


FAKE_INTERFACES = [
    NetworkInterface("en0", "192.168.1.105", "255.255.255.0", "192.168.1.0/24"),
]


def test_start_with_no_hosts_offers_a_network_and_populates_it(window, monkeypatch):
    assert window._model.rowCount() == 0
    monkeypatch.setattr(
        "pinginfoview.ui.main_window.list_network_interfaces",
        lambda: FAKE_INTERFACES,
    )

    def accept_first(self):
        self._list.setCurrentRow(0)
        return QDialog.DialogCode.Accepted
    monkeypatch.setattr(NetworkSelectDialog, "exec", accept_first)

    assert window._offer_network_scan() is True
    assert window._model.rowCount() == 254  # a /24 minus network + broadcast
    names = [e.display_name for e in window._model.entries()]
    assert names[0] == "192.168.1.1" and names[-1] == "192.168.1.254"


def test_cancelling_the_network_dialog_leaves_the_host_list_empty(window, monkeypatch):
    monkeypatch.setattr(
        "pinginfoview.ui.main_window.list_network_interfaces",
        lambda: FAKE_INTERFACES,
    )
    monkeypatch.setattr(
        NetworkSelectDialog, "exec", lambda self: QDialog.DialogCode.Rejected
    )

    assert window._offer_network_scan() is False
    assert window._model.rowCount() == 0


def test_start_pinging_skips_the_dialog_when_hosts_already_exist(window, monkeypatch):
    _entries_with_statuses(window, "192.168.1.1 Already Here\n")

    def fail(*a, **k):
        raise AssertionError("the dialog should not appear when hosts already exist")
    monkeypatch.setattr("pinginfoview.ui.main_window.list_network_interfaces", fail)

    window.start_pinging()
    assert window._engine is not None
    window.stop_pinging()
    window._engine.wait(2000)


def test_no_interfaces_found_falls_through_to_manual_entry(window, monkeypatch):
    monkeypatch.setattr(
        "pinginfoview.ui.main_window.list_network_interfaces", lambda: []
    )

    def accept_with_hosts(self):
        self._editor.setPlainText("192.168.1.1 Router\n")
        return QDialog.DialogCode.Accepted
    monkeypatch.setattr(AddHostsDialog, "exec", accept_with_hosts)

    assert window._offer_network_scan() is True
    assert [e.host for e in window._model.entries()] == ["192.168.1.1"]


def test_no_interfaces_found_and_manual_entry_cancelled_returns_false(window, monkeypatch):
    monkeypatch.setattr(
        "pinginfoview.ui.main_window.list_network_interfaces", lambda: []
    )
    monkeypatch.setattr(
        AddHostsDialog, "exec", lambda self: QDialog.DialogCode.Rejected
    )
    assert window._offer_network_scan() is False
    assert window._model.rowCount() == 0


def test_enter_hosts_manually_button_opens_add_hosts_dialog(window, monkeypatch):
    monkeypatch.setattr(
        "pinginfoview.ui.main_window.list_network_interfaces",
        lambda: FAKE_INTERFACES,
    )

    def request_manual(self):
        self.manual_entry_requested = True
        return QDialog.DialogCode.Rejected
    monkeypatch.setattr(NetworkSelectDialog, "exec", request_manual)

    def accept_with_hosts(self):
        self._editor.setPlainText("10.0.0.5 Printer\n")
        return QDialog.DialogCode.Accepted
    monkeypatch.setattr(AddHostsDialog, "exec", accept_with_hosts)

    assert window._offer_network_scan() is True
    assert [e.host for e in window._model.entries()] == ["10.0.0.5"]


def test_default_ping_interval_is_one_second():
    assert Settings().ping_interval_seconds == 1.0


def test_table_defaults_to_sorted_by_ip_address_ascending(window):
    entries = _entries_with_statuses(window, "192.168.1.50\n192.168.1.2\n192.168.1.100\n")
    for entry, ip in zip(entries, ("192.168.1.50", "192.168.1.2", "192.168.1.100")):
        entry.ip_address = ip
    window._model.set_entries(entries)

    shown = [
        window._proxy.data(window._proxy.index(row, 1))
        for row in range(window._proxy.rowCount())
    ]
    assert shown == ["192.168.1.2", "192.168.1.50", "192.168.1.100"]


# -- port scanning integration ------------------------------------------


def test_port_scan_runs_by_default_and_fills_in_the_columns(window, monkeypatch):
    monkeypatch.setattr(
        "pinginfoview.ping.device_info.port_scan.scan_many",
        lambda ip_by_key, ports=None, udp_ports=None: {key: [22, 80] for key in ip_by_key},
    )
    monkeypatch.setattr(
        "pinginfoview.ping.device_info.port_scan.guess_device_type",
        lambda ports: "Something SSH-ish",
    )
    monkeypatch.setattr("pinginfoview.ping.hostname.resolve", lambda ip: "")
    monkeypatch.setattr("pinginfoview.ping.arp.lookup", lambda ip, force_refresh=False: "")

    entries = _entries_with_statuses(window, "192.168.90.1 Scanned\n")
    entries[0].apply(
        PingResult(PingStatus.SUCCEEDED, 5.0, "192.168.90.1", 64, "192.168.90.1")
    )
    assert _run_sweep_and_wait(window)

    entry = entries[0]
    assert entry.ports_scanned is True
    assert entry.open_ports == [22, 80]
    assert entry.device_type_guess == "Something SSH-ish"


def test_port_scan_can_be_disabled_with_an_empty_ports_field(window, monkeypatch):
    def fail(*a, **k):
        raise AssertionError("scan_many must not run when the ports field is empty")
    monkeypatch.setattr("pinginfoview.ping.device_info.port_scan.scan_many", fail)
    monkeypatch.setattr("pinginfoview.ping.hostname.resolve", lambda ip: "real.local")
    monkeypatch.setattr(
        "pinginfoview.ping.arp.lookup", lambda ip, force_refresh=False: "E8:13:6E:00:00:00"
    )
    window._vendor_db.replace_all([("E8136E", "Example Co")], updated_at="now")
    window.settings.port_scan_ports = ""

    entries = _entries_with_statuses(window, "192.168.90.2 NoScan\n")
    entries[0].apply(
        PingResult(PingStatus.SUCCEEDED, 5.0, "192.168.90.2", 64, "192.168.90.2")
    )
    _run_sweep_and_wait(window)

    entry = entries[0]
    assert entry.ports_scanned is False
    assert entry.hostname == "real.local"
    assert entry.vendor == "Example Co"


def test_port_scan_still_runs_for_a_host_with_a_known_vendor(window, monkeypatch):
    """Scanning is enabled (unlike the test above); this host's MAC already
    has a real vendor, but the scan should still run — the point of the
    feature is to report whatever ports a host has open, for any host."""
    monkeypatch.setattr(
        "pinginfoview.ping.device_info.port_scan.scan_many",
        lambda ip_by_key, ports=None, udp_ports=None: {key: [22] for key in ip_by_key},
    )
    monkeypatch.setattr("pinginfoview.ping.hostname.resolve", lambda ip: "")
    monkeypatch.setattr(
        "pinginfoview.ping.arp.lookup", lambda ip, force_refresh=False: "E8:13:6E:00:00:00"
    )
    window._vendor_db.replace_all([("E8136E", "Example Co")], updated_at="now")
    window.settings.port_scan_ports = "2222, 9999"

    entries = _entries_with_statuses(window, "192.168.90.9 KnownVendor\n")
    entries[0].apply(
        PingResult(PingStatus.SUCCEEDED, 5.0, "192.168.90.9", 64, "192.168.90.9")
    )
    _run_sweep_and_wait(window)

    entry = entries[0]
    assert entry.vendor == "Example Co"
    assert entry.ports_scanned is True
    assert entry.open_ports == [22]


def test_port_scan_can_be_disabled_with_an_all_invalid_ports_field(window, monkeypatch):
    """A field that parses to nothing (garbage text, no valid port numbers)
    behaves the same as an empty one, rather than silently scanning zero
    ports in a tight, pointless loop."""
    def fail(*a, **k):
        raise AssertionError("scan_many must not run when nothing valid was entered")
    monkeypatch.setattr("pinginfoview.ping.device_info.port_scan.scan_many", fail)
    monkeypatch.setattr("pinginfoview.ping.hostname.resolve", lambda ip: "")
    monkeypatch.setattr("pinginfoview.ping.arp.lookup", lambda ip, force_refresh=False: "")
    window.settings.port_scan_ports = "not, a, port, list"

    entries = _entries_with_statuses(window, "192.168.90.3\n")
    entries[0].apply(
        PingResult(PingStatus.SUCCEEDED, 5.0, "192.168.90.3", 64, "192.168.90.3")
    )
    _run_sweep_and_wait(window)

    assert entries[0].ports_scanned is False


def test_custom_ports_field_is_actually_used_for_the_scan(window, monkeypatch):
    """The point of this feature: typing a custom port list into Options
    changes which ports actually get probed."""
    monkeypatch.setattr("pinginfoview.ping.hostname.resolve", lambda ip: "")
    monkeypatch.setattr("pinginfoview.ping.arp.lookup", lambda ip, force_refresh=False: "")

    seen_ports = []

    def fake_scan_many(ip_by_key, ports=None, udp_ports=None):
        seen_ports.append(set(ports))
        return {key: [] for key in ip_by_key}
    monkeypatch.setattr(
        "pinginfoview.ping.device_info.port_scan.scan_many", fake_scan_many
    )
    window.settings.port_scan_ports = "2222, 9999"

    entries = _entries_with_statuses(window, "192.168.90.4\n")
    entries[0].apply(
        PingResult(PingStatus.SUCCEEDED, 5.0, "192.168.90.4", 64, "192.168.90.4")
    )
    _run_sweep_and_wait(window)

    assert seen_ports == [{2222, 9999}]


def test_port_scan_against_a_real_local_listener(window, monkeypatch):
    """One end-to-end pass with no mocking of the scan itself — a real TCP
    listener on localhost, found by the real scan_many/guess_device_type.

    settings.port_scan_ports (parsed by the Options dialog's text field) is
    the real path's actual source of ports now, not port_scan.STATIC_PORTS
    directly — main_window._refresh_device_info() always parses and passes
    an explicit ports dict, so patching the module constant alone wouldn't
    reach the scan.
    """
    import socket as socket_module

    # Undo the window fixture's speed-focused no-op mock for this one test.
    monkeypatch.setattr(
        "pinginfoview.ping.device_info.port_scan.scan_many", _REAL_SCAN_MANY
    )

    server = socket_module.socket(socket_module.AF_INET, socket_module.SOCK_STREAM)
    server.bind(("127.0.0.1", 0))  # an ephemeral port, so nothing can conflict
    port = server.getsockname()[1]
    window.settings.port_scan_ports = str(port)
    server.listen(1)
    try:
        monkeypatch.setattr("pinginfoview.ping.hostname.resolve", lambda ip: "")
        monkeypatch.setattr(
            "pinginfoview.ping.arp.lookup", lambda ip, force_refresh=False: ""
        )
        entries = _entries_with_statuses(window, "127.0.0.1 Loopback\n")
        entries[0].apply(
            PingResult(PingStatus.SUCCEEDED, 1.0, "127.0.0.1", 64, "127.0.0.1")
        )
        assert _run_sweep_and_wait(window)
        entry = entries[0]
        assert entry.ports_scanned is True
        assert entry.open_ports == [port]
    finally:
        server.close()


def test_udp_port_scan_against_a_real_local_listener(window, monkeypatch):
    """Same as test_port_scan_against_a_real_local_listener but for a
    "123/udp"-style entry in the Options field, end to end through the real
    settings-parsing -> device_info -> port_scan path."""
    import socket as socket_module

    monkeypatch.setattr(
        "pinginfoview.ping.device_info.port_scan.scan_many", _REAL_SCAN_MANY
    )

    server = socket_module.socket(socket_module.AF_INET, socket_module.SOCK_DGRAM)
    server.bind(("127.0.0.1", 0))
    port = server.getsockname()[1]
    window.settings.port_scan_ports = f"{port}/udp"
    try:
        monkeypatch.setattr("pinginfoview.ping.hostname.resolve", lambda ip: "")
        monkeypatch.setattr(
            "pinginfoview.ping.arp.lookup", lambda ip, force_refresh=False: ""
        )
        entries = _entries_with_statuses(window, "127.0.0.1 Loopback\n")
        entries[0].apply(
            PingResult(PingStatus.SUCCEEDED, 1.0, "127.0.0.1", 64, "127.0.0.1")
        )
        assert _run_sweep_and_wait(window)
        entry = entries[0]
        assert entry.ports_scanned is True
        assert entry.open_ports == [f"{port}/udp"]
    finally:
        server.close()


# -- all-IPs-for-a-name integration --------------------------------------


def test_named_host_gets_all_its_resolved_ips(window, monkeypatch):
    monkeypatch.setattr("pinginfoview.ping.hostname.resolve", lambda ip: "")
    monkeypatch.setattr("pinginfoview.ping.arp.lookup", lambda ip, force_refresh=False: "")
    monkeypatch.setattr(
        "pinginfoview.ping.device_info.resolve_all_ips",
        lambda host: ["203.0.113.1", "203.0.113.2", "203.0.113.3"],
    )

    entries = _entries_with_statuses(window, "cdn.example.com\n")
    entries[0].apply(
        PingResult(PingStatus.SUCCEEDED, 5.0, "203.0.113.1", 64, "203.0.113.1")
    )
    assert _run_sweep_and_wait(window)

    entry = entries[0]
    assert entry.all_ips_resolved is True
    assert entry.all_resolved_ips == ["203.0.113.1", "203.0.113.2", "203.0.113.3"]


def test_literal_ip_host_gets_an_empty_all_ips_list_not_a_retry_loop(window, monkeypatch):
    """A host already given as a literal IP has nothing to discover — it
    should settle immediately rather than burn through retry attempts."""
    monkeypatch.setattr("pinginfoview.ping.hostname.resolve", lambda ip: "real.local")
    monkeypatch.setattr(
        "pinginfoview.ping.arp.lookup", lambda ip, force_refresh=False: "E8:13:6E:00:00:00"
    )
    window._vendor_db.replace_all([("E8136E", "Example Co")], updated_at="now")

    entries = _entries_with_statuses(window, "192.168.95.1\n")
    key = entries[0].key
    entries[0].apply(
        PingResult(PingStatus.SUCCEEDED, 5.0, "192.168.95.1", 64, "192.168.95.1")
    )
    assert _run_sweep_and_wait(window)

    entry = entries[0]
    assert entry.all_ips_resolved is True
    assert entry.all_resolved_ips == []
    assert window._device_info_attempts[key] == 1, "should resolve fully on the first pass"


# -- clear all hosts ------------------------------------------------------


def test_clear_all_hosts_removes_everything_on_confirm(window, monkeypatch):
    _entries_with_statuses(window, "192.168.1.1\n192.168.1.2\n192.168.1.3\n")
    assert window._model.rowCount() == 3
    monkeypatch.setattr(
        "pinginfoview.ui.main_window.QMessageBox.question",
        lambda *a, **k: QMessageBox.StandardButton.Yes,
    )

    window.clear_all_hosts()

    assert window._model.rowCount() == 0


def test_clear_all_hosts_does_nothing_on_cancel(window, monkeypatch):
    _entries_with_statuses(window, "192.168.1.1\n192.168.1.2\n")
    monkeypatch.setattr(
        "pinginfoview.ui.main_window.QMessageBox.question",
        lambda *a, **k: QMessageBox.StandardButton.No,
    )

    window.clear_all_hosts()

    assert window._model.rowCount() == 2


def test_clear_all_hosts_on_an_empty_list_skips_the_confirmation(window, monkeypatch):
    assert window._model.rowCount() == 0

    def fail(*a, **k):
        raise AssertionError("should not prompt when there's nothing to clear")
    monkeypatch.setattr("pinginfoview.ui.main_window.QMessageBox.question", fail)

    window.clear_all_hosts()  # must not raise


def test_remove_selected_is_still_available_on_the_context_menu(window):
    names = [
        action.text()
        for action in window._table.actions()
        if not action.isSeparator() and action.menu() is None
    ]
    assert "&Remove Selected" in names


def test_add_hosts_ok_disabled_until_a_host_is_entered(qapp):
    dialog = AddHostsDialog()
    ok = dialog._ok_button
    assert not ok.isEnabled()  # only the placeholder is showing
    dialog._editor.setPlainText("   \n")
    assert not ok.isEnabled()
    dialog._editor.setPlainText("192.168.1.1 Router")
    assert ok.isEnabled()
    dialog._editor.setPlainText("Group: Servers\n#")
    assert not ok.isEnabled()


def test_add_hosts_ok_enabled_for_initial_text(qapp):
    assert AddHostsDialog(initial_text="8.8.8.8")._ok_button.isEnabled()


def test_add_hosts_typing_a_huge_cidr_does_not_expand_it(qapp, monkeypatch):
    """Typing /24 passes through /2 (a billion addresses); that used to hang."""
    import time

    dialog = AddHostsDialog()
    started = time.perf_counter()
    for text in ("192.168.1.0/2", "192.168.1.0/24"):
        dialog._editor.setPlainText(text)
    assert time.perf_counter() - started < 1.0
    assert dialog._ok_button.isEnabled()


def test_add_hosts_refuses_an_oversized_range_and_stays_open(qapp, monkeypatch):
    warnings = []
    monkeypatch.setattr(QMessageBox, "warning", lambda *args: warnings.append(args[2]))
    dialog = AddHostsDialog(initial_text="10.0.0.0/8")
    dialog.accept()
    assert dialog.result() != QDialog.DialogCode.Accepted
    assert "16,777,216 addresses" in warnings[0]


def test_status_bar_counts_hosts_hidden_by_display_mode(window):
    from pinginfoview.settings import DisplayMode

    window._set_display_mode(DisplayMode.SUCCEEDED)
    _entries_with_statuses(window, "192.168.1.1\n192.168.1.2")
    window._update_status_bar()
    assert window.statusBar().currentMessage() == "0 item(s), Stopped, 2 hidden by filter"


def test_adding_hosts_switches_a_filtered_view_back_to_show_all(window, monkeypatch):
    from pinginfoview.settings import DisplayMode

    window._set_display_mode(DisplayMode.SUCCEEDED)

    def accept_with_hosts(self):
        self._editor.setPlainText("192.168.1.1\n192.168.1.2")
        return QDialog.DialogCode.Accepted

    monkeypatch.setattr(AddHostsDialog, "exec", accept_with_hosts)
    monkeypatch.setattr(window, "start_pinging", lambda: None)
    window.action_add.trigger()

    assert window._proxy.display_mode is DisplayMode.ALL
    assert window.settings.display_mode is DisplayMode.ALL
    assert window._display_actions[DisplayMode.ALL].isChecked()
    assert window._proxy.rowCount() == 2


def test_add_hosts_starts_pinging_on_ok(window, monkeypatch):
    def accept_with_hosts(self):
        self._editor.setPlainText("192.168.1.1")
        return QDialog.DialogCode.Accepted

    started = []
    monkeypatch.setattr(AddHostsDialog, "exec", accept_with_hosts)
    monkeypatch.setattr(window, "start_pinging", lambda: started.append(True))
    window.action_add.trigger()
    assert started == [True]


def test_add_hosts_cancel_does_not_start_pinging(window, monkeypatch):
    started = []
    monkeypatch.setattr(AddHostsDialog, "exec", lambda self: QDialog.DialogCode.Rejected)
    monkeypatch.setattr(window, "start_pinging", lambda: started.append(True))
    window.action_add.trigger()
    assert started == []


def test_add_hosts_remembers_the_last_entry(window, monkeypatch):
    seen = []

    def accept_with_hosts(self):
        seen.append((self.text(), self.skip_first(), self.skip_last()))
        self._editor.setPlainText("192.168.1.0/24 Office")
        self._skip_first.setChecked(True)
        return QDialog.DialogCode.Accepted

    monkeypatch.setattr(AddHostsDialog, "exec", accept_with_hosts)
    monkeypatch.setattr(window, "start_pinging", lambda: None)
    window.action_add.trigger()
    window.action_add.trigger()

    assert seen == [("", False, False), ("192.168.1.0/24 Office", True, False)]
    assert window.settings.last_added_hosts == "192.168.1.0/24 Office"


def test_last_added_hosts_survives_a_settings_round_trip(qapp, monkeypatch):
    from PyQt6.QtCore import QSettings

    store: dict = {}
    monkeypatch.setattr(QSettings, "setValue", lambda self, k, v: store.__setitem__(k, v))
    monkeypatch.setattr(QSettings, "value", lambda self, k, d=None: store.get(k, d))
    Settings(last_added_hosts="10.0.0.1\n10.0.0.2", add_hosts_skip_last=True).save()
    loaded = Settings.load()
    assert loaded.last_added_hosts == "10.0.0.1\n10.0.0.2"
    assert loaded.add_hosts_skip_last is True


def test_add_hosts_replaces_the_current_list_by_default(window, monkeypatch):
    window._model.set_entries(window._entries_from_parsed(parse_host_list("10.0.0.1")))

    def accept_with_hosts(self):
        assert self.replace()  # on unless the user unticks it
        self._editor.setPlainText("172.16.10.22")
        return QDialog.DialogCode.Accepted

    monkeypatch.setattr(AddHostsDialog, "exec", accept_with_hosts)
    monkeypatch.setattr(window, "start_pinging", lambda: None)
    window.action_add.trigger()
    assert [e.host for e in window._model.entries()] == ["172.16.10.22"]


def test_add_hosts_can_still_add_to_the_list(window, monkeypatch):
    window._model.set_entries(window._entries_from_parsed(parse_host_list("10.0.0.1")))

    def accept_with_hosts(self):
        self._editor.setPlainText("172.16.10.22")
        self._replace.setChecked(False)
        return QDialog.DialogCode.Accepted

    monkeypatch.setattr(AddHostsDialog, "exec", accept_with_hosts)
    monkeypatch.setattr(window, "start_pinging", lambda: None)
    window.action_add.trigger()
    assert [e.host for e in window._model.entries()] == ["10.0.0.1", "172.16.10.22"]
    assert window.settings.add_hosts_replace is False  # remembered for next time

