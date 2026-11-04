"""Tests for Check MTU's path MTU search (ping/mtu.py)."""

import pytest
from PyQt6.QtWidgets import QApplication

from NetInfoView.model.columns import COLUMN_BY_KEY
from NetInfoView.model.host import HostEntry
from NetInfoView.ping import mtu


@pytest.fixture(scope="session")
def qapp():
    yield QApplication.instance() or QApplication([])


def _no_link_mtu(ip):
    return None


def _path(path_mtu, lost=()):
    """A fake probe for a path of `path_mtu` bytes; sizes in `lost` never
    answer, as if every try at them were dropped."""
    calls = []

    def probe(ip, payload):
        calls.append(payload)
        return payload + mtu.HEADERS <= path_mtu and payload not in lost

    return probe, calls


def test_standard_ethernet_path_takes_two_probes():
    probe, calls = _path(1500)
    assert mtu.find_mtu("10.0.0.1", probe, _no_link_mtu) == 1500
    assert calls == [1472, 1473]


def test_jumbo_paths_are_found_exactly():
    for path_mtu in (1501, 4000, 8000, 8211):
        probe, _ = _path(path_mtu)
        assert mtu.find_mtu("10.0.0.1", probe, _no_link_mtu) == path_mtu


def test_paths_above_the_ceiling_report_the_ceiling():
    probe, calls = _path(9000)
    assert mtu.find_mtu("10.0.0.1", probe, _no_link_mtu) == mtu.MAX_MTU == 8212
    assert calls == [1472, 1473, 8184]


def test_smaller_paths_are_found_exactly():
    for path_mtu in (1492, 1400, 1280, 576, 29):
        probe, _ = _path(path_mtu)
        assert mtu.find_mtu("10.0.0.1", probe, _no_link_mtu) == path_mtu


def test_a_1500_interface_is_never_probed_above_1500():
    probe, calls = _path(9000)
    assert mtu.find_mtu("10.0.0.1", probe, lambda ip: 1500) == 1500
    assert calls == [1472]


def test_a_jumbo_interface_caps_the_search():
    probe, _ = _path(9216)
    assert mtu.find_mtu("10.0.0.1", probe, lambda ip: 4000) == 4000


def test_route_mtu_reads_the_loopback_interface():
    assert mtu.route_mtu("127.0.0.1") == 16384


def test_a_host_that_never_answers_has_no_mtu():
    probe, _ = _path(0)
    assert mtu.find_mtu("10.0.0.1", probe, _no_link_mtu) is None


def test_find_many_reports_every_host():
    probe, _ = _path(1400)
    found = {}
    mtu.find_many([(1, "10.0.0.1"), (2, "10.0.0.2")], found.__setitem__, probe, _no_link_mtu)
    assert found == {1: 1400, 2: 1400}


def test_mtu_column_text():
    column = COLUMN_BY_KEY["mtu"]
    assert column.display(HostEntry(1, "h")) == ""
    assert column.display(HostEntry(1, "h", mtu=1492)) == "1492"
    assert column.display(HostEntry(1, "h", mtu=8212)) == "\u22658212"
    assert column.display(HostEntry(1, "h", mtu_no_reply=True)) == "No reply"


def test_real_ping_reaches_loopback():
    # Loopback's MTU is 16384, more than an unprivileged ping can send.
    assert mtu.find_mtu("127.0.0.1") == mtu.MAX_MTU


def test_mtu_is_checked_automatically_once_a_host_answers(qapp, tmp_path, monkeypatch):
    from NetInfoView.fileio.hostfile import parse_host_list
    from NetInfoView.ping.result import PingResult, PingStatus
    from NetInfoView.settings import Settings
    from NetInfoView.ui.main_window import MainWindow

    monkeypatch.setattr(
        "NetInfoView.fileio.vendor_db.default_db_path", lambda: tmp_path / "v.sqlite"
    )
    started = []
    monkeypatch.setattr(MainWindow, "_start_mtu_check",
                        lambda self, targets: (self._mtu_tried.update(k for k, _ in targets),
                                               started.append(targets)))
    win = MainWindow(Settings())
    try:
        up, down = win._entries_from_parsed(parse_host_list("10.0.0.1\n10.0.0.2"))
        up.ip_address, down.ip_address = "10.0.0.1", "10.0.0.2"  # as the engine sets
        win._model.set_entries([up, down])
        win._on_results([(up.key, PingResult(PingStatus.SUCCEEDED, rtt_ms=1, timestamp=1)),
                         (down.key, PingResult(PingStatus.TIMEOUT, timestamp=1))])
        win._auto_check_mtu()
        assert started == [[(up.key, "10.0.0.1")]]
        win._auto_check_mtu()  # checked once, not every tick
        assert len(started) == 1
    finally:
        win._vendor_db.close()
        win.deleteLater()


def test_check_mtu_fills_the_column(qapp, tmp_path, monkeypatch):
    from NetInfoView.fileio.hostfile import parse_host_list
    from NetInfoView.settings import Settings
    from NetInfoView.ui.main_window import MainWindow

    monkeypatch.setattr(
        "NetInfoView.fileio.vendor_db.default_db_path", lambda: tmp_path / "v.sqlite"
    )
    win = MainWindow(Settings())
    try:
        (entry,) = win._entries_from_parsed(parse_host_list("127.0.0.1"))
        entry.ip_address = "127.0.0.1"
        win._model.set_entries([entry])
        win._table.selectRow(0)
        win.check_mtu()
        win._mtu_thread.wait(10000)
        QApplication.processEvents()  # deliver the queued result
        assert entry.mtu == mtu.MAX_MTU
    finally:
        win._vendor_db.close()
        win.deleteLater()
