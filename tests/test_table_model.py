"""The live grid keeps its sort order while ping results stream in, without
re-sorting rows whose sort value didn't change."""

import pytest
from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import QApplication

from NetInfoView.model.columns import COLUMNS
from NetInfoView.model.host import HostEntry
from NetInfoView.model.table_model import HostFilterProxy, HostTableModel
from NetInfoView.ping.result import PingResult, PingStatus


@pytest.fixture(scope="module")
def qapp():
    yield QApplication.instance() or QApplication([])


def _column(key):
    return next(i for i, c in enumerate(COLUMNS) if c.key == key)


def _grid(count):
    model = HostTableModel()
    model.set_entries([HostEntry(key=n, host=f"10.0.0.{n}") for n in range(1, count + 1)])
    proxy = HostFilterProxy()
    proxy.setSourceModel(model)
    return model, proxy


def _order(proxy):
    host = _column("host_name")
    return [proxy.index(row, host).data() for row in range(proxy.rowCount())]


def _reply(n, rtt):
    return PingResult(PingStatus.SUCCEEDED, rtt, f"10.0.0.{n}", 64, f"10.0.0.{n}")


def test_rows_move_when_the_sorted_value_changes(qapp):
    model, proxy = _grid(4)
    proxy.sort(_column("last_rtt"), Qt.SortOrder.AscendingOrder)
    assert model.sort_column == _column("last_rtt")
    model.apply_results([(n, _reply(n, rtt)) for n, rtt in ((1, 40), (2, 10), (3, 30), (4, 20))])
    assert _order(proxy) == ["10.0.0.2", "10.0.0.4", "10.0.0.3", "10.0.0.1"]
    model.apply_results([(2, _reply(2, 50)), (1, _reply(1, 5))])
    assert _order(proxy) == ["10.0.0.1", "10.0.0.4", "10.0.0.3", "10.0.0.2"]


def test_sorted_by_a_column_pings_dont_change_nothing_is_resorted(qapp, monkeypatch):
    model, proxy = _grid(50)
    proxy.sort(_column("ip_address"), Qt.SortOrder.AscendingOrder)
    model.apply_results([(n, _reply(n, 1.0)) for n in range(1, 51)])  # sets the IPs
    calls = []
    original = HostFilterProxy.lessThan
    monkeypatch.setattr(HostFilterProxy, "lessThan",
                        lambda self, a, b: calls.append(1) or original(self, a, b))
    painted = []
    model.dataChanged.connect(lambda tl, br, roles: painted.append((tl.column(), br.column())))
    model.apply_results([(n, _reply(n, 2.0)) for n in range(1, 51)])
    assert calls == []
    ip = _column("ip_address")
    assert painted == [(0, ip - 1), (ip + 1, len(COLUMNS) - 1)]
    assert _order(proxy) == [f"10.0.0.{n}" for n in sorted(range(1, 51), key=lambda n: n)]


def test_show_only_succeeded_follows_each_result_without_a_full_refilter(qapp):
    from NetInfoView.settings import DisplayMode

    model, proxy = _grid(3)
    proxy.sort(_column("ip_address"), Qt.SortOrder.AscendingOrder)
    proxy.set_display_mode(DisplayMode.SUCCEEDED)
    model.apply_results([(n, _reply(n, 1.0)) for n in (1, 2, 3)])
    assert _order(proxy) == ["10.0.0.1", "10.0.0.2", "10.0.0.3"]
    model.apply_results([(2, PingResult(PingStatus.TIMEOUT, destination_ip="10.0.0.2"))])
    assert _order(proxy) == ["10.0.0.1", "10.0.0.3"]
    model.apply_results([(2, _reply(2, 1.0))])
    assert _order(proxy) == ["10.0.0.1", "10.0.0.2", "10.0.0.3"]
