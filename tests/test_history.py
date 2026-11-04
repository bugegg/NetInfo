"""Tests for the lower pane's history model and host filter."""

from pinginfoview.model.history import HistoryFilterProxy, HistoryModel, HistoryRecord
from pinginfoview.ping.result import PingStatus


def _record(key: int, ip: str = "192.168.1.1") -> HistoryRecord:
    return HistoryRecord(
        timestamp=0.0, host=ip, ip=ip, status=PingStatus.SUCCEEDED, rtt_ms=1.0, ttl=64, key=key
    )


def _proxy_with_records(*records: HistoryRecord) -> tuple[HistoryModel, HistoryFilterProxy]:
    model = HistoryModel()
    model.append_many(list(records))
    proxy = HistoryFilterProxy()
    proxy.setSourceModel(model)
    return model, proxy


def test_lower_pane_shows_nothing_until_a_host_is_selected():
    _, proxy = _proxy_with_records(_record(1), _record(2))
    assert proxy.rowCount() == 0


def test_selecting_a_host_shows_only_its_history():
    _, proxy = _proxy_with_records(_record(1), _record(2), _record(1))
    proxy.set_filter_keys({1})
    assert proxy.rowCount() == 2


def test_clearing_the_selection_hides_everything_again():
    _, proxy = _proxy_with_records(_record(1), _record(2))
    proxy.set_filter_keys({1})
    assert proxy.rowCount() == 1
    proxy.set_filter_keys(set())
    assert proxy.rowCount() == 0


def test_appending_past_the_cap_evicts_oldest_without_a_reset():
    model = HistoryModel(max_records=100)
    model.append_many([_record(i) for i in range(100)])
    resets: list[bool] = []
    removed: list[tuple[int, int]] = []
    model.modelReset.connect(lambda: resets.append(True))
    model.rowsRemoved.connect(lambda _parent, first, last: removed.append((first, last)))

    model.append_many([_record(i) for i in range(100, 130)])

    assert not resets
    assert removed == [(0, 29)]
    assert model.rowCount() == 100
    assert [r.key for r in model.records()] == list(range(30, 130))


def test_a_batch_bigger_than_the_cap_keeps_only_the_newest():
    model = HistoryModel(max_records=100)
    model.append_many([_record(i) for i in range(50)])
    model.append_many([_record(i) for i in range(1000, 1150)])
    assert [r.key for r in model.records()] == list(range(1050, 1150))


def test_proxy_follows_eviction():
    model, proxy = _proxy_with_records()
    model.set_capacity(100)
    proxy.set_filter_keys({1})
    model.append_many([_record(i % 2) for i in range(100)])
    assert proxy.rowCount() == 50
    model.append_many([_record(1) for _ in range(10)])
    assert proxy.rowCount() == 55


def test_proxy_keeps_the_right_records_through_eviction():
    model = HistoryModel(max_records=10)
    proxy = HistoryFilterProxy()
    proxy.setSourceModel(model)
    proxy.set_filter_keys({1, 3})
    for start in range(0, 40, 4):
        model.append_many([_record(i, f"10.0.0.{start + i}") for i in range(4)])
    expected = [r for r in model.records() if r.key in {1, 3}]
    assert len(expected) == 5
    assert [proxy.record_at(i) for i in range(proxy.rowCount())] == expected
    model.set_capacity(5)
    assert [proxy.record_at(i) for i in range(proxy.rowCount())] == [
        r for r in model.records() if r.key in {1, 3}
    ]
    model.clear()
    assert proxy.rowCount() == 0
