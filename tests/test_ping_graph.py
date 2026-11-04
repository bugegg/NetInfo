"""Tests for the per-host sample store and the Ping Graph window."""

import pytest
from PyQt6.QtCore import QEvent
from PyQt6.QtWidgets import QApplication

from pinginfoview.fileio.hostfile import parse_host_list
from pinginfoview.model.samples import SampleStore, nice_ceiling, summarize
from pinginfoview.ping.result import PingResult, PingStatus
from pinginfoview.settings import Settings
from pinginfoview.ui.main_window import MainWindow


def _ok(rtt, ts):
    return PingResult(PingStatus.SUCCEEDED, rtt_ms=rtt, timestamp=ts)


def _lost(ts):
    return PingResult(PingStatus.TIMEOUT, timestamp=ts)


def test_store_keeps_failed_pings_as_none_and_caps_per_host():
    store = SampleStore(per_host=3)
    for result in [_ok(10, 1), _lost(2), _ok(20, 3), _ok(30, 4)]:
        store.add(7, result)
    samples = store.samples(7)
    assert [s.rtt_ms for s in samples] == [None, 20, 30]
    assert [s.timestamp for s in store.samples(7, since=3)] == [3, 4]
    assert store.samples(99) == []


def test_store_retain_drops_removed_hosts():
    store = SampleStore()
    store.add(1, _ok(1, 1))
    store.add(2, _ok(1, 1))
    store.retain({2})
    assert store.samples(1) == [] and len(store.samples(2)) == 1


def test_summarize_reports_min_avg_max_and_loss():
    store = SampleStore()
    for result in [_ok(10, 1), _lost(2), _ok(30, 3), _lost(4)]:
        store.add(1, result)
    stats = summarize(store.samples(1))
    assert (stats.sent, stats.lost) == (4, 2)
    assert (stats.min_ms, stats.avg_ms, stats.max_ms) == (10, 20, 30)
    assert stats.loss_percent == 50.0
    assert summarize([]).avg_ms is None


@pytest.mark.parametrize(
    "value, expected", [(0.4, 10), (11, 12), (45, 50), (99, 100), (115.5, 120), (900, 1000)]
)
def test_nice_ceiling(value, expected):
    assert nice_ceiling(value) == expected


@pytest.fixture
def window(qapp, tmp_path, monkeypatch):
    monkeypatch.setattr(
        "pinginfoview.fileio.vendor_db.default_db_path",
        lambda: tmp_path / "vendor.sqlite",
    )
    win = MainWindow(Settings())
    yield win
    if win._graph_window is not None:
        win._graph_window.close()
    win._engine = None  # may be a test's stand-in, never really started
    win._vendor_db.close()
    win.deleteLater()
    QApplication.sendPostedEvents(None, QEvent.Type.DeferredDelete.value)


@pytest.fixture(scope="session")
def qapp():
    yield QApplication.instance() or QApplication([])


def _add(window, text):
    entries = window._entries_from_parsed(parse_host_list(text))
    window._model.set_entries(entries)
    return entries


def test_double_click_opens_the_host_graph(window):
    (entry,) = _add(window, "10.0.0.1")
    window._on_results([(entry.key, _ok(12, 1000)), (entry.key, _lost(1001))])
    index = window._proxy.index(0, 0)
    window._on_table_double_clicked(index)
    first = window._graph_window
    window._on_table_double_clicked(index)
    assert window._graph_window is first and first.keys == [entry.key]
    assert "10.0.0.1" in first.windowTitle()
    window.grab()
    first.graph.grab()  # paints without raising


def test_samples_ignore_the_lower_pane_recording_filter(window):
    from pinginfoview.settings import HistoryMode

    window._set_history_mode(HistoryMode.FAILED_ONLY)
    (entry,) = _add(window, "10.0.0.1")
    window._on_results([(entry.key, _ok(5, 1)), (entry.key, _lost(2))])
    assert len(window._samples.samples(entry.key)) == 2
    assert window._history.rowCount() == 1


def test_graph_window_closes_when_its_host_is_removed(window):
    (entry,) = _add(window, "10.0.0.1")
    graph = window.open_graph(entry.key)
    window._table.selectRow(0)
    window.remove_selected()
    assert window._samples.samples(entry.key) == []
    graph.refresh()
    assert not graph.isVisible()


def test_graph_freezes_on_stop_and_resumes_on_start(window, monkeypatch):
    class FakeEngine:
        def __init__(self, *args):
            self.results_ready = self.finished_pinging = type(
                "Sig", (), {"connect": lambda self, slot: None}
            )()

        def start(self):
            pass

        def stop_pinging(self):
            pass

    monkeypatch.setattr("pinginfoview.ui.main_window.EngineThread", FakeEngine)
    (entry,) = _add(window, "10.0.0.1")
    graph = window.open_graph(entry.key)
    assert graph.frozen  # opened before pinging ever started

    window.start_pinging()
    assert not graph.frozen

    window.stop_pinging()
    assert graph.frozen
    stopped_at = graph._frozen_at
    # A reply that lands after Stop is left off the frozen graph.
    window._samples.add(entry.key, _ok(5, stopped_at + 1))
    graph.refresh()
    assert graph.graph._end == stopped_at
    assert all(s.timestamp <= stopped_at for s in graph.graph._samples)


def test_show_graph_stacks_a_panel_per_selected_host(window):
    a, b = _add(window, "10.0.0.1\n10.0.0.2")
    t = window._stopped_at - 5  # inside the frozen graph's visible span
    window._on_results([(a.key, _ok(12, t)), (b.key, _lost(t)), (b.key, _ok(40, t + 1))])
    window._table.selectAll()
    window.show_graph()
    graph = window._graph_window
    assert graph.keys == [a.key, b.key]
    first, second = graph.panels
    assert len(first.graph._samples) == 1 and len(second.graph._samples) == 2
    # Every panel runs on the same clock so they line up.
    assert first.graph._end == second.graph._end == second.jitter._end
    assert "10.0.0.1" in graph.windowTitle() and "10.0.0.2" in graph.windowTitle()
    assert "Lost 1/2" in second._stats.text()
    graph.grab()  # paints without raising

    # The same selection reuses the window.
    window.show_graph()
    assert window._graph_window is graph and graph.keys == [a.key, b.key]


def test_double_clicking_another_host_stacks_it_on_the_open_graph(window):
    a, b = _add(window, "10.0.0.1\n10.0.0.2")
    window._on_table_double_clicked(window._proxy.index(0, 0))
    graph = window._graph_window
    window._on_table_double_clicked(window._proxy.index(1, 0))
    assert window._graph_window is graph and graph.keys == [a.key, b.key]

    # Closing the window starts the next graph afresh.
    graph.close()
    fresh = window.open_graph(b.key)
    assert fresh is not graph and fresh.keys == [b.key]


def test_panel_drops_a_removed_host_and_keeps_the_rest(window):
    a, b = _add(window, "10.0.0.1\n10.0.0.2")
    graph = window.open_graph(a.key, b.key)
    window._table.selectRow(0)
    window.remove_selected()
    graph.refresh()
    assert graph.keys == [b.key]
    assert "10.0.0.2" in graph.windowTitle()


def test_panel_remove_button_drops_just_that_host(window):
    a, b = _add(window, "10.0.0.1\n10.0.0.2")
    graph = window.open_graph(a.key, b.key)
    graph._remove_panel(graph.panels[0])
    assert graph.keys == [b.key] and graph.isVisible()
    graph._remove_panel(graph.panels[0])
    assert not graph.isVisible()


def test_rolling_loss_and_jitter():
    from pinginfoview.model.samples import Sample
    from pinginfoview.ui.ping_graph import rolling_jitter, rolling_loss_percent

    samples = [Sample(1, 10), Sample(2, None), Sample(3, 20), Sample(4, 14)]
    assert rolling_loss_percent(samples, window=2) == [0, 50, 50, 0]
    # |20-10| = 10, then mean(10, |14-20|) = 8; the lost ping is skipped.
    assert rolling_jitter(samples) == [(3, 10), (4, 8)]


def test_history_bar_scrolls_every_panel_back_together(window):
    a, b = _add(window, "10.0.0.1\n10.0.0.2")
    stopped = window._stopped_at
    # An hour of pings, most of it out of the default 10-minute view.
    for i in range(3600):
        window._samples.add(a.key, _ok(10, stopped - 3600 + i))
        window._samples.add(b.key, _ok(20, stopped - 3600 + i))
    graph = window.open_graph(a.key, b.key)
    bar = graph.history_bar
    # Right-hand end is now; the left end shows the oldest ten minutes.
    assert bar.value() == bar.maximum() == 3000

    bar.setValue(1200)
    for panel in graph.panels:
        assert panel.graph._end == stopped - 1800
        assert all(s.timestamp <= stopped - 1800 for s in panel.graph._samples)
        # The span's 601 pings, plus the one before that carries the line in.
        assert len(panel.graph._samples) == 602
        assert "Lost 0/601" in panel._stats.text()
        # Only time before the host's first ping is greyed out.
        assert panel.graph.first_seen == stopped - 3600

    # Back at the right-hand end the graph follows now again.
    bar.setValue(bar.maximum())
    assert graph.graph._end == stopped


def test_one_time_span_for_every_panel(window):
    a, b, c = _add(window, "10.0.0.1\n10.0.0.2\n10.0.0.3")
    graph = window.open_graph(a.key, b.key)
    graph.range_combo.setCurrentIndex(0)  # 1 minute
    assert [p.graph.span_seconds for p in graph.panels] == [60, 60]
    # A host added later starts on the same span.
    graph.add_hosts([c.key])
    assert graph.panels[2].graph.span_seconds == 60


def test_panels_shrink_to_share_the_window(window):
    entries = _add(window, "\n".join(f"10.0.0.{i}" for i in range(1, 9)))
    graph = window.open_graph(entries[0].key)
    assert graph.panels[0].height() == 250 and not graph.panels[0].jitter.isHidden()

    graph.add_hosts([e.key for e in entries[1:5]])
    heights = {p.height() for p in graph.panels}
    assert len(heights) == 1 and 120 <= heights.pop() < 250
    assert all(p.jitter.isHidden() for p in graph.panels)  # compact
    # Stacked without overlapping.
    QApplication.processEvents()
    tops = [p.geometry().top() for p in graph.panels]
    assert all(b - a == graph.panels[0].height() for a, b in zip(tops, tops[1:]))

    graph.add_hosts([e.key for e in entries[5:]])
    assert graph.windowTitle() == "Ping Graph - 8 hosts"


def test_many_hosts_still_fit_one_page(window):
    entries = _add(window, "\n".join(f"10.0.0.{i}" for i in range(1, 16)))
    graph = window.open_graph(*[e.key for e in entries])
    viewport = graph._scroll.viewport().height()
    assert sum(p.height() for p in graph.panels) <= viewport
    # Crowded: time labels move to one strip under all the panels, and every
    # panel is laid out alike so their graphs are the same size.
    QApplication.processEvents()
    assert not graph.time_axis.isHidden()
    assert all(p.graph.margin_bottom == 4 for p in graph.panels)
    assert len({p.graph.height() for p in graph.panels}) == 1
    graph.grab()  # paints without raising
