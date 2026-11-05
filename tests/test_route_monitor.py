"""Route Monitor: the round tracker, the hop log and its file, the window."""

import pytest
from PyQt6.QtCore import QEvent
from PyQt6.QtWidgets import QApplication

from NetInfoView.model.route_log import (
    RouteLog, RouteLogFile, export_csv, hop_stats, log_path, prune_logs, rate_limited,
)
from NetInfoView.model.samples import Sample
from NetInfoView.ping import route_monitor
from NetInfoView.ping.netpath import Answer
from NetInfoView.ping.route_monitor import CHANGE_ROUNDS, RouteTracker, sequence_for


def _hop(address, rtt):
    return Answer(address, rtt)


def _host(address, rtt):
    return Answer(address, rtt, reached=True)


def _round(hops, host_ttl=None, host="10.9.9.9", rtt=20.0):
    """{ttl: Answer}: routers `hops` (address or None) then the host, which
    answers every TTL from `host_ttl` on, as a real one does."""
    answers = {ttl: _hop(a, ttl * 2.0) for ttl, a in enumerate(hops, 1) if a}
    if host_ttl:
        for ttl in range(host_ttl, route_monitor.MAX_HOPS + 1):
            answers[ttl] = _host(host, rtt)
    return answers


def test_sequence_numbers_tell_rounds_and_ttls_apart():
    seen = {sequence_for(r, t) for r in range(64) for t in range(1, 31)}
    assert len(seen) == 64 * 30
    assert all(0xB000 <= s <= 0xBFFF for s in seen)


def test_tracker_finds_the_host_hop_and_probes_only_that_far():
    tracker = RouteTracker()
    assert tracker.ttls() == list(range(1, 31))
    result = tracker.record(1.0, _round(["10.0.0.1", None, "10.0.0.3"], host_ttl=4))
    assert result.hop_count == 4 and tracker.ttls() == [1, 2, 3, 4]
    assert [(s.ttl, s.address, s.rtt_ms) for s in result.samples] == [
        (1, "10.0.0.1", 2.0), (2, "", None), (3, "10.0.0.3", 6.0), (4, "10.9.9.9", 20.0)]


def test_tracker_without_the_host_keeps_the_hops_that_answered():
    tracker = RouteTracker()
    result = tracker.record(1.0, _round(["10.0.0.1", "10.0.0.2"]))
    assert result.hop_count is None and [s.ttl for s in result.samples] == [1, 2]
    assert tracker.ttls() == list(range(1, 31))


def test_a_lost_host_reply_is_a_lost_sample_not_a_shorter_route():
    tracker = RouteTracker()
    tracker.record(1.0, _round(["10.0.0.1"], host_ttl=2))
    result = tracker.record(2.0, _round(["10.0.0.1"]))
    assert tracker.hop_count == 2
    assert result.samples[-1].ttl == 2 and result.samples[-1].rtt_ms is None


def test_a_longer_route_is_looked_for_again():
    tracker = RouteTracker()
    tracker.record(1.0, _round(["10.0.0.1"], host_ttl=2))
    # A router now answers where the host did.
    tracker.record(2.0, _round(["10.0.0.1", "10.0.0.2"]))
    assert tracker.hop_count is None and len(tracker.ttls()) == 30
    tracker.record(3.0, _round(["10.0.0.1", "10.0.0.2"], host_ttl=3))
    assert tracker.hop_count == 3


def _warmed_up(hops):
    tracker = RouteTracker()
    for i in range(route_monitor.WARMUP_ROUNDS):
        tracker.record(-100.0 + i, _round(hops, host_ttl=3))
    return tracker


def test_a_route_change_needs_the_new_address_several_rounds_in_a_row():
    tracker = _warmed_up(["10.0.0.1", "10.0.0.2"])
    # One stray answer from elsewhere (load balancing) changes nothing.
    assert not tracker.record(1.0, _round(["10.0.0.1", "10.0.7.7"], host_ttl=3)).changes
    assert not tracker.record(2.0, _round(["10.0.0.1", "10.0.0.2"], host_ttl=3)).changes
    changes = []
    for i in range(CHANGE_ROUNDS):
        changes += tracker.record(3.0 + i, _round(["10.0.0.1", "10.0.8.8"], host_ttl=3)).changes
    assert [(c.ttl, c.old, c.new) for c in changes] == [(2, "10.0.0.2", "10.0.8.8")]
    assert tracker.addresses[2] == "10.0.8.8"


def test_hop_stats():
    stats = hop_stats([Sample(1, 10.0), Sample(2, None), Sample(3, 14.0), Sample(4, 12.0)])
    assert (stats.sent, stats.lost) == (4, 1)
    assert (stats.min_ms, stats.avg_ms, stats.max_ms, stats.last_ms) == (10.0, 12.0, 14.0, 12.0)
    assert stats.jitter_ms == 3.0  # |14-10| and |12-14|
    assert hop_stats([Sample(1, None)]).silent


def test_loss_that_does_not_carry_on_is_the_router_limiting_replies():
    def hop(lost, sent=100):
        return hop_stats([Sample(i, None if i < lost else 5.0) for i in range(sent)])

    stats = {1: hop(0), 2: hop(30), 3: hop(2), 4: hop(3)}
    assert rate_limited(stats) == {2}
    # Loss all the way to the host is real.
    assert rate_limited({1: hop(0), 2: hop(10), 3: hop(10)}) == set()


def _log_rounds():
    tracker = _warmed_up(["10.0.0.1", "10.0.0.2"])
    log = RouteLog()
    results = []
    for i in range(5):
        hops = ["10.0.0.1", "10.0.0.2" if i < 2 else "10.0.8.8"]
        result = tracker.record(100.0 + i, _round(hops, host_ttl=3))
        log.add(result)
        results.append(result)
    return log, results


def test_route_log_keeps_each_hop_and_the_changes():
    log, _ = _log_rounds()
    assert log.ttls() == [1, 2, 3]
    assert log.addresses == {1: "10.0.0.1", 2: "10.0.8.8", 3: "10.9.9.9"}
    assert len(log.changes) == 1 and log.changes[0].ttl == 2
    assert len(log.samples(1)) == 5 and len(log.samples(1, since=103.0)) == 2
    assert (log.first, log.last) == (100.0, 104.0)
    assert log.stats()[3].avg_ms == 20.0


def test_log_file_round_trip_csv_and_pruning(tmp_path):
    _, results = _log_rounds()
    path = log_path("example host/1", 0.0, tmp_path)
    assert path.parent == tmp_path and path.name.startswith("example_host_1-")
    log = RouteLogFile(path, "example host", "10.9.9.9", 2.5)
    for result in results:
        log.write(result)
    assert len(log.samples()) == 15 and len(log.changes()) == 1
    log.close()

    out = tmp_path / "out.csv"
    assert export_csv(path, out, {"10.0.0.1": "gw.home"}) == 15
    lines = out.read_text().splitlines()
    assert lines[0] == "time,hop,address,name,rtt_ms"
    assert lines[1].endswith(",1,10.0.0.1,gw.home,2.00")

    import os
    os.utime(path, (0, 0))
    assert prune_logs(tmp_path, days=30) == 1 and not path.exists()
    assert prune_logs(tmp_path / "missing") == 0


@pytest.fixture(scope="session")
def qapp():
    yield QApplication.instance() or QApplication([])


@pytest.fixture
def window(qapp, tmp_path):
    from NetInfoView.ui.route_monitor_window import RouteMonitorWindow

    win = RouteMonitorWindow("example.com", start=False, log_folder=tmp_path)
    yield win
    win.close()
    QApplication.sendPostedEvents(None, QEvent.Type.DeferredDelete.value)


def test_window_shows_each_hop_and_graphs_the_host(window):
    from NetInfoView.ui.route_monitor_window import AVG, IP, NAME, PL

    window.session_target = "example.com"
    _, results = _log_rounds()
    window._on_resolved("10.9.9.9")
    for result in results:
        window._on_round(result)
    window._on_name("10.0.0.1", "gw.home")
    tree = window.tree
    assert tree.topLevelItemCount() == 3
    assert tree.topLevelItem(0).text(NAME) == "gw.home"
    assert tree.topLevelItem(1).text(IP) == "10.0.8.8"
    assert tree.topLevelItem(2).text(NAME) == "example.com"
    assert tree.topLevelItem(2).text(AVG) == "20"
    assert tree.topLevelItem(2).text(PL) == ""
    assert window.selected_ttl == 3 and "Hop 3" in window.graph_title.text()
    assert len(window.graph.changes) == 1
    window.resize(1000, 700)
    window.grab()  # paints the delegates and the graph without raising
    tree.setCurrentItem(tree.topLevelItem(0))
    assert window.selected_ttl == 1 and window.graph.changes == []


def test_window_runs_a_fake_route(window, monkeypatch):
    monkeypatch.setattr(route_monitor, "resolve", lambda target: "10.9.9.9")
    import NetInfoView.ui.route_monitor_window as module
    monkeypatch.setattr(module, "resolve", lambda target: "10.9.9.9")
    monkeypatch.setattr(module.hostname, "resolve", lambda address: "")
    monkeypatch.setattr(module.whois, "netname", lambda address: "")
    monkeypatch.setattr(module.whois, "reserved_name", lambda address: "")

    def probe(ip, ttls, round_no):
        return {t: a for t, a in _round(["10.0.0.1"], host_ttl=2).items() if t in ttls}

    window._probe = probe
    window.interval.setCurrentIndex(0)
    window.start()
    thread = window._thread
    import time
    deadline = time.monotonic() + 5
    while window.log.last is None and time.monotonic() < deadline:
        QApplication.processEvents()
        time.sleep(0.02)
    window.stop()
    assert thread.wait(5000)
    assert window.tree.topLevelItemCount() == 2
    assert window.log_file is not None and window.log_file.exists()
    assert window.button.text() == "Start"


def test_a_load_balanced_hop_answering_by_turns_is_no_route_change():
    tracker = _warmed_up(["10.0.0.1", "10.0.4.253"])
    pattern = "aabbbaaabbbabab"
    changes = []
    for i, which in enumerate(pattern):
        hops = ["10.0.0.1", "10.0.4.253" if which == "a" else "10.0.4.255"]
        changes += tracker.record(float(i), _round(hops, host_ttl=3)).changes
    # Only the first move to the address never seen before counts.
    assert [(c.old, c.new) for c in changes] == [("10.0.4.253", "10.0.4.255")]
    assert tracker.addresses[2] == "10.0.4.255"


def test_hop_colour_follows_the_thresholds():
    from NetInfoView.ui import netpath_window
    from NetInfoView.ui.route_monitor_window import (
        BUBBLE_BAD, BUBBLE_GOOD, BUBBLE_WARN, Thresholds, bubble_color,
    )

    assert (BUBBLE_GOOD, BUBBLE_WARN, BUBBLE_BAD) == (
        netpath_window.GREEN, netpath_window.AMBER, netpath_window.RED)

    def hop(ms, lost=0):
        return hop_stats([Sample(i, None if i < lost else ms) for i in range(100)])

    # Net Path's thresholds: 25 / 100 ms, 5 / 10% loss.
    default = Thresholds()
    assert (default.warn_ms, default.crit_ms, default.warn_loss, default.crit_loss) == (25, 100, 5, 10)
    assert bubble_color(hop(24.9), False, default) == BUBBLE_GOOD
    assert bubble_color(hop(25), False, default) == BUBBLE_WARN
    assert bubble_color(hop(99), False, default) == BUBBLE_WARN
    assert bubble_color(hop(100), False, default) == BUBBLE_BAD
    assert bubble_color(hop(5, lost=4), False, default) == BUBBLE_GOOD
    assert bubble_color(hop(5, lost=5), False, default) == BUBBLE_WARN
    assert bubble_color(hop(5, lost=10), False, default) == BUBBLE_BAD
    # A router limiting its replies isn't coloured for that loss.
    assert bubble_color(hop(5, lost=30), True, default) == BUBBLE_GOOD
    assert bubble_color(hop_stats([Sample(1, None)]), False, default) == ""
    # Loss can be left out.
    assert bubble_color(hop(5, lost=50), False, Thresholds(25, 100, 0, 0)) == BUBBLE_GOOD


def test_colours_are_kept_in_settings(window, monkeypatch):
    from NetInfoView.settings import Settings
    from NetInfoView.ui.route_monitor_window import Thresholds

    settings = Settings()
    assert Thresholds.from_settings(settings) == Thresholds()
    saved = []
    monkeypatch.setattr(settings, "save", lambda: saved.append(True))
    window._settings = settings
    window.set_limits(Thresholds(30, 60, 1, 5))
    assert (settings.route_latency_warn_ms, settings.route_latency_crit_ms) == (30, 60)
    assert (settings.route_loss_warn_percent, settings.route_loss_crit_percent) == (1, 5)
    assert saved and window.graph.warn_ms == 30 and window.graph.bad_ms == 60
    assert "Warning: 30 ms+ or 1%+ loss" in window.legend.text()
    assert "Critical: 60 ms+ or 5%+ loss" in window.legend.text()
    window.set_limits(Thresholds(25, 100, 0, 0))
    assert "Up: under 25 ms" in window.legend.text() and "loss" not in window.legend.text()
    bad = Settings(route_latency_warn_ms=80, route_latency_crit_ms=40,
                   route_loss_warn_percent=5, route_loss_crit_percent=1)
    bad.sanitised()
    assert bad.route_latency_crit_ms > bad.route_latency_warn_ms
    assert bad.route_loss_crit_percent >= bad.route_loss_warn_percent


def test_a_day_is_kept_and_stats_come_from_the_running_totals():
    from NetInfoView.model.route_log import HopSeries
    from NetInfoView.ping.route_monitor import HopSample, RoundResult

    log = RouteLog(keep_seconds=100)
    for t in range(300):
        rtt = None if t % 10 == 0 else float(t % 7 + 1)
        log.add(RoundResult(float(t), [HopSample(float(t), 1, "10.0.0.1", rtt)], hop_count=1))
    kept = log.samples(1)
    assert kept[0].timestamp == 199.0 and len(kept) == 101
    assert log.started == 0.0 and log.first == 199.0
    # The running totals agree with working it out from the samples.
    for since in (None, 250.0, 291.5, 299.0):
        assert log.hop(1, since) == hop_stats(log.samples(1, since))
    series = HopSeries()
    for t in range(5000):
        series.append(float(t), 5.0)
    series.forget_before(4000.0)
    assert len(series) == 1000 and len(series.times) == 1000  # shifted down
    assert series.stats().avg_ms == 5.0 and series.stats(4500.0).sent == 500


def test_span_text():
    from NetInfoView.ui.route_monitor_window import span_text

    assert span_text(60) == "1 minute" and span_text(600) == "10 minutes"
    assert span_text(3600) == "1 hour" and span_text(21600) == "6 hours"
    assert span_text(5400) == "1.5 hours" and span_text(75) == "75 seconds"


def test_window_marks_the_graphed_hop_and_shows_the_session(window):
    from NetInfoView.ui.route_monitor_window import GRAPHED_ROLE, NAME

    window.session_target = "example.com"
    _, results = _log_rounds()
    for result in results:
        window._on_round(result)
    tree = window.tree
    graphed = [tree.topLevelItem(i).data(NAME, GRAPHED_ROLE) for i in range(3)]
    assert graphed == [False, False, True]
    tree.setCurrentItem(tree.topLevelItem(0))
    graphed = [tree.topLevelItem(i).data(NAME, GRAPHED_ROLE) for i in range(3)]
    assert graphed == [True, False, False]
    assert window.graph_time.text() == "Graph time 10 minutes"
    assert "Lost ping" in window.graph_legend.text()
    assert "Session example.com · started" in window.status.text()
    assert "Stopped" in window.logging_label.text()
    window.grab()


def test_logging_indicator_follows_the_log(window, monkeypatch):
    window._thread = object()  # running, as far as the label goes
    window._logging_ok = True
    window._show_logging()
    assert "Logging" in window.logging_label.text()
    window._on_log_failed("Not logging to /x: disk full")
    assert "Not logging" in window.logging_label.text()
    assert "disk full" in window.status.text()
    window._thread = None


def test_log_retention_comes_from_options(qapp, tmp_path):
    import os
    from NetInfoView.settings import Settings
    from NetInfoView.ui.options_dialog import OptionsDialog
    from NetInfoView.ui.route_monitor_window import RouteMonitorWindow

    dialog = OptionsDialog(Settings(route_log_keep_days=7))
    dialog._route_keep_days.setValue(3)
    assert dialog.result_settings().route_log_keep_days == 3

    old = tmp_path / "old.sqlite"
    old.write_bytes(b"")
    four_days = 4 * 86400
    import time
    os.utime(old, (time.time() - four_days, time.time() - four_days))

    from PyQt6.QtWidgets import QWidget
    parent = QWidget()
    parent.settings = Settings(route_log_keep_days=7)
    RouteMonitorWindow(parent=parent, start=False, log_folder=tmp_path).close()
    assert old.exists()
    parent.settings = Settings(route_log_keep_days=3)
    RouteMonitorWindow(parent=parent, start=False, log_folder=tmp_path).close()
    assert not old.exists()
    parent.deleteLater()


def test_addresses_seen_while_warming_up_are_learned_not_reported():
    tracker = RouteTracker()
    changes = []
    for i, which in enumerate("abbbabaa"):
        hops = ["10.0.0.1", "10.0.4.253" if which == "a" else "10.0.4.255"]
        changes += tracker.record(float(i), _round(hops, host_ttl=3)).changes
    assert changes == []
    # After the warm-up the hop going back and forth is still no change...
    for i, which in enumerate("bbbbaaaa"):
        hops = ["10.0.0.1", "10.0.4.253" if which == "a" else "10.0.4.255"]
        changes += tracker.record(20.0 + i, _round(hops, host_ttl=3)).changes
    assert changes == []
    # ...but a new router is.
    for i in range(CHANGE_ROUNDS):
        changes += tracker.record(40.0 + i, _round(["10.0.0.1", "10.0.9.9"], host_ttl=3)).changes
    assert [(c.ttl, c.new) for c in changes] == [(2, "10.0.9.9")]


def test_loss_bar_label():
    from NetInfoView.ui.route_monitor_window import loss_text

    assert loss_text(8.6129) == "8.61% packet loss"
    assert loss_text(100) == "100% packet loss (no reply)"
    assert loss_text(5.04, limited=True) == "5.04% packet loss *"


def test_latency_column_scale_fits_every_hop():
    from NetInfoView.ui.route_monitor_window import latency_scale

    def hop(*rtts):
        return hop_stats([Sample(i, r) for i, r in enumerate(rtts)])

    # The slowest whisker (66 ms) fits, rounded up as the graph's axis is.
    assert latency_scale([hop(10, 13, 25), hop(10, 18, 66)]) == 80
    assert latency_scale([hop(1, 2)]) == 10
    assert latency_scale([hop_stats([Sample(1, None)])]) == 10


def test_latency_header_shows_the_scale(window):
    window.session_target = "example.com"
    _, results = _log_rounds()
    for result in results:
        window._on_round(result)
    # The host answers in 20 ms: 22 rounded up to 25.
    assert window.latency_header.scale == (25, 25, 100)
    window.set_limits(type(window.limits)(10, 20, 5, 10))
    assert window.latency_header.scale == (25, 10, 20)
    window.resize(1100, 600)
    window.grab()  # paints the header without raising


def test_route_line_runs_straight_past_hops_that_do_not_answer(window):
    window.session_target = "example.com"
    tracker = RouteTracker()
    for i in range(3):
        # Hops 2-4 never answer; the host is hop 5.
        window._on_round(tracker.record(float(i), _round(["10.0.0.1", None, None, None], host_ttl=5)))
    window.resize(1100, 600)
    window.show()
    QApplication.processEvents()
    points = window.route_line.points()
    # Hop 1 and the host: one segment, from row 1 straight to row 5.
    assert len(points) == 2
    first, host = points[0][0], points[1][0]
    rows = [window.tree.visualItemRect(window.tree.topLevelItem(i)) for i in (0, 4)]
    from PyQt6.QtCore import QRectF
    assert first.y() == QRectF(rows[0]).center().y()
    assert host.y() == QRectF(rows[1]).center().y()
    window.route_line.grab()  # paints without raising
    # Scrolling moves the viewport's children; the line stays over its rows.
    window.resize(1100, 160)
    QApplication.processEvents()
    window.tree.verticalScrollBar().setValue(window.tree.verticalScrollBar().maximum())
    QApplication.processEvents()
    assert window.route_line.pos().x() == 0 and window.route_line.pos().y() == 0


def test_window_is_called_ping_monitor_and_fits_its_columns(window):
    from NetInfoView.ui.route_monitor_window import IP, NAME, NAME_MAX_WIDTH

    assert window.windowTitle() == "Ping Monitor"
    window.session_target = "example.com"
    window._update_title()
    assert window.windowTitle() == "Ping Monitor - example.com"
    _, results = _log_rounds()
    for result in results:
        window._on_round(result)
    narrow = window.tree.columnWidth(NAME)
    window._on_name("10.0.0.1", "a-rather-long-router-name.core.example.net")
    assert window.tree.columnWidth(NAME) > narrow
    window._on_name("10.0.0.2", "x" * 200)
    assert window.tree.columnWidth(NAME) == NAME_MAX_WIDTH
    assert window.tree.columnWidth(IP) >= window.fontMetrics().horizontalAdvance("10.9.9.9")


def test_sidebar_shows_the_version(qapp, tmp_path, monkeypatch):
    from NetInfoView import __version__
    from NetInfoView.settings import Settings
    from NetInfoView.ui.main_window import MainWindow

    monkeypatch.setattr("NetInfoView.fileio.vendor_db.default_db_path",
                        lambda: tmp_path / "vendor.sqlite")
    win = MainWindow(Settings())
    try:
        assert win._dashboard.version_label.text() == f"v{__version__}"
        assert win.action_route_monitor.text() == "Ping &Monitor"
    finally:
        win._engine = None
        win._vendor_db.close()
        win.deleteLater()


def test_a_round_ends_soon_after_the_host_answers():
    from NetInfoView.ping.route_monitor import SETTLE_MS, settle

    deadline = 10.0 + route_monitor.WAIT_MS / 1000
    # A router's answer changes nothing; the host's brings the end in.
    assert settle(deadline, 10.03, Answer("10.0.0.1", 30)) == deadline
    assert settle(deadline, 10.03, _host("10.9.9.9", 30)) == 10.03 + SETTLE_MS / 1000
    # A far host gets twice its own time for the routers before it.
    assert settle(deadline, 10.4, _host("10.9.9.9", 400)) == pytest.approx(10.4 + 0.8)
    # Never past the timeout.
    assert settle(deadline, 11.2, _host("10.9.9.9", 900)) == deadline


def test_private_hops_are_named_at_once(window):
    from NetInfoView.ui.route_monitor_window import NAME

    window.session_target = "example.com"
    tracker = RouteTracker()
    window._on_round(tracker.record(0.0, _round(["192.168.1.1", "203.0.113.5"], host_ttl=3)))
    tree = window.tree
    assert tree.topLevelItem(0).text(NAME) == "Private (192.168.0.0/16)"
    # A lookup that finds nothing keeps it; one that finds a name replaces it.
    window._on_name("192.168.1.1", "")
    assert tree.topLevelItem(0).text(NAME) == "Private (192.168.0.0/16)"
    window._on_name("192.168.1.1", "gw.home")
    assert tree.topLevelItem(0).text(NAME) == "gw.home"


def test_window_says_so_when_no_hop_answers(window):
    window.session_target = "example.com"
    tracker = RouteTracker()
    for i in range(3):
        window._on_round(tracker.record(float(i), {}))
    # Hop 1 shows the loss, in red, in the table and on the graph.
    from NetInfoView.ui.route_monitor_window import IP, PL
    assert window.tree.topLevelItemCount() == 1
    assert window.tree.topLevelItem(0).text(PL) == "100"
    assert window.tree.topLevelItem(0).text(IP) == "*"
    assert window.selected_ttl == 1
    assert [s.rtt_ms for s in window.graph._samples] == [None, None, None]
    assert "No hop has answered in 3 rounds" in window.status.text()
    window.grab()
    # The first answer clears it.
    window._on_round(tracker.record(5.0, _round(["10.0.0.1"], host_ttl=2)))
    assert window.tree.topLevelItemCount() == 2
    assert "No hop has answered" not in window.status.text()


def test_silent_rounds_count_as_loss_on_the_hops_seen():
    tracker = RouteTracker()
    first = tracker.record(0.0, {})
    assert [(s.ttl, s.rtt_ms) for s in first.samples] == [(1, None)]
    tracker.record(1.0, _round(["10.0.0.1", "10.0.0.2", "10.0.0.3"]))
    # The network drops: all three hops lose the round, none disappear.
    dropped = tracker.record(2.0, {})
    assert [(s.ttl, s.rtt_ms) for s in dropped.samples] == [(1, None), (2, None), (3, None)]
