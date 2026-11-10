import time

import pytest
from PyQt6.QtWidgets import QApplication

from NetInfoView.ping import device_link, logos, provider, speedtest
from NetInfoView.ping.device_link import DeviceLink
from NetInfoView.ping.provider import Provider
from NetInfoView.ping.speed_locations import locate
from NetInfoView.ping.speedtest import SpeedResult, TransferResult
from NetInfoView.ui.speedtest_window import (
    Gauge, SpeedTestWindow, format_mbps, result_text, server_text,
)
from test_main_window import qapp, window  # noqa: F401
from test_speedtest import server  # noqa: F401


OFFLINE = [(speedtest.FALLBACK_SERVERS[0], 100.0), (speedtest.FALLBACK_SERVERS[1], None)]


LINK = DeviceLink(interface="en0", kind="Wi-Fi", local_ip="192.168.1.24", link_mbps=866.0,
                  ssid="Home Network", band="5 GHz", channel="40", signal_dbm=-55)
PROVIDER = Provider("AIS", "ADVANCED WIRELESS NETWORK COMPANY LIMITED", "203.0.113.9",
                    "AWN-CO-LTD-TH", "TH", ipv4="203.0.113.9", ipv6="2001:db8::9")


@pytest.fixture(autouse=True)
def offline_server_list(monkeypatch):
    monkeypatch.setattr(speedtest, "fetch_servers", lambda: [s for s, _ in OFFLINE])
    monkeypatch.setattr(speedtest, "rank_servers", lambda servers, on_progress=None: OFFLINE)
    monkeypatch.setattr(speedtest, "connect_time_ms", lambda spec: 12.0)
    monkeypatch.setattr(provider, "fetch_provider", lambda: (True, PROVIDER))
    monkeypatch.setattr(device_link, "device_link", lambda: LINK)
    # No logos from the network: each site "has none", known from the cache.
    monkeypatch.setattr(logos, "cached", lambda domain, folder=None: (True, None))
    yield
    # Windows a test didn't close keep their background threads running;
    # stop them while the fakes are still in place (not the real tools).
    from NetInfoView.ui import threads
    for window in QApplication.topLevelWidgets():
        if isinstance(window, SpeedTestWindow):
            window.close()
    threads.stop_all(10000)


def _wait(cond, timeout=10.0):
    end = time.monotonic() + timeout
    while not cond() and time.monotonic() < end:
        QApplication.processEvents()
        time.sleep(0.01)
    assert cond()


def test_format_mbps():
    assert format_mbps(None) == "–"
    assert format_mbps(1234.5) == "1,234"
    assert format_mbps(56.78) == "56.8"
    assert format_mbps(1.234) == "1.23"


def test_gauge_scale_is_even_between_marks_and_grows(qapp):
    g = Gauge()
    assert g.fraction(0) == 0 and g.fraction(1000) == 1
    assert g.fraction(100) == 5 / 8
    g.set_value(2000, "download")
    assert g.marks[-1] == 10000 and 0 < g.fraction(2000) < 1


def test_gauge_reads_ms_while_pinging(qapp):
    from NetInfoView.ui.speedtest_window import PING_MARKS, SCALES
    g = Gauge()
    g.set_value(0, "ping")
    assert g.ping and g.marks is PING_MARKS
    g.set_value(5000)  # a slow ping doesn't switch to the Gbps scale
    assert g.marks is PING_MARKS and g.fraction(5000) == 1
    assert g.fraction(50) == 4 / 8
    g.set_value(100, "download")
    assert not g.ping and g.marks is SCALES[0]


def test_server_text_and_copy_text():
    meta = {"host": "speed.cloudflare.com", "colo": "BKK", "loc": "TH", "ip": "1.2.3.4"}
    assert server_text(meta) == "speed.cloudflare.com  ·  BKK (TH)  ·  your IP 1.2.3.4"
    assert server_text(meta, show_ip=False) == "speed.cloudflare.com  ·  BKK (TH)"
    r = SpeedResult(latency_ms=12.3, jitter_ms=1.5, meta=meta,
                    download=TransferResult(mbps=500, peak_mbps=600, loaded_latency_ms=40))
    text = result_text(r)
    assert "Download    500 Mbps   peak 600   loaded ping 40 ms" in text
    assert "Ping        12 ms   jitter 1.5 ms" in text


def test_default_server_is_cloudflare(qapp):
    w = SpeedTestWindow(load_servers=False)
    assert w.server.text.text() == "Automatic (Cloudflare)"
    assert w.options().server == speedtest.CLOUDFLARE
    w.set_choice("https://speed.example.com")
    assert w.server.text.text() == "speed.example.com"
    assert w.options().server == "https://speed.example.com"
    w.close()


def test_window_runs_a_test_end_to_end(qapp, server, monkeypatch):  # noqa: F811
    monkeypatch.setattr(speedtest, "DOWN_CHUNK", 2_000_000)
    monkeypatch.setattr(speedtest, "UP_CHUNK", 1_000_000)
    w = SpeedTestWindow(load_servers=False)
    w.set_choice(server)
    w.duration.setItemData(0, 0.6)
    w.duration.setCurrentIndex(0)
    monkeypatch.setattr(speedtest.SpeedTestOptions, "pause_s", 0.2)
    w.start()
    assert w.button.text() == "Stop"
    _wait(lambda: w._thread is None)
    assert w.status.text() == "Test complete"
    assert w.card_ping.note.text().startswith("Median of 20 pings")
    # The needle swings home and the gauge is back to its starting state.
    _wait(lambda: w.gauge.phase == "" and w.gauge.value == 0.0, 3)
    assert w.button.text() == "Run again"
    assert w.card_down.value.text() != "–" and w.card_up.value.text() != "–"
    assert w.history.topLevelItemCount() == 1
    assert w.copy_button.isEnabled()
    assert w.graph.series["download"] and w.graph.series["upload"]
    w.close()


def test_sidebar_button_opens_one_window(window):  # noqa: F811
    window._dashboard.nav_speed_test.click()
    window._dashboard.nav_speed_test.click()
    assert len(window.findChildren(SpeedTestWindow)) == 1


def _rows(w):
    return [(r.title.text(), " · ".join(line.text() for line in r.lines), r.latency.text(),
             r.isEnabled()) for r in w.picker._rows]


def test_picker_lists_servers_with_country_city_and_latency(qapp):
    w = SpeedTestWindow()
    _wait(lambda: w._list_thread is None)
    w.show()
    w.open_picker()
    assert w.picker.is_open() and w.picker.scrim.isVisible()
    assert _rows(w) == [
        ("Japan", "Tokyo · NRT · A573", "100 ms", True),
        ("Germany", "Frankfurt · FRA · Clouvider", "unreachable", False),
    ]
    assert w.picker.automatic.checked
    assert w.picker.automatic.latency.text() == "12 ms"
    assert "Automatic · Cloudflare" in w.picker.selected_label.text()
    chips = [w.picker.chips.itemAt(i).widget().text() for i in range(w.picker.chips.count() - 1)]
    assert chips == ["All", "Asia", "Europe"]
    w.close()


def test_thailand_chip_filters_to_thai_servers(qapp, monkeypatch):
    thai = speedtest.FALLBACK_OOKLA[0]
    ranked = [(thai, 9.0)] + OFFLINE
    monkeypatch.setattr(speedtest, "rank_servers", lambda servers, on_progress=None: ranked)
    w = SpeedTestWindow()
    _wait(lambda: w._list_thread is None)
    w.open_picker()
    chips = [w.picker.chips.itemAt(i).widget().text() for i in range(w.picker.chips.count() - 1)]
    assert chips == ["All", "Thailand", "Asia", "Europe"]
    w.picker._set_region("Thailand")
    assert [(r[0], r[1]) for r in _rows(w)] == [("Bangkok", "Thailand · BKK · True Online")]
    w.picker._rows[0].clicked.emit()
    w.picker.use_button.click()
    assert w.server.text.text() == "Bangkok · True Online"


def test_connection_cards_show_the_isp_ip_and_device(qapp):
    w = SpeedTestWindow()
    _wait(lambda: w._provider_thread is None and w._link is not None)
    assert w.provider_name.text() == "AIS"
    assert "ADVANCED WIRELESS" in w.provider_card.toolTip()
    assert "Wi-Fi connected" in w.connection.text()
    # The public IP shows; the eye hides it (and shows it again).
    assert w.public_ip.text() == "203.0.113.9"
    w.ip_eye.setChecked(False)
    assert "203.0.113.9" not in w.public_ip.text()
    w.ip_eye.setChecked(True)
    assert w.public_ip.text() == "203.0.113.9"
    assert w.public_ipv6.text() == "2001:db8::9"
    w.copy_public6.click()
    assert QApplication.clipboard().text() == "2001:db8::9"
    assert w.local_ip.text() == "192.168.1.24"
    assert w.link_speed.text() == "866 Mbps"
    assert w.network_name.text() == "Wi-Fi network"
    assert w.network_name.toolTip() == "Home Network"
    assert w.band_tag.text() == "5 GHz"
    assert w.signal_label.text() == "Strong"
    assert w.device_tag.text() == "Wi-Fi"
    w.copy_local.click()
    assert QApplication.clipboard().text() == "192.168.1.24"
    w.close()


def test_ethernet_device_card(qapp, monkeypatch):
    wired = DeviceLink(interface="en7", kind="Ethernet", local_ip="10.0.0.5", link_mbps=1000.0,
                       port="USB-C Ethernet", duplex="Full duplex", active=True)
    monkeypatch.setattr(device_link, "device_link", lambda: wired)
    w = SpeedTestWindow()
    _wait(lambda: w._provider_thread is None and w._link is not None)
    assert "Ethernet connected" in w.connection.text()
    assert w.device_tag.text() == "LAN"
    assert w.link_speed.text() == "1 Gbps"
    assert w.network_name.text() == "USB-C Ethernet"
    assert w.band_tag.text() == "Full duplex" and w.band_tag.isVisibleTo(w)
    assert w.signal_label.text() == "Link active"
    w.close()


def test_ethernet_adapter_name_drops_its_interface(qapp, monkeypatch):
    wired = DeviceLink(interface="en4", kind="Ethernet", local_ip="10.0.0.5", link_mbps=2500.0,
                       port="Ethernet Adapter (en4)", active=False)
    monkeypatch.setattr(device_link, "device_link", lambda: wired)
    w = SpeedTestWindow()
    _wait(lambda: w._link is not None)
    assert w.network_name.text() == "Ethernet Adapter"
    assert w.link_speed.text() == "2.5 Gbps"
    assert w.signal_label.text() == "No link"
    assert not w.band_tag.isVisibleTo(w)
    w.close()


def test_offline_shows_in_the_provider_card(qapp, monkeypatch):
    monkeypatch.setattr(provider, "fetch_provider", lambda: (False, None))
    w = SpeedTestWindow()
    _wait(lambda: w._provider_thread is None)
    assert w.provider_name.text() == "No Internet"
    assert "Offline" in w.connection.text()
    w.close()
    w.close()


def test_picker_search_and_region_filter(qapp):
    w = SpeedTestWindow()
    _wait(lambda: w._list_thread is None)
    w.open_picker()
    w.picker.search.setText("tok")
    assert [r[0] for r in _rows(w)] == ["Japan"]
    w.picker.search.setText("")
    w.picker._set_region("Europe")
    assert [r[0] for r in _rows(w)] == ["Germany"]
    w.picker.search.setText("https://speed.example.com")
    assert _rows(w)[0][:2] == ("Custom server", "https://speed.example.com")
    w.close()


def test_choosing_a_server_in_the_picker(qapp):
    w = SpeedTestWindow()
    _wait(lambda: w._list_thread is None)
    w.open_picker()
    w.picker._rows[0].clicked.emit()
    assert "Tokyo · A573" in w.picker.selected_label.text()
    assert w.picker._rows[0].checked and not w.picker.automatic.checked
    w.picker.use_button.click()
    assert not w.picker.is_open()
    assert w.options().server == speedtest.FALLBACK_SERVERS[0]
    assert w.server.text.text() == "Tokyo · A573"
    w.close()


def test_choice_is_remembered_in_settings(window):  # noqa: F811
    w = window.speed_test()
    _wait(lambda: w._list_thread is None)
    w.set_choice(speedtest.FALLBACK_SERVERS[0])
    w.duration.setCurrentIndex(0)
    w._remember_choice(w.options())
    assert window.settings.speed_test_server == speedtest.FALLBACK_SERVERS[0].url
    assert window.settings.speed_test_seconds == 5.0
    w.close()
    w2 = window.speed_test()
    assert w2.options().server == speedtest.FALLBACK_SERVERS[0]
    assert w2.options().duration_s == 5.0
    w2.close()


def test_badges_show_a_logo_once_it_arrives(qapp, monkeypatch):
    from PyQt6.QtCore import QBuffer, QByteArray, QIODevice
    from PyQt6.QtGui import QColor, QImage
    from NetInfoView.ui.provider_badge import LogoStore, ProviderBadge

    image = QImage(64, 64, QImage.Format.Format_ARGB32)
    image.fill(QColor("#ff0000"))
    data = QByteArray()
    buffer = QBuffer(data)
    buffer.open(QIODevice.OpenModeFlag.WriteOnly)
    image.save(buffer, "PNG")
    monkeypatch.setattr(logos, "cached", lambda domain, folder=None: (False, None))
    monkeypatch.setattr(logos, "logo_for", lambda domain, folder=None: bytes(data))
    store = LogoStore()
    badge = ProviderBadge(40)
    badge.set_provider("AIS", "ais.th", store)
    assert badge._logo is None  # initials until the logo comes
    _wait(lambda: badge._logo is not None, 5)
    assert badge._logo.width() == 64
    other = ProviderBadge(40)
    other.set_provider("AIS", "ais.th", store)  # now straight from memory
    assert other._logo is not None


def test_badge_shows_a_logo_from_the_cache_folder_at_once(qapp, monkeypatch):
    from PyQt6.QtCore import QBuffer, QByteArray, QIODevice
    from PyQt6.QtGui import QColor, QImage
    from NetInfoView.ui.provider_badge import LogoStore, ProviderBadge

    image = QImage(32, 32, QImage.Format.Format_ARGB32)
    image.fill(QColor("#00ff00"))
    data = QByteArray()
    buffer = QBuffer(data)
    buffer.open(QIODevice.OpenModeFlag.WriteOnly)
    image.save(buffer, "PNG")
    monkeypatch.setattr(logos, "cached", lambda domain, folder=None: (True, bytes(data)))
    badge = ProviderBadge(40)
    badge.set_provider("AIS", "ais.th", LogoStore())
    assert badge._logo is not None and badge._logo.width() == 32


def test_device_card_updates_live(qapp, monkeypatch):
    from NetInfoView.ui.speedtest_window import DeviceThread
    monkeypatch.setattr(DeviceThread, "INTERVAL_S", 0.05)
    rates = iter([866.0, 1201.0] + [1201.0] * 500)
    monkeypatch.setattr(device_link, "device_link",
                        lambda: DeviceLink(interface="en0", kind="Wi-Fi", local_ip="192.168.1.24",
                                           link_mbps=next(rates), signal_dbm=-55))
    w = SpeedTestWindow()
    _wait(lambda: w.link_speed.text() == "1.2 Gbps", 5)
    thread = w._device_thread
    w.close()
    _wait(lambda: thread.isFinished(), 5)


def test_offline_stays_offline_when_the_wifi_is_up(qapp, monkeypatch):
    from NetInfoView.ui.speedtest_window import DeviceThread
    monkeypatch.setattr(DeviceThread, "INTERVAL_S", 0.05)
    monkeypatch.setattr(provider, "fetch_provider", lambda: (False, None))
    w = SpeedTestWindow()
    _wait(lambda: w._provider_thread is None and w._link is not None)
    for _ in range(20):  # more Wi-Fi reads arrive after the provider's answer
        QApplication.processEvents()
        time.sleep(0.01)
    assert "Offline" in w.connection.text()
    w.close()


def test_coming_back_online_rechecks_the_provider(qapp, monkeypatch):
    from NetInfoView.ui.speedtest_window import DeviceThread
    monkeypatch.setattr(DeviceThread, "INTERVAL_S", 0.05)
    answers = iter([(False, None)] + [(True, PROVIDER)] * 50)
    monkeypatch.setattr(provider, "fetch_provider", lambda: next(answers))
    w = SpeedTestWindow()
    _wait(lambda: "Wi-Fi connected" in w.connection.text() and w.provider_name.text() == "AIS", 5)
    w.close()


def test_dropped_link_shows_offline(qapp, monkeypatch):
    from NetInfoView.ui.speedtest_window import DeviceThread
    monkeypatch.setattr(DeviceThread, "INTERVAL_S", 0.05)
    links = iter([LINK] + [DeviceLink()] * 500)
    monkeypatch.setattr(device_link, "device_link", lambda: next(links))
    w = SpeedTestWindow()
    _wait(lambda: "Offline" in w.connection.text(), 5)
    w.close()


def test_ipv4_only_connection(qapp, monkeypatch):
    from dataclasses import replace
    monkeypatch.setattr(provider, "fetch_provider", lambda: (True, replace(PROVIDER, ipv6="")))
    w = SpeedTestWindow()
    _wait(lambda: w._provider_thread is None)
    assert w.public_ip.text() == "203.0.113.9"
    assert w.public_ipv6.text() == "–" and not w.copy_public6.isEnabled()
    w.close()



def test_automatic_tries_the_nearest_ookla_servers(qapp):
    ookla = speedtest.FALLBACK_OOKLA
    ranked = [(speedtest.FALLBACK_SERVERS[0], 3.0),  # nearer, but not Ookla
              (ookla[0], 20.0), (ookla[1], 8.0), (ookla[2], None), (ookla[3], 9.0)]
    w = SpeedTestWindow(load_servers=False)
    assert w.options().server == speedtest.CLOUDFLARE  # until the list is timed
    assert w.options().candidates == ()
    w._servers_loaded(ranked)
    opts = w.options()
    assert opts.candidates == (ookla[1], ookla[3], ookla[0])  # nearest first
    assert w.server.text.text() == "Automatic (fastest nearby)"
    # After a run, the one it picked is named.
    w._finished(SpeedResult(meta={"server_url": ookla[3].url, "host": "x"}))
    assert w.server.text.text() == f"Automatic · {locate(ookla[3]).short}"
    # A server chosen by hand is used as is, with nothing to try first.
    w.set_choice(ookla[0])
    assert w.options().server == ookla[0] and w.options().candidates == ()
    w.close()


def test_automatic_is_remembered_as_automatic(window):  # noqa: F811
    w = window.speed_test()
    _wait(lambda: w._list_thread is None)
    w._servers_loaded([(speedtest.FALLBACK_OOKLA[1], 8.0)])
    w.set_choice(speedtest.CLOUDFLARE)
    w._remember_choice(w.options())
    # Not the server it resolved to this time, so the next run picks afresh.
    assert window.settings.speed_test_server == speedtest.CLOUDFLARE.url
    w.close()


def test_nearest_ookla_ignores_unreachable_and_other_kinds():
    a, b, c = speedtest.FALLBACK_OOKLA[:3]
    other = speedtest.FALLBACK_SERVERS[0]
    ranked = [(a, 30.0), (b, None), (other, 1.0), (c, 12.0)]
    assert speedtest.nearest_ookla(ranked) == [(c, 12.0)]
    assert speedtest.nearest_ookla(ranked, 5) == [(c, 12.0), (a, 30.0)]
    assert speedtest.nearest_ookla([(b, None)]) == []


def test_graph_reads_the_clock_and_shows_the_hovered_reading(qapp):
    from PyQt6.QtCore import QPointF

    from NetInfoView.ui.speedtest_window import LiveGraph, _clock

    g = LiveGraph()
    g.resize(800, 240)
    g.reset(10.0)
    g.begin("download")
    start = g.phase_start["download"]
    for i in range(1, 101):
        g.add("download", i / 10, 300.0 if i < 50 else 500.0)
    g.grab()  # paint once, so the panes are laid out
    plot = g._plots["download"]
    # Over the pane at 8 s into the download: the 500 Mbps reading there.
    g.hover = QPointF(plot.left() + plot.width() * 0.8, plot.center().y())
    phase, when, value = g.hovered()
    assert phase == "download" and value == 500.0
    assert when == pytest.approx(start + 8.0, abs=0.06)
    g.grab()  # the readout paints without error
    # Off the panes, or over a pane with no readings yet: nothing.
    g.hover = QPointF(2, 2)
    assert g.hovered() is None
    g.hover = QPointF(g._plots["upload"].center())
    assert g.hovered() is None
    assert len(_clock(start)) == 8 and _clock(start).count(":") == 2
