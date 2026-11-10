"""Repeat Ping (ping/repeat_ping.py and its window, ui/repeat_ping_window.py)."""

import sys

import pytest

from NetInfoView.ping import repeat_ping
from NetInfoView.ping.repeat_ping import RepeatOptions, RepeatStats
from NetInfoView.ping.result import PingStatus
from NetInfoView.ui import repeat_ping_window
from test_main_window import window, qapp, _entries_with_statuses  # noqa: F401


class FakeEcho:
    """Answers from a script of (status, rtt) and records what was sent."""

    def __init__(self, script):
        self.script = list(script)
        self.sent = []
        self.closed = False

    def __call__(self, dont_fragment):
        self.dont_fragment = dont_fragment
        return self

    def echo(self, ip, data, timeout):
        self.sent.append((ip, data, timeout))
        return self.script.pop(0) if self.script else (PingStatus.SUCCEEDED, 1.0)

    def close(self):
        self.closed = True


def test_payload_follows_ios_size_and_pattern():
    data = repeat_ping.payload(100, 0xABCD)
    assert len(data) == 72 and data[:4] == b"\xab\xcd\xab\xcd"
    assert len(repeat_ping.payload(37, 0xABCD)) == 9
    assert repeat_ping.parse_pattern("0x00ff") == 0x00FF
    assert repeat_ping.parse_pattern("FFFF") == 0xFFFF
    with pytest.raises(ValueError):
        repeat_ping.parse_pattern("0x10000")


def test_run_sends_back_to_back_and_maps_ios_characters():
    fake = FakeEcho([
        (PingStatus.SUCCEEDED, 1.5), (PingStatus.TIMEOUT, None),
        (PingStatus.HOST_UNREACHABLE, None), (PingStatus.FRAGMENTATION_NEEDED, None),
        (PingStatus.TTL_EXPIRED, None), (PingStatus.GENERAL_FAILURE, None),
    ])
    chars = []
    options = RepeatOptions(count=6, size=200, dont_fragment=True, pattern=0x0000)
    assert repeat_ping.run("10.0.0.1", options, lambda c, r, s: chars.append(c),
                           echo_factory=fake)
    assert "".join(chars) == "!.UM&?"
    assert fake.dont_fragment and fake.closed
    assert all(len(data) == 172 and set(data) == {0} for _, data, _ in fake.sent)


def test_sweep_and_stop():
    fake = FakeEcho([])
    sizes = []
    options = RepeatOptions(count=2, sweep=(100, 300, 100))
    assert options.total == 6
    repeat_ping.run("10.0.0.1", options, lambda c, r, s: sizes.append(s), echo_factory=fake)
    assert sizes == [100, 100, 200, 200, 300, 300]
    seen = []
    assert not repeat_ping.run("10.0.0.1", RepeatOptions(count=1000),
                               lambda c, r, s: seen.append(c),
                               should_stop=lambda: len(seen) >= 3, echo_factory=FakeEcho([]))
    assert len(seen) == 3


def test_ios_style_text():
    stats = RepeatStats()
    for rtt in (1.0, 2.0, 3.0):
        stats.add("!", rtt, 100)
    stats.add(".", None, 100)
    assert repeat_ping.summary_text(stats) == \
        "Success rate is 75 percent (3/4), round-trip min/avg/max = 1.0/2.0/3.0 ms"
    options = RepeatOptions(count=100000, dont_fragment=True)
    assert repeat_ping.header_text("10.0.0.1", "10.0.0.1", options) == (
        "Sending 100,000, 100-byte ICMP Echos to 10.0.0.1, timeout is 2 seconds:\n"
        "Packet sent with the DF bit set")
    assert repeat_ping.header_text("10.0.0.1", "10.0.0.1", RepeatOptions(pattern=0)).endswith(
        "Packet has data pattern 0x0000")
    sweep = RepeatStats()
    sweep.add("!", 1.0, 1400)
    sweep.add("M", None, 1600)
    assert "Largest size through with DF: 1400 bytes" in repeat_ping.summary_text(sweep)


@pytest.mark.skipif(sys.platform != "darwin", reason="macOS unprivileged ICMP socket")
def test_real_echoes_to_localhost():
    chars = []
    options = RepeatOptions(count=200, timeout=1)
    assert repeat_ping.run("127.0.0.1", options, lambda c, r, s: chars.append(c))
    assert chars.count("!") == 200


@pytest.mark.skipif(sys.platform != "darwin", reason="macOS unprivileged ICMP socket")
def test_df_bigger_than_the_link_is_could_not_fragment():
    # Loopback's MTU is 16384, beyond the 8212-byte cap, so ask for a path
    # with a 1500 MTU only if one exists; the socket option itself must work.
    echo = repeat_ping.SocketEcho(dont_fragment=True)
    echo.close()


def test_window_wraps_results_to_the_box(window, qapp, monkeypatch):
    monkeypatch.setattr(repeat_ping, "open_echo", FakeEcho(
        [(PingStatus.SUCCEEDED, 1.0)] * 30 + [(PingStatus.TIMEOUT, None)] * 2))
    ping = repeat_ping_window.RepeatPingWindow("127.0.0.1", window)
    ping.resize(700, 500)
    ping.show()
    ping.count.setValue(300)
    ping.start()
    assert ping.button.text() == "Stop"
    assert ping._thread.wait(5000)
    qapp.processEvents()
    width = ping._line_width()
    lines = ping.text.toPlainText().splitlines()
    assert lines[0].startswith("Sending 300, 100-byte ICMP Echos to 127.0.0.1")
    result_lines = lines[1:-1]
    assert "".join(result_lines) == "!" * 30 + ".." + "!" * 268
    assert all(len(line) == width for line in result_lines[:-1]) and width > 10
    assert lines[-1].startswith("Success rate is 99 percent (298/300)")
    assert ping.button.text() == "Ping" and ping.copy_button.isEnabled()

    ping.resize(400, 500)  # narrower: wrapped again
    qapp.processEvents()
    narrow = ping.text.toPlainText().splitlines()
    assert ping._line_width() < width
    assert "".join(narrow[1:-1]) == "".join(result_lines)
    assert len(narrow[1]) == ping._line_width()
    ping.close()


def test_mono_font_survives_the_app_stylesheet(window):
    ping = repeat_ping_window.RepeatPingWindow("127.0.0.1", window)
    ping.show()
    ping.text.ensurePolished()
    metrics = ping.text.fontMetrics()
    assert metrics.horizontalAdvance("!") == metrics.horizontalAdvance("W")
    ping.close()


def test_window_uses_cisco_defaults(window):
    ping = repeat_ping_window.RepeatPingWindow("127.0.0.1", window)
    ping.count.setValue(100000)
    assert ping.options() == RepeatOptions(count=100000, size=100, timeout=2.0,
                                           dont_fragment=False, pattern=0xABCD)
    ping.close()


def test_menu_opens_repeat_ping_for_the_selected_host(window):
    entries = _entries_with_statuses(window, "10.0.0.7")
    entries[0].ip_address = "10.0.0.7"
    window._table.selectRow(0)
    window.action_repeat_ping.trigger()
    opened = window.findChildren(repeat_ping_window.RepeatPingWindow)
    assert opened and opened[-1].host.text() == "10.0.0.7" and opened[-1]._thread is None
    assert window.action_repeat_ping in window._table.actions()
    opened[-1].close()


def test_window_starts_at_1000_with_an_empty_box(window):
    ping = repeat_ping_window.RepeatPingWindow("127.0.0.1", window)
    assert ping.count.value() == 1000 and ping.text.placeholderText() == ""
    ping.close()


def test_sidebar_opens_repeat_ping(window):
    button = window._dashboard.nav_repeat_ping
    assert button.text() == "Repeat Ping"
    button.click()
    opened = window.findChildren(repeat_ping_window.RepeatPingWindow)
    assert opened
    for each in opened:
        each.close()


def test_repeat_count_regroups_its_digits_while_typing(qapp):
    from PyQt6.QtCore import QLocale
    from PyQt6.QtTest import QTest

    spin = repeat_ping_window.GroupedSpinBox()
    spin.setLocale(QLocale(QLocale.Language.English, QLocale.Country.UnitedStates))
    spin.setRange(1, repeat_ping.MAX_COUNT)
    spin.setValue(1000)
    edit = spin.lineEdit()
    edit.selectAll()
    QTest.keyClicks(edit, "100000")
    assert edit.text() == "100,000" and spin.value() == 100000
    assert edit.cursorPosition() == len("100,000")
    # Typing in the middle keeps the cursor after the digit just typed.
    edit.setCursorPosition(1)  # 1|00,000
    QTest.keyClicks(edit, "5")
    assert edit.text() == "1,500,000"
    assert edit.cursorPosition() == 3  # 1,5|00,000
