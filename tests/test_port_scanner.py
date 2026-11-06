"""Port Scan (ping/port_scanner.py and its window, ui/port_scan_window.py)."""

import socket
import sys
import threading

import pytest

from NetInfoView.ping import port_scanner
from NetInfoView.ui import port_scan_window
from test_main_window import window, qapp, _entries_with_statuses  # noqa: F401

#: What a refused TCP connect comes back as. Windows retries a refused
#: connect for ~2 s, past the timeout, so there it reads as filtered.
TCP_CLOSED = ("closed", "filtered") if sys.platform == "win32" else ("closed",)


@pytest.fixture
def listeners():
    """Two listening TCP ports on localhost: one that greets like SSH, one
    that stays silent; plus a port that was free and is now closed."""
    greeter = socket.socket()
    greeter.bind(("127.0.0.1", 0))
    greeter.listen()
    silent = socket.socket()
    silent.bind(("127.0.0.1", 0))
    silent.listen()
    with socket.socket() as spare:
        spare.bind(("127.0.0.1", 0))
        closed_port = spare.getsockname()[1]
    running = True

    def greet():
        while running:
            try:
                conn, _ = greeter.accept()
            except OSError:
                return
            with conn:
                conn.sendall(b"SSH-2.0-OpenSSH_9.6\r\n")

    thread = threading.Thread(target=greet, daemon=True)
    thread.start()
    yield greeter.getsockname()[1], silent.getsockname()[1], closed_port
    running = False
    greeter.close()
    silent.close()


def test_parse_port_spec():
    assert port_scanner.parse_port_spec("22, 80 443,80") == [22, 80, 443]
    assert port_scanner.parse_port_spec("8002-8000") == [8000, 8001, 8002]
    assert port_scanner.parse_port_spec("") == []
    assert len(port_scanner.parse_port_spec("1-65535")) == 65535
    with pytest.raises(ValueError, match="abc"):
        port_scanner.parse_port_spec("22, abc")
    with pytest.raises(ValueError, match="outside"):
        port_scanner.parse_port_spec("0-10")
    with pytest.raises(ValueError, match="outside"):
        port_scanner.parse_port_spec("70000")


def test_presets_parse():
    for _, spec in port_scanner.PRESETS:
        if spec:
            assert port_scanner.jobs_for(spec, ("tcp", "udp"))


def test_service_name_and_banner():
    assert port_scanner.service_name(22) == "SSH"
    assert port_scanner.service_name(8291) == "MikroTik Winbox"
    assert port_scanner.clean_banner(b"\r\n220 mail ESMTP\x00ready\r\nnext") == "220 mail ESMTPready"
    assert port_scanner.clean_banner(b"") == ""


def test_probe_open_closed_and_banner(listeners):
    greeter, silent, closed = listeners
    ssh = port_scanner.probe("127.0.0.1", greeter, timeout=1, banner_timeout=1)
    assert ssh.state == port_scanner.OPEN and ssh.banner == "SSH-2.0-OpenSSH_9.6"
    quiet = port_scanner.probe("127.0.0.1", silent, timeout=1, banner_timeout=0.1)
    assert quiet.state == port_scanner.OPEN and quiet.banner == ""
    assert port_scanner.probe("127.0.0.1", closed, timeout=1).state in TCP_CLOSED


def test_scan_reports_every_port_and_can_stop(listeners):
    greeter, silent, closed = listeners
    results = []
    assert port_scanner.scan("127.0.0.1", [greeter, silent, closed], results.append,
                             banner_timeout=0.1)
    states = {r.port: r.state for r in results}
    assert states[greeter] == states[silent] == "open" and states[closed] in TCP_CLOSED

    seen = []
    assert not port_scanner.scan("127.0.0.1", range(1, 5000), seen.append,
                                 should_stop=lambda: len(seen) >= 10, workers=4)
    assert len(seen) < 100


def test_window_scans_and_lists_open_ports(window, qapp, listeners):
    greeter, silent, closed = listeners
    scan = port_scan_window.PortScanWindow("127.0.0.1", window)
    scan.preset.setCurrentIndex(len(port_scanner.PRESETS) - 1)  # Custom
    scan.ports.setText(f"{closed},{silent},{greeter}")
    scan.start()
    thread = scan._thread
    assert scan.button.text() == "Stop"
    assert thread.wait(10000)
    qapp.processEvents()
    assert scan._thread is None and scan.button.text() == "Scan"
    assert [r.port for r in scan._results] == sorted([greeter, silent])
    assert scan.table.rowCount() == 2
    assert "2 open, " in scan.status.text()
    assert scan.table.item(1 if greeter > silent else 0, 3).text() == "SSH-2.0-OpenSSH_9.6"
    scan.close()


def test_window_rejects_bad_ports(window):
    scan = port_scan_window.PortScanWindow("127.0.0.1", window)
    scan.preset.setCurrentIndex(len(port_scanner.PRESETS) - 1)
    scan.ports.setText("22, http")
    scan.start()
    assert scan._thread is None and "http" in scan.status.text()
    scan.close()


def test_menu_opens_port_scan_for_the_selected_host(window, monkeypatch):
    started = []
    monkeypatch.setattr(port_scan_window.PortScanWindow, "start", lambda self: started.append(self))
    entries = _entries_with_statuses(window, "10.0.0.7")
    entries[0].ip_address = "10.0.0.7"
    window._table.selectRow(0)
    window.action_port_scan.trigger()
    assert started[0].host.text() == "10.0.0.7"
    assert window.action_port_scan in window._table.actions()
    assert window._dashboard.nav_port_scan.text() == "Port Scan"
    started[0].close()


@pytest.fixture
def udp_ports():
    """A UDP port that echoes, one that's bound but never replies, and one
    with nothing on it."""
    echo = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    echo.bind(("127.0.0.1", 0))
    silent = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    silent.bind(("127.0.0.1", 0))
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as spare:
        spare.bind(("127.0.0.1", 0))
        closed_port = spare.getsockname()[1]

    def serve():
        while True:
            try:
                data, peer = echo.recvfrom(4096)
                echo.sendto(b"hello from udp\n", peer)
            except OSError:
                return

    threading.Thread(target=serve, daemon=True).start()
    yield echo.getsockname()[1], silent.getsockname()[1], closed_port
    echo.close()
    silent.close()


def test_jobs_for_protocols():
    common = port_scanner.jobs_for(port_scanner.COMMON, ("tcp", "udp"))
    assert ("tcp", 22) in common and ("udp", 161) in common and ("udp", 22) not in common
    assert port_scanner.jobs_for("53, 80", ("udp",)) == [("udp", 53), ("udp", 80)]
    assert port_scanner.service_name(161, "udp") == "SNMP"


def test_udp_probes_are_real_requests():
    def payload(port):
        return port_scanner.udp_payload("10.0.0.1", port)[0]
    assert payload(123)[0] == 0x1B and len(payload(123)) == 48
    assert b"\x011\x010\x010\x0210\x07in-addr\x04arpa" in payload(53)
    assert payload(1900).startswith(b"M-SEARCH")
    assert payload(40000) == b""
    assert port_scanner.describe_reply(b"\x00\x01\xff\x02") == "replied (4 bytes)"


def test_probe_udp_states(udp_ports):
    echo, silent, closed = udp_ports
    answered = port_scanner.probe_udp("127.0.0.1", echo, timeout=0.4)
    assert answered.state == "open" and answered.banner == "hello from udp"
    assert answered.label == f"{echo}/udp"
    assert port_scanner.probe_udp("127.0.0.1", silent, timeout=0.4).state == "open|filtered"
    assert port_scanner.probe_udp("127.0.0.1", closed, timeout=0.4).state == "closed"


def test_window_scans_tcp_and_udp(window, qapp, listeners, udp_ports):
    greeter, _, _ = listeners
    echo, silent, closed = udp_ports
    scan = port_scan_window.PortScanWindow("127.0.0.1", window)
    scan.protocol.setCurrentIndex(2)  # TCP + UDP
    scan.preset.setCurrentIndex(len(port_scanner.PRESETS) - 1)
    scan.ports.setText(f"{greeter},{echo},{silent},{closed}")
    scan._timeout = 0.4
    scan.start()
    assert scan._thread.wait(10000)
    qapp.processEvents()
    shown = [r.label for r in scan._results]
    assert shown == [f"{port}/{proto}" for port, proto in sorted([(greeter, "tcp"), (echo, "udp")])]
    assert scan.table.rowCount() == 2
    assert "1 UDP open|filtered" in scan.status.text()
    scan.close()


def test_binary_greetings_are_not_shown_as_text():
    assert port_scanner.clean_banner(b"\xff\xfb\x01\xff\xfb\x03\xff\xfd\x18") == ""
    assert port_scanner.clean_banner(b"\xff\xfb\x01\r\nUser Access Verification\r\n") == "User Access Verification"
    assert port_scanner.describe_reply(b"\x12\x34\x81\x80\x00\x01" + b"\x07in-addr") == "replied (14 bytes)"
    assert port_scanner.describe_reply(b"HTTP/1.1 200 OK\r\nSERVER: Linux UPnP/1.0\r\n") == "HTTP/1.1 200 OK"


@pytest.fixture
def http_server():
    """A TCP port that says nothing until asked, then answers like nginx."""
    server = socket.socket()
    server.bind(("127.0.0.1", 0))
    server.listen(8)

    def serve():
        while True:
            try:
                conn, _ = server.accept()
            except OSError:
                return
            with conn:
                conn.settimeout(2)
                try:
                    if conn.recv(1024).startswith(b"HEAD"):
                        conn.sendall(b"HTTP/1.1 200 OK\r\nServer: nginx/1.24\r\n\r\n")
                except OSError:
                    pass

    threading.Thread(target=serve, daemon=True).start()
    yield server.getsockname()[1]
    server.close()


def test_silent_tcp_port_is_identified_as_a_web_server(http_server):
    result = port_scanner.probe("127.0.0.1", http_server, timeout=1, banner_timeout=0.3)
    assert result.state == "open" and result.banner == "HTTP 200 · nginx/1.24"


def test_describe_http():
    assert port_scanner.describe_http(b"HTTP/1.0 401 Unauthorized\r\nserver: GoAhead\r\n\r\n") == \
        "HTTP 401 · GoAhead"
    assert port_scanner.describe_http(b"SSH-2.0-x") == ""


def test_udp_decoders():
    payload, decode = port_scanner.udp_payload("10.0.0.1", 123)
    assert decode(bytes([0x24, 2]) + b"\0" * 46) == "NTPv4 · stratum 2"
    payload, decode = port_scanner.udp_payload("10.0.0.1", 53)
    reply = bytearray(payload)
    reply[2] |= 0x80
    reply[3] = 0x83
    assert decode(bytes(reply)) == "DNS answered (NXDOMAIN)"
    payload, decode = port_scanner.udp_payload("10.0.0.1", 5351)
    assert decode(bytes([0, 128, 0, 0, 0, 0, 0, 1, 203, 0, 113, 9])) == "NAT-PMP · external IP 203.0.113.9"
    for port in (111, 500, 1194, 2049, 3702, 5683, 47808):
        assert port_scanner.udp_payload("10.0.0.1", port)[0]
    ike = port_scanner.udp_payload("10.0.0.1", 500)[0]
    assert int.from_bytes(ike[24:28], "big") == len(ike)


def test_snmp_tries_settings_community_then_public(monkeypatch):
    from NetInfoView.ping import snmp
    monkeypatch.setattr(snmp, "_community", b"s3cret")
    first = port_scanner.udp_payload("10.0.0.1", 161, 0)[0]
    second = port_scanner.udp_payload("10.0.0.1", 161, 1)[0]
    assert b"s3cret" in first and b"public" in second


def test_recheck_settles_ports_a_rate_limit_hid(monkeypatch):
    """A host that sends one port unreachable per round, like Linux's ICMP
    limit: 10, 20 and 30 are closed, 40 really is silent."""
    closed = [10, 20, 30]
    answered_this_round = []

    def fake_probe(ip, port, timeout=1.0, attempts=2):
        if port in closed and not answered_this_round:
            answered_this_round.append(port)
            closed.remove(port)
            return port_scanner.PortResult(port, "closed", protocol="udp")
        return port_scanner.PortResult(port, "open|filtered", protocol="udp")

    monkeypatch.setattr(port_scanner, "probe_udp", fake_probe)
    settled, rounds = [], []

    def on_round(number, silent):
        answered_this_round.clear()
        rounds.append(silent)

    assert port_scanner.recheck_udp("127.0.0.1", [10, 20, 30, 40],
                                    lambda r: settled.append(r.port), on_round=on_round)
    assert sorted(settled) == [10, 20, 30]
    assert rounds == [4, 3, 2, 1]  # the last round settles nothing, so it stops


def test_greeting_after_telnet_negotiation():
    server = socket.socket()
    server.bind(("127.0.0.1", 0))
    server.listen(1)

    def serve():
        conn, _ = server.accept()
        with conn:
            conn.sendall(b"\xff\xfb\x01\xff\xfb\x03")
            import time
            time.sleep(0.1)
            conn.sendall(b"\r\nWelcome Visiting Gateway\r\nLogin: ")
            time.sleep(0.5)

    threading.Thread(target=serve, daemon=True).start()
    result = port_scanner.probe("127.0.0.1", server.getsockname()[1], banner_timeout=1)
    server.close()
    assert result.banner == "Welcome Visiting Gateway"
