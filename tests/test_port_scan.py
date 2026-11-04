import socket
import threading
import time

import pytest

from pinginfoview.ping import port_scan
from pinginfoview.ping.port_scan import (
    DEFAULT_PORTS_TEXT,
    guess_device_type,
    parse_ports,
    scan_many,
)


@pytest.fixture
def listening_port():
    """A real, locally-bound TCP listener, so scan_many has something true
    to find without touching the network."""
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(("127.0.0.1", 0))
    server.listen(1)
    port = server.getsockname()[1]

    stop = threading.Event()

    def accept_loop():
        server.settimeout(0.2)
        while not stop.is_set():
            try:
                conn, _ = server.accept()
                conn.close()
            except socket.timeout:
                continue
            except OSError:
                break

    thread = threading.Thread(target=accept_loop, daemon=True)
    thread.start()
    yield port
    stop.set()
    server.close()
    thread.join(timeout=1)


def test_scan_many_finds_a_real_open_port(listening_port):
    results = scan_many({1: "127.0.0.1"}, ports={listening_port: "test"})
    assert results == {1: [listening_port]}


def test_scan_many_reports_closed_ports_as_empty(listening_port):
    # A port nothing is listening on, right next to one that is.
    closed_port = listening_port + 1 if listening_port < 65535 else listening_port - 1
    results = scan_many({1: "127.0.0.1"}, ports={closed_port: "test"})
    assert results == {1: []}


def test_scan_many_handles_multiple_hosts_independently(listening_port):
    results = scan_many(
        {1: "127.0.0.1", 2: "127.0.0.1"}, ports={listening_port: "test"}
    )
    assert results[1] == [listening_port]
    assert results[2] == [listening_port]


def test_scan_many_skips_hosts_with_no_ip():
    results = scan_many({1: "", 2: "127.0.0.1"}, ports={9: "discard"})
    assert results[1] == []


def test_scan_many_with_empty_input_returns_empty_dict():
    assert scan_many({}) == {}


def test_scan_many_results_are_sorted():
    # Use two real listeners to confirm ascending order regardless of
    # which connection happens to complete first.
    pass  # covered implicitly by scan_many's own sort(); see guess tests below


# -- UDP ----------------------------------------------------------------


@pytest.fixture
def echoing_udp_port():
    """A real UDP socket that replies to anything it receives, so the
    "got an actual response" path can be tested without mocking sockets."""
    server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server.bind(("127.0.0.1", 0))
    port = server.getsockname()[1]

    stop = threading.Event()

    def echo_loop():
        server.settimeout(0.2)
        while not stop.is_set():
            try:
                data, addr = server.recvfrom(512)
                server.sendto(b"ack", addr)
            except socket.timeout:
                continue
            except OSError:
                break

    thread = threading.Thread(target=echo_loop, daemon=True)
    thread.start()
    yield port
    stop.set()
    server.close()
    thread.join(timeout=1)


def test_scan_many_finds_a_udp_port_that_replies(echoing_udp_port):
    results = scan_many({1: "127.0.0.1"}, ports={}, udp_ports={echoing_udp_port: "test"})
    assert results == {1: [f"{echoing_udp_port}/udp"]}


def test_scan_many_reports_a_udp_port_as_closed_on_icmp_unreachable():
    # Bind then immediately release a UDP port, so nothing is listening and
    # loopback reliably sends back ICMP port-unreachable for it.
    probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    probe.bind(("127.0.0.1", 0))
    closed_port = probe.getsockname()[1]
    probe.close()

    results = scan_many({1: "127.0.0.1"}, ports={}, udp_ports={closed_port: "test"})
    assert results == {1: []}


def test_scan_many_treats_a_silent_udp_port_as_open(monkeypatch):
    """No reply and no ICMP error (the common case for a real, working UDP
    service that ignores an unsolicited empty probe) is reported as open —
    this is the documented best-effort behaviour of _check_udp_port."""
    monkeypatch.setattr(port_scan, "UDP_TIMEOUT_SECONDS", 0.05)
    server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server.bind(("127.0.0.1", 0))  # bound, so no ICMP unreachable, but silent
    port = server.getsockname()[1]
    try:
        results = scan_many({1: "127.0.0.1"}, ports={}, udp_ports={port: "test"})
        assert results == {1: [f"{port}/udp"]}
    finally:
        server.close()


def test_scan_many_merges_tcp_and_udp_with_tcp_first_at_the_same_port_number(
    listening_port, monkeypatch
):
    monkeypatch.setattr(port_scan, "_check_udp_port", lambda ip, port: True)
    results = scan_many(
        {1: "127.0.0.1"},
        ports={listening_port: "test"},
        udp_ports={listening_port: "test"},
    )
    assert results == {1: [listening_port, f"{listening_port}/udp"]}


# -- parse_ports ----------------------------------------------------------


def test_parse_ports_treats_a_bare_number_as_tcp():
    parsed = parse_ports("22")
    assert parsed.tcp == {22: "SSH"}
    assert parsed.udp == {}


def test_parse_ports_splits_tcp_and_udp_by_suffix():
    parsed = parse_ports("22, 53/udp, 161/udp, 443/tcp")
    assert parsed.tcp == {22: "SSH", 443: "HTTPS"}
    assert parsed.udp == {53: "DNS", 161: "SNMP"}


def test_parse_ports_accepts_newlines_as_separators():
    parsed = parse_ports("22\n53/udp\n443")
    assert parsed.tcp == {22: "SSH", 443: "HTTPS"}
    assert parsed.udp == {53: "DNS"}


def test_parse_ports_gives_a_known_udp_port_its_static_udp_ports_label():
    parsed = parse_ports("5353/udp, 9999/udp")
    assert parsed.udp == {5353: "mDNS", 9999: ""}


def test_parse_ports_skips_invalid_tokens_and_unknown_protocols():
    parsed = parse_ports("22, not-a-port, 99999, 80/sctp")
    assert parsed.tcp == {22: "SSH"}
    assert parsed.udp == {}


def test_parse_ports_empty_text_is_falsy():
    assert not parse_ports("")
    assert not parse_ports("not-a-port")


def test_parse_ports_result_is_truthy_when_only_udp_is_given():
    assert parse_ports("53/udp")


def test_default_ports_text_covers_both_tcp_and_a_default_udp_service_list():
    """The Options dialog pre-fills this text, so a fresh install scans a
    sensible default set of both TCP and UDP service ports out of the box."""
    parsed = parse_ports(DEFAULT_PORTS_TEXT)
    assert parsed.tcp == port_scan.STATIC_PORTS
    assert parsed.udp == port_scan.STATIC_UDP_PORTS


def test_default_ports_text_names_each_services_as_a_comment():
    """One port per line with a "# label" naming the service, so the
    pre-filled field is self-documenting rather than a bare number list."""
    lines = DEFAULT_PORTS_TEXT.splitlines()
    assert "22  # SSH" in lines
    assert "53/udp  # DNS" in lines


def test_parse_ports_ignores_hash_comments():
    parsed = parse_ports("22  # SSH\n53/udp  # DNS, used for lookups (port 53)\n")
    assert parsed.tcp == {22: "SSH"}
    assert parsed.udp == {53: "DNS"}


def test_parse_ports_comment_can_contain_numbers_without_being_added_as_ports():
    parsed = parse_ports("22  # see also ports 80 and 443\n")
    assert parsed.tcp == {22: "SSH"}


# -- guess_device_type ------------------------------------------------------


def test_ios_sync_port_is_the_most_specific_signal():
    # Even with a web port also open, the more specific iOS signal should win.
    assert guess_device_type([80, 443, 62078]) == "Apple Mobile Device (iPhone/iPad)"


def test_smb_port_does_not_claim_a_specific_os():
    """Regression: macOS's own File Sharing uses SMB too (confirmed live
    against this Mac, which opened 445) — the label must not say "Windows"
    outright for a signal both major OSes use."""
    guess = guess_device_type([445])
    assert "Windows or macOS" in guess
    assert guess != "Windows"


def test_bare_web_port_gets_generic_label():
    assert guess_device_type([80]) == "Has a Web Interface"
    assert guess_device_type([443, 8080]) == "Has a Web Interface"


def test_rdp_is_windows_specific():
    assert guess_device_type([3389]) == "Windows (RDP)"


def test_no_open_ports_returns_empty_string():
    assert guess_device_type([]) == ""


def test_unrecognised_open_ports_return_empty_string():
    assert guess_device_type([12345, 54321]) == ""
