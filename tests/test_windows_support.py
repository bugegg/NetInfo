"""Windows support: the parsing and mapping run everywhere; the tests that
call into Windows itself run only there (the Windows CI job)."""

import asyncio
import sys

import pytest

from NetInfoView.app_update import WINDOWS_ASSET_SUFFIX, parse_release
from NetInfoView.ping import arp
from NetInfoView.ping.icmp_windows import (
    IcmpWindowsPinger,
    ip_to_ipaddr,
    ipaddr_to_ip,
    status_for_ip_status,
)
from NetInfoView.ping.result import PingStatus

windows_only = pytest.mark.skipif(sys.platform != "win32", reason="calls Windows APIs")

WINDOWS_ARP = """
Interface: 192.168.1.5 --- 0xb
  Internet Address      Physical Address      Type
  192.168.1.1           aa-bb-cc-dd-ee-0f     dynamic
  192.168.1.20          00-11-22-33-44-55     dynamic
  192.168.1.255         ff-ff-ff-ff-ff-ff     static
  224.0.0.22            01-00-5e-00-00-16     static
"""


def test_parse_windows_arp_skips_broadcast_and_multicast():
    assert arp.parse_windows_arp(WINDOWS_ARP) == {
        "192.168.1.1": "AA:BB:CC:DD:EE:0F",
        "192.168.1.20": "00:11:22:33:44:55",
    }


def test_parse_windows_arp_ignores_localised_headers():
    thai = "อินเทอร์เฟซ: 10.0.0.2 --- 0x4\n  ที่อยู่อินเทอร์เน็ต  ที่อยู่ทางกายภาพ  ชนิด\n  10.0.0.1  0a-0b-0c-0d-0e-0f  ไดนามิก\n"
    assert arp.parse_windows_arp(thai) == {"10.0.0.1": "0A:0B:0C:0D:0E:0F"}


@pytest.mark.parametrize(
    "code, status",
    [
        (0, PingStatus.SUCCEEDED),
        (11010, PingStatus.TIMEOUT),
        (11003, PingStatus.HOST_UNREACHABLE),
        (11013, PingStatus.TTL_EXPIRED),
        (11009, PingStatus.FRAGMENTATION_NEEDED),
        (11050, PingStatus.GENERAL_FAILURE),
    ],
)
def test_status_for_ip_status(code, status):
    assert status_for_ip_status(code) is status


def test_ipaddr_round_trip_is_network_byte_order_in_memory():
    assert ip_to_ipaddr("1.2.3.4") == 0x04030201
    assert ipaddr_to_ip(ip_to_ipaddr("192.168.10.200")) == "192.168.10.200"


def test_parse_release_picks_the_windows_installer():
    data = {
        "tag_name": "v1.4",
        "assets": [
            {"name": "NetInfoView-1.4-arm64.zip", "browser_download_url": "https://x/mac.zip"},
            {"name": f"NetInfoView-1.4{WINDOWS_ASSET_SUFFIX}", "browser_download_url": "https://x/win.exe"},
        ],
    }
    assert parse_release(data, windows=True).asset_url == "https://x/win.exe"
    assert parse_release(data, machine="arm64", windows=False).asset_url == "https://x/mac.zip"


@windows_only
def test_real_ping_to_loopback():
    async def go():
        pinger = IcmpWindowsPinger()
        pinger.open()
        try:
            return await pinger.ping("127.0.0.1", 2000)
        finally:
            pinger.close()

    result = asyncio.run(go())
    assert result.status is PingStatus.SUCCEEDED
    assert result.reply_ip == "127.0.0.1"
    assert result.rtt_ms is not None and result.rtt_ms >= 0


@windows_only
def test_real_ping_to_unroutable_address_times_out():
    async def go():
        pinger = IcmpWindowsPinger()
        try:
            return await pinger.ping("192.0.2.1", 500)  # TEST-NET-1, never answers
        finally:
            pinger.close()

    assert not asyncio.run(go()).succeeded


@windows_only
def test_windows_nameservers_returns_addresses():
    from NetInfoView.ping.dns_ptr import windows_nameservers

    servers = windows_nameservers()
    assert isinstance(servers, list)
    assert all(server.count(".") == 3 or ":" in server for server in servers)


@windows_only
def test_list_interfaces_on_windows():
    from NetInfoView.ping.network_interfaces import list_interfaces

    for interface in list_interfaces():
        assert interface.cidr.count("/") == 1


# -- Check MTU / Trace Path MTU ------------------------------------------------


@pytest.mark.parametrize(
    "status, source, kind",
    [
        (PingStatus.SUCCEEDED, "10.0.0.9", "reached"),
        (PingStatus.TTL_EXPIRED, "192.168.1.1", "exceeded"),
        (PingStatus.FRAGMENTATION_NEEDED, "10.0.0.1", "frag"),
        (PingStatus.FRAGMENTATION_NEEDED, "", "frag"),  # this PC's own link refused it
        (PingStatus.HOST_UNREACHABLE, "10.0.0.1", "unreachable"),
        (PingStatus.HOST_UNREACHABLE, "", "timeout"),  # no router to pin it on
        (PingStatus.TIMEOUT, "", "timeout"),
        (PingStatus.GENERAL_FAILURE, "", "timeout"),
    ],
)
def test_echo_statuses_become_trace_replies(status, source, kind):
    from NetInfoView.ping.tracepath import reply_for_status

    reply = reply_for_status(status, source)
    assert reply.kind == kind
    assert reply.source == (source if kind != "timeout" else "")
    if kind == "unreachable":
        assert reply.text == "Destination Host Unreachable"


def test_a_frag_without_an_mtu_is_searched_for():
    """IcmpSendEcho doesn't pass on the MTU a router names, so the drop is
    found by search, and pinned on the hop all the same."""
    from NetInfoView.ping import tracepath
    from NetInfoView.ping.tracepath import FRAG, REACHED, Reply

    def probe(ip, ttl, payload):
        return Reply(REACHED, "10.0.0.9") if payload + tracepath.HEADERS <= 1400 else Reply(FRAG)

    hop = tracepath.trace_hop("10.0.0.9", 1, 1500, probe)
    assert hop.mtu == 1400 and hop.reached
    assert hop.note == "MTU drops to 1400 (no router reported it)"


@windows_only
def test_real_mtu_probe_on_windows():
    from NetInfoView.ping import mtu

    assert mtu.probe("127.0.0.1", 1473)
    assert mtu.find_mtu("127.0.0.1") == mtu.MAX_MTU


@windows_only
def test_loopback_sets_no_link_mtu_ceiling():
    from NetInfoView.ping.icmp_windows import link_mtu

    assert link_mtu("127.0.0.1") is None


@windows_only
def test_link_mtu_of_the_default_route():
    from NetInfoView.ping.icmp_windows import link_mtu

    found = link_mtu("8.8.8.8")
    assert found is None or 576 <= found <= 65535


# -- Whois ----------------------------------------------------------------------


IANA_8888 = "% IANA WHOIS server\n\nrefer:        whois.arin.net\n\ninetnum:      8.0.0.0 - 8.255.255.255\n"
ARIN_8888 = "NetRange:       8.8.8.0 - 8.8.8.255\nNetName:        GOGL\n"


def test_direct_whois_follows_ianas_referral():
    from NetInfoView.ping import whois

    asked = []

    def ask(server, text, port):
        asked.append((server, text, port))
        return {"whois.iana.org": IANA_8888, "whois.arin.net": ARIN_8888}[server]

    output = whois.query_direct("8.8.8.8", ask=ask)
    assert asked == [("whois.iana.org", "8.8.8.8", 43), ("whois.arin.net", "8.8.8.8", 43)]
    assert whois.parse(output) == "GOGL"


def test_direct_whois_follows_arins_referral_server_once():
    from NetInfoView.ping import whois

    answers = {
        "whois.iana.org": "refer: whois.arin.net\n",
        "whois.arin.net": "NetName: RIPE-ERX\nReferralServer:  whois://whois.ripe.net\n",
        # Points back at ARIN: must not loop.
        "whois.ripe.net": "netname: EXAMPLE-NET\nwhois: whois.arin.net\n",
    }
    asked = []

    def ask(server, text, port):
        asked.append(server)
        return answers[server]

    assert whois.parse(whois.query_direct("193.0.0.1", ask=ask)) == "EXAMPLE-NET"
    assert asked == ["whois.iana.org", "whois.arin.net", "whois.ripe.net"]


def test_direct_whois_to_a_named_server_asks_only_it():
    from NetInfoView.ping import whois

    asked = []
    whois.query_direct(" -v 8.8.8.8", whois.CYMRU,
                       ask=lambda s, t, p: asked.append((s, t)) or "")
    assert asked == [(whois.CYMRU, "-v 8.8.8.8")]


def test_whois_referral_forms():
    from NetInfoView.ping.whois import referral

    assert referral("refer:        whois.apnic.net\n") == ("whois.apnic.net", 43)
    assert referral("ReferralServer:  whois://whois.ripe.net\n") == ("whois.ripe.net", 43)
    assert referral("ReferralServer:  rwhois://rwhois.example.net:4321\n") == (
        "rwhois.example.net", 4321)
    assert referral("netname: X\n") is None


# -- LLDP/CDP through Npcap ----------------------------------------------------


def test_npcap_connection_status():
    from NetInfoView.ping import npcap

    assert npcap.is_connected(npcap.PCAP_IF_CONNECTION_STATUS_CONNECTED)
    assert not npcap.is_connected(0x20 | npcap.PCAP_IF_UP | npcap.PCAP_IF_RUNNING)
    # Status unknown: go by up and running.
    assert npcap.is_connected(npcap.PCAP_IF_UP | npcap.PCAP_IF_RUNNING)
    assert not npcap.is_connected(npcap.PCAP_IF_UP)


def test_npcap_installed_after_launch_is_found_on_refresh(monkeypatch):
    import ctypes

    from NetInfoView.ping import npcap

    monkeypatch.setattr(npcap, "_dll", None)
    monkeypatch.setattr(npcap.os, "add_dll_directory", lambda path: None, raising=False)

    def missing(path):
        raise OSError("not found")

    monkeypatch.setattr(ctypes, "CDLL", missing)
    assert npcap.available() == npcap.NOT_INSTALLED

    class FakeFunction:
        pass

    class FakeDll:
        def __getattr__(self, name):
            function = FakeFunction()
            setattr(self, name, function)
            return function

    monkeypatch.setattr(ctypes, "CDLL", lambda path: FakeDll())
    assert npcap.available() == ""


def test_npcap_adapters_are_named_as_windows_names_them(monkeypatch):
    from NetInfoView.ping import network_interfaces as ni
    from NetInfoView.ping import npcap

    monkeypatch.setattr(npcap, "devices", lambda: [
        npcap.Device(r"\Device\NPF_{W}", "Intel(R) Wi-Fi 6 AX201", ("192.168.1.5",), True, True),
        npcap.Device(r"\Device\NPF_{D}", "Realtek USB GbE", (), False, False),
        npcap.Device(r"\Device\NPF_{E}", "Intel(R) Ethernet I219-V", ("10.0.0.5",), True, False),
    ])
    monkeypatch.setattr(ni, "_friendly_names_by_ip",
                        lambda: {"192.168.1.5": "Wi-Fi", "10.0.0.5": "Ethernet 2"})
    found = ni._ethernet_interfaces_npcap()
    assert [(i.name, i.label, i.active) for i in found] == [
        (r"\Device\NPF_{E}", "Ethernet 2 (Intel(R) Ethernet I219-V) — 10.0.0.5", True),
        (r"\Device\NPF_{W}", "Wi-Fi (Intel(R) Wi-Fi 6 AX201) — 192.168.1.5", True),
        (r"\Device\NPF_{D}", "Realtek USB GbE", False),
    ]


def test_without_npcap_there_are_no_adapters(monkeypatch):
    from NetInfoView.ping import network_interfaces as ni
    from NetInfoView.ping import npcap

    def missing():
        raise npcap.NpcapError(npcap.NOT_INSTALLED)

    monkeypatch.setattr(npcap, "devices", missing)
    assert ni._ethernet_interfaces_npcap() == []


def test_npcap_listen_reports_each_switch_port_once(monkeypatch):
    from NetInfoView.ping import lldp_cdp, npcap
    from test_lldp_cdp import cdp_frame, lldp_frame

    frames = {"good": [lldp_frame(), None, lldp_frame(), cdp_frame()]}

    class FakeCapture:
        def __init__(self, name, program):
            if name == "bad":
                raise npcap.NpcapError("access denied")
            assert program.bf_len == len(lldp_cdp._FILTER)
            self.name, self.closed = name, False

        def next_frame(self):
            queue = frames[self.name]
            return queue.pop(0) if queue else None

        def close(self):
            self.closed = True

    monkeypatch.setattr(npcap, "Capture", FakeCapture)
    heard, errors = [], []
    lldp_cdp._listen_npcap(["bad", "good"], heard.append, 0.3, lambda: False,
                           lambda i, m: errors.append((i, m)))
    assert [(n.interface, n.protocol) for n in heard] == [("good", "LLDP"), ("good", "CDP")]
    assert errors == [("bad", "access denied")]



def test_downloads_are_verified_by_the_operating_system():
    import truststore

    from NetInfoView.https import ssl_context

    assert isinstance(ssl_context(), truststore.SSLContext)


# -- Repeat Ping on Windows ---------------------------------------------------


def test_repeat_ping_sends_the_pattern_through_icmpsendecho(monkeypatch):
    """WindowsEcho hands the IOS pattern data to send_echo (runs anywhere:
    the iphlpapi calls are replaced)."""
    from NetInfoView.ping import icmp_windows, repeat_ping
    from NetInfoView.ping.result import PingResult

    calls = []
    monkeypatch.setattr(icmp_windows, "_IcmpApi", lambda: object())

    def fake_send_echo(api, ip, timeout_ms, size, ttl, dont_fragment, data=None):
        calls.append((ip, timeout_ms, size, dont_fragment, data))
        return PingResult(PingStatus.SUCCEEDED, 1.0, ip, 64)

    monkeypatch.setattr(icmp_windows, "send_echo", fake_send_echo)
    chars = []
    options = repeat_ping.RepeatOptions(count=3)
    assert repeat_ping.run("10.0.0.1", options, lambda c, r, s: chars.append(c),
                           echo_factory=repeat_ping.WindowsEcho)
    assert chars == ["!", "!", "!"]
    ip, timeout_ms, size, dont_fragment, data = calls[0]
    assert (ip, timeout_ms, size, dont_fragment) == ("10.0.0.1", 2000, 72, False)
    assert data == repeat_ping.payload(100, 0xABCD)


@windows_only
def test_real_repeat_ping_to_loopback_on_windows():
    from NetInfoView.ping import repeat_ping

    chars = []
    assert repeat_ping.run("127.0.0.1", repeat_ping.RepeatOptions(count=50),
                           lambda c, r, s: chars.append(c))
    assert chars == ["!"] * 50


@windows_only
def test_send_echo_carries_the_given_data():
    from NetInfoView.ping import icmp_windows

    api = icmp_windows._IcmpApi()
    result = icmp_windows.send_echo(api, "127.0.0.1", 2000, 8, 64, False, data=b"\xab\xcd" * 4)
    assert result.status is PingStatus.SUCCEEDED
