"""Windows support: the parsing and mapping run everywhere; the tests that
call into Windows itself run only there (the Windows CI job)."""

import asyncio
import sys

import pytest

from pinginfoview.app_update import WINDOWS_ASSET_SUFFIX, parse_release
from pinginfoview.ping import arp
from pinginfoview.ping.icmp_windows import (
    IcmpWindowsPinger,
    ip_to_ipaddr,
    ipaddr_to_ip,
    status_for_ip_status,
)
from pinginfoview.ping.result import PingStatus

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
            {"name": "NetInfo-1.4-arm64.zip", "browser_download_url": "https://x/mac.zip"},
            {"name": f"NetInfo-1.4{WINDOWS_ASSET_SUFFIX}", "browser_download_url": "https://x/win.exe"},
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
    from pinginfoview.ping.dns_ptr import windows_nameservers

    servers = windows_nameservers()
    assert isinstance(servers, list)
    assert all(server.count(".") == 3 or ":" in server for server in servers)


@windows_only
def test_list_interfaces_on_windows():
    from pinginfoview.ping.network_interfaces import list_interfaces

    for interface in list_interfaces():
        assert interface.cidr.count("/") == 1
