"""Tests for MACs from a router's ARP table over SNMP (ping/snmp_arp.py)."""

import socket
import threading

import pytest

from pinginfoview.ping import ber, device_info, snmp_arp
from pinginfoview.ping.device_info import DeviceInfoJob

ARP = snmp_arp.ARP_TABLE_OID


def test_oid_round_trip():
    for oid in [ARP, ARP + (65, 192, 168, 104, 254), (1, 3, 6, 1, 4, 1, 9, 300000)]:
        assert snmp_arp.decode_oid(snmp_arp.encode_oid(oid)) == oid


def test_parse_routers():
    assert snmp_arp.parse_routers(" 10.0.0.1, 10.0.1.1\n10.0.2.1 ") == [
        "10.0.0.1", "10.0.1.1", "10.0.2.1",
    ]
    assert snmp_arp.parse_routers("") == []


def _response(request_id, binds, error=0):
    body = b"".join(
        ber.encode(ber.SEQUENCE, ber.encode(ber.OID, snmp_arp.encode_oid(oid)) + ber.encode(tag, value))
        for oid, tag, value in binds
    )
    pdu = ber.encode(
        0xA2,
        ber.encode_int(request_id) + ber.encode_int(error) + ber.encode_int(0)
        + ber.encode(ber.SEQUENCE, body),
    )
    return ber.encode(ber.SEQUENCE, ber.encode_int(1) + ber.encode(ber.OCTET_STRING, b"public") + pdu)


@pytest.fixture
def agent():
    """A fake SNMP agent on localhost serving `rows` ({OID: MAC bytes}), two
    rows per GETBULK, followed by an unrelated OID past the table."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("127.0.0.1", 0))
    rows = {}
    community = {"value": b"public"}

    def serve():
        while True:
            try:
                message, peer = sock.recvfrom(65535)
            except OSError:
                return
            _, start, end = ber.read(message)
            (_, _, _), (_, c_start, c_end), (_, pdu_start, pdu_end) = list(ber.children(message, start, end))
            if message[c_start:c_end] != community["value"]:
                continue  # wrong community: agents stay silent
            (_, id_start, id_end), _, _, (_, binds_start, binds_end) = list(ber.children(message, pdu_start, pdu_end))
            (_, bind_start, bind_end), = ber.children(message, binds_start, binds_end)
            (_, oid_start, oid_end), _ = ber.children(message, bind_start, bind_end)
            after = snmp_arp.decode_oid(message[oid_start:oid_end])
            following = sorted(oid for oid in rows if oid > after)[:2]
            binds = [(oid, ber.OCTET_STRING, rows[oid]) for oid in following]
            if len(binds) < 2:
                binds.append(((1, 3, 6, 1, 2, 1, 4, 23, 0), ber.INTEGER, b"\x00"))
            sock.sendto(_response(ber.decode_int(message, id_start, id_end), binds), peer)

    threading.Thread(target=serve, daemon=True).start()
    snmp_arp._cache.clear()
    yield sock.getsockname()[1], rows, community
    sock.close()
    snmp_arp._cache.clear()


def test_walk_reads_the_whole_arp_table(agent, monkeypatch):
    port, rows, _ = agent
    monkeypatch.setattr(snmp_arp, "SNMP_PORT", port)
    for n in range(1, 6):
        rows[ARP + (65, 192, 168, 104, n)] = bytes([0, 0x0C, 0x29, 0, 0, n])
    assert snmp_arp.walk("127.0.0.1", "public") == {
        f"192.168.104.{n}": f"00:0C:29:00:00:{n:02X}" for n in range(1, 6)
    }


def test_walk_gives_up_quietly_on_a_wrong_community(agent, monkeypatch):
    port, rows, community = agent
    monkeypatch.setattr(snmp_arp, "SNMP_PORT", port)
    rows[ARP + (65, 10, 0, 0, 1)] = b"\x00\x11\x22\x33\x44\x55"
    community["value"] = b"secret"
    assert snmp_arp.walk("127.0.0.1", "public", timeout=0.2) == {}


def test_lookup_many_asks_later_routers_only_for_what_is_missing(monkeypatch):
    tables = {
        "r1": {"10.0.0.1": "AA:AA:AA:AA:AA:01"},
        "r2": {"10.0.0.1": "BB:BB:BB:BB:BB:01", "10.0.1.1": "BB:BB:BB:BB:BB:02"},
        "r3": {"10.0.2.1": "CC:CC:CC:CC:CC:01"},
    }
    asked = []

    def fake_table(router, community):
        asked.append(router)
        return tables[router]

    monkeypatch.setattr(snmp_arp, "table", fake_table)
    assert snmp_arp.lookup_many(["10.0.0.1", "10.0.1.1"], ["r1", "r2", "r3"], "public") == {
        "10.0.0.1": "AA:AA:AA:AA:AA:01", "10.0.1.1": "BB:BB:BB:BB:BB:02",
    }
    assert asked == ["r1", "r2"]


def test_sweep_fills_macs_the_local_arp_table_lacks(monkeypatch):
    monkeypatch.setattr(device_info.dns_ptr, "system_nameservers", lambda: [])
    monkeypatch.setattr(device_info.arp, "lookup", lambda ip: "11:11:11:11:11:11" if ip == "192.168.1.5" else "")
    calls = []

    def fake_lookup_many(ips, routers, community):
        calls.append((ips, routers, community))
        return {"192.168.104.11": "00:50:56:A6:6C:0D"}

    monkeypatch.setattr(device_info.snmp_arp, "lookup_many", fake_lookup_many)

    class VendorDB:
        def lookup(self, mac):
            return "VMware, Inc." if mac.startswith("00:50:56") else ""

    jobs = [DeviceInfoJob(key=1, ip="192.168.1.5"), DeviceInfoJob(key=2, ip="192.168.104.11"),
            DeviceInfoJob(key=3, ip="192.168.104.99")]
    results = {r.key: r for r in device_info.resolve_batch(
        jobs, VendorDB(), snmp_routers=["192.168.104.254"], snmp_community="c")}
    assert calls == [(["192.168.104.11", "192.168.104.99"], ["192.168.104.254"], "c")]
    assert results[1].mac == "11:11:11:11:11:11"
    assert (results[2].mac, results[2].vendor) == ("00:50:56:A6:6C:0D", "VMware, Inc.")
    assert results[3].mac == ""
    # No routers configured: SNMP isn't touched.
    calls.clear()
    device_info.resolve_batch(jobs, VendorDB())
    assert calls == []


def test_guess_gateways_per_network():
    assert snmp_arp.guess_gateways(["192.168.104.11", "192.168.104.12", "10.0.5.254"]) == [
        "192.168.104.254", "192.168.104.1", "10.0.5.1",
    ]
    assert snmp_arp.guess_gateways(["fe80::1", "bogus"]) == []


def test_silent_router_is_not_asked_again_soon(monkeypatch):
    walks = []
    monkeypatch.setattr(snmp_arp, "walk", lambda router, community: walks.append(router) or {})
    snmp_arp._cache.clear()
    snmp_arp.table("10.0.0.254", "public")
    snmp_arp.table("10.0.0.254", "public")
    assert walks == ["10.0.0.254"]
    snmp_arp._cache.clear()


def test_sweep_auto_tries_configured_routers_then_usual_gateways(monkeypatch):
    monkeypatch.setattr(device_info.dns_ptr, "system_nameservers", lambda: [])
    monkeypatch.setattr(device_info.arp, "lookup", lambda ip: "")
    calls = []
    monkeypatch.setattr(device_info.snmp_arp, "lookup_many",
                        lambda ips, routers, community: calls.append(routers) or {})

    class VendorDB:
        def lookup(self, mac):
            return ""

    device_info.resolve_batch([DeviceInfoJob(key=1, ip="192.168.104.11")], VendorDB(),
                              snmp_routers=["10.9.9.9", "192.168.104.1"], snmp_auto=True)
    assert calls == [["10.9.9.9", "192.168.104.1", "192.168.104.254"]]
