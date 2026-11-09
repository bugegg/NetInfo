import socket
import struct

from NetInfoView.ping import arp_scan
from NetInfoView.ping.network_interfaces import NetworkInterface

OURS = bytes.fromhex("ac0775146 52a".replace(" ", ""))


def _reply(ip, mac, to_ip="192.168.1.5"):
    return (
        OURS + mac + struct.pack("!H", 0x0806)
        + struct.pack("!HHBBH", 1, 0x0800, 6, 4, 2)
        + mac + socket.inet_aton(ip) + OURS + socket.inet_aton(to_ip)
    )


def test_request_is_a_broadcast_who_has():
    frame = arp_scan.build_request(OURS, "192.168.1.5", "192.168.1.9")
    assert frame[:6] == b"\xff" * 6 and frame[6:12] == OURS
    assert frame[12:14] == b"\x08\x06" and frame[20:22] == b"\x00\x01"
    assert frame[22:28] == OURS and frame[28:32] == socket.inet_aton("192.168.1.5")
    assert frame[38:42] == socket.inet_aton("192.168.1.9")


def test_parse_reply_reads_the_sender():
    mac = bytes.fromhex("00505685ddf0")
    assert arp_scan.parse_reply(_reply("192.168.1.16", mac)) == (
        "192.168.1.16", "00:50:56:85:DD:F0")


def test_parse_reply_ignores_requests_and_other_frames():
    assert arp_scan.parse_reply(arp_scan.build_request(OURS, "192.168.1.5", "192.168.1.9")) is None
    assert arp_scan.parse_reply(b"\0" * 60) is None


def test_own_mac_comes_from_a_frame_we_sent():
    ipv4 = b"\xff" * 6 + OURS + b"\x08\x00" + b"\x45" + b"\0" * 11 + socket.inet_aton("192.168.1.5") + b"\0" * 8
    assert arp_scan.own_mac_from_frame(ipv4, "192.168.1.5") == OURS
    assert arp_scan.own_mac_from_frame(ipv4, "192.168.1.6") is None
    request = arp_scan.build_request(OURS, "192.168.1.5", "192.168.1.9")
    assert arp_scan.own_mac_from_frame(request, "192.168.1.5") == OURS


def test_only_ips_on_a_local_subnet_are_scanned(monkeypatch):
    monkeypatch.setattr(arp_scan.network_interfaces, "list_interfaces", lambda: [
        NetworkInterface("en0", "192.168.1.5", "255.255.255.0", "192.168.1.0/24"),
    ])
    groups = arp_scan._by_interface(["192.168.1.9", "10.0.0.1", "192.168.1.5"])
    assert [(iface.name, wanted) for iface, wanted in groups] == [("en0", ["192.168.1.9"])]


def test_scan_gives_nothing_when_bpf_cannot_be_opened(monkeypatch):
    monkeypatch.setattr(arp_scan, "IS_WINDOWS", False)
    monkeypatch.setattr(arp_scan.network_interfaces, "list_interfaces", lambda: [
        NetworkInterface("en0", "192.168.1.5", "255.255.255.0", "192.168.1.0/24"),
    ])

    def denied(name):
        raise PermissionError("no access_bpf")
    monkeypatch.setattr(arp_scan, "_open", denied)
    assert arp_scan.scan(["192.168.1.9"]) == {}
