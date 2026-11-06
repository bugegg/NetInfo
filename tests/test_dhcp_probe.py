"""DHCP server probe (ping/dhcp_probe.py) and its use for UDP 67."""

import struct

from NetInfoView.ping import dhcp_probe, port_scanner


def _reply(xid, options):
    request = dhcp_probe.build_inform(xid, "192.168.1.105")
    return bytes([2]) + request[1:dhcp_probe._HEADER.size] + dhcp_probe.MAGIC_COOKIE + options


def test_inform_is_a_relayed_request():
    packet = dhcp_probe.build_inform(0x12345678, "192.168.1.105")
    assert packet[0] == 1 and packet[3] == 1  # BOOTREQUEST, one hop
    assert struct.unpack_from("!I", packet, 4)[0] == 0x12345678
    assert packet[12:16] == bytes([192, 168, 1, 105])  # ciaddr
    assert packet[24:28] == bytes([192, 168, 1, 105])  # giaddr: answer comes to our 67
    assert packet[236:240] == dhcp_probe.MAGIC_COOKIE
    assert packet[240:243] == bytes([53, 1, 8])  # DHCPINFORM


def test_parse_and_describe_an_ack():
    reply = _reply(7, bytes([53, 1, 5, 54, 4, 192, 168, 1, 1, 0, 3, 4, 192, 168, 1, 1, 255]))
    options = dhcp_probe.parse_reply(reply, 7)
    assert options[53] == b"\x05" and options[3] == bytes([192, 168, 1, 1])
    assert dhcp_probe.describe(options) == "DHCP ACK · server 192.168.1.1"
    assert dhcp_probe.parse_reply(reply, 8) is None  # someone else's transaction
    assert dhcp_probe.parse_reply(dhcp_probe.build_inform(7, "10.0.0.1"), 7) is None  # a request


def test_udp_67_uses_the_dhcp_probe(monkeypatch):
    monkeypatch.setattr(dhcp_probe, "ask", lambda ip, timeout: {53: b"\x05"})
    result = port_scanner.probe_udp("192.0.2.1", 67)
    assert result.state == "open" and result.banner == "DHCP ACK"


def test_udp_67_falls_back_to_a_plain_probe(monkeypatch):
    monkeypatch.setattr(dhcp_probe, "ask", lambda ip, timeout: None)
    # Nothing on 127.0.0.1:67 (ask never got a reply), so it's refused.
    assert port_scanner.probe_udp("127.0.0.1", 67, timeout=0.4).state == "closed"
