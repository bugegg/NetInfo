"""Tests for Check LLDP/CDP (ping/lldp_cdp.py and its window)."""

import os
import struct

import pytest
from PyQt6.QtWidgets import QApplication, QToolButton

from NetInfoView.ping import lldp_cdp
from NetInfoView.ping.lldp_cdp import Neighbor

MAC = bytes.fromhex("0011223344aa")


def _iface(name, port="", active=True):
    from NetInfoView.ping.network_interfaces import EthernetInterface

    return EthernetInterface(name, port, active)


@pytest.fixture(scope="session")
def qapp():
    yield QApplication.instance() or QApplication([])


def _tlv(kind, value):
    return struct.pack("!H", kind << 9 | len(value)) + value


def lldp_frame(port=b"Gi1/0/12", vlan=20):
    """What a Cisco Catalyst sends out of an access port."""
    lldpdu = b"".join([
        _tlv(1, b"\x04" + bytes.fromhex("a0b1c2d3e4f5")),  # chassis: MAC
        _tlv(2, b"\x05" + port),  # port: interface name
        _tlv(3, b"\x00\x78"),  # TTL 120
        _tlv(4, b"GigabitEthernet1/0/12"),
        _tlv(5, b"core-sw.example"),
        _tlv(6, b"Cisco IOS Software, C9300\nCopyright (c) Cisco"),
        _tlv(7, struct.pack("!HH", 0x0014, 0x0004)),  # supports bridge+router, bridge on
        _tlv(8, bytes([5, 1, 10, 0, 0, 2, 2, 0, 0, 0, 1, 0])),  # mgmt 10.0.0.2, ifIndex 1
        _tlv(127, b"\x00\x80\xc2\x01" + struct.pack("!H", vlan)),  # port VLAN ID
        _tlv(0, b""),
    ])
    return bytes.fromhex("0180c200000e") + MAC + b"\x88\xcc" + lldpdu


def _cdp_tlv(kind, value):
    return struct.pack("!HH", kind, len(value) + 4) + value


def cdp_frame():
    address = struct.pack("!I", 1) + bytes([1, 1, 0xCC]) + struct.pack("!H", 4) + bytes([10, 0, 0, 3])
    cdp = bytes([2, 180, 0, 0]) + b"".join([
        _cdp_tlv(0x01, b"access-sw1"),
        _cdp_tlv(0x02, address),
        _cdp_tlv(0x03, b"FastEthernet0/7"),
        _cdp_tlv(0x04, struct.pack("!I", 0x28)),  # switch, IGMP
        _cdp_tlv(0x05, b"Cisco IOS Software, C2960 Version 15.2"),
        _cdp_tlv(0x06, b"cisco WS-C2960-24TT-L"),
        _cdp_tlv(0x0A, struct.pack("!H", 30)),
    ])
    body = bytes.fromhex("aaaa0300000c2000") + cdp
    return lldp_cdp.CDP_MULTICAST + MAC + struct.pack("!H", len(body)) + body


def test_parse_lldp_frame():
    assert lldp_cdp.parse_frame(lldp_frame(), "en7") == Neighbor(
        interface="en7", protocol="LLDP", name="core-sw.example", port="Gi1/0/12",
        port_description="GigabitEthernet1/0/12", vlan="20", address="10.0.0.2",
        platform="Cisco IOS Software, C9300", capabilities="Bridge",
        chassis_id="a0:b1:c2:d3:e4:f5",
        description="Cisco IOS Software, C9300\nCopyright (c) Cisco",
        management=["IPv4 10.0.0.2"],
        details=[("Capabilities Supported", "Bridge, Router"), ("TTL", "120 s")],
    )


def _hpe_frame():
    """A real announcement from an HPE OfficeConnect 1950 (Comware 7)."""
    path = os.path.join(os.path.dirname(__file__), "fixtures", "lldp_hpe_1950.hex")
    with open(path) as f:
        return bytes.fromhex(f.read().strip())


def test_parse_every_tlv_of_a_real_hpe_switch():
    n = lldp_cdp.parse_frame(_hpe_frame(), "en10")
    assert (n.name, n.port, n.port_id, n.vlan) == (
        "AD-ACC-02", "GigabitEthernet1/0/25 Interface", "dc:68:0c:70:ad:71", "19",
    )
    # It advertises a MAC as its management address, no IP.
    assert n.address == "" and n.management == ["MAC dc:68:0c:70:ad:71"]
    assert n.macs == ["dc:68:0c:70:ad:30", "dc:68:0c:70:ad:71"]
    assert n.capabilities == "Bridge, Router, C-VLAN"
    assert dict(n.details) == {
        "Capabilities Supported": "Bridge, Router, C-VLAN, S-VLAN",
        "TTL": "121 s",
        "Link Aggregation": "capable, not aggregated",
        "Link": "1000BASE-T full duplex, auto-negotiation on",
        "PoE": "PSE (switch supplies power), not supported",
        "Max Frame Size": "9216 bytes",
        "MED Device Type": "Network Connectivity",
        "Hardware Revision": "Ver.D",
        "Firmware Revision": "145",
        "Software Revision": "7.1.045 Release 3113P05",
        "Serial Number": "CN11GQT0B3",
        "Manufacturer": "HPE",
        "Model": "JG961A",
        "Asset ID": "Unknown",
    }


def test_more_extension_tlvs():
    org = lambda oui, sub, value: _tlv(127, bytes.fromhex(oui) + bytes([sub]) + value)
    lldpdu = b"".join([
        _tlv(1, b"\x07sw"), _tlv(2, b"\x07" + b"1"),
        _tlv(8, bytes([17, 2]) + bytes(15) + b"\x01" + bytes(6)),  # IPv6 ::1
        org("0080c2", 3, b"\x00\x13\x05staff"),  # VLAN name
        org("00120f", 2, b"\x07\x01\x01"),  # PoE PSE, supported, enabled
        org("0012bb", 2, bytes([1]) + (0x400000 | 100 << 9 | 5 << 6 | 46).to_bytes(3, "big")),
        org("0012bb", 4, b"\x51\x00\x9b"),  # 15.5 W
        org("00e02b", 1, b"\xab"),  # some vendor's own
        _tlv(0, b""),
    ])
    n = lldp_cdp.parse_lldp(lldpdu)
    assert n.management == ["IPv6 ::1"]
    assert n.details == [
        ("VLAN Name", "19 staff"),
        ("PoE", "PSE (switch supplies power), enabled"),
        ("Network Policy", "Voice: VLAN 100 tagged, priority 5, DSCP 46"),
        ("PoE Power", "15.5 W"),
        ("TLV 00:e0:2b/1", "ab"),
    ]


def test_an_ip_is_looked_up_in_arp_when_not_advertised(qapp, monkeypatch):
    from NetInfoView.ui import lldp_cdp_window
    from NetInfoView.ui.lldp_cdp_window import format_neighbor

    n = lldp_cdp.parse_frame(_hpe_frame(), "en10")
    assert "  IP Address:             not advertised, and not found in the ARP table\n" in (
        format_neighbor(n, "en10")
    )
    asked = []
    monkeypatch.setattr(lldp_cdp_window.arp, "find_ip", lambda macs: asked.append(macs) or "172.16.5.2")
    thread = lldp_cdp_window.LldpCdpThread(["en10"], 1)
    heard = []
    thread.neighbor_found.connect(heard.append)
    thread._on_neighbor(n)
    assert asked == [["dc:68:0c:70:ad:30", "dc:68:0c:70:ad:71"]]
    assert heard == [n] and (n.address, n.address_source) == ("172.16.5.2", "ARP")
    text = format_neighbor(n, "en10")
    assert "  IP Address:             172.16.5.2 (from ARP)\n" in text
    assert "  Management:             MAC dc:68:0c:70:ad:71\n" in text
    assert "  Serial Number:          CN11GQT0B3\n" in text

    advertised = lldp_cdp.parse_frame(lldp_frame(), "en7")
    thread._on_neighbor(advertised)  # has an IP of its own: no lookup
    assert len(asked) == 1 and advertised.address_source == ""


def test_find_ip_from_the_arp_table(monkeypatch):
    from NetInfoView.ping import arp

    monkeypatch.setattr(arp, "_load_table", lambda: {
        "172.16.19.1": "B8:38:61:03:6E:FF", "172.16.19.2": "DC:68:0C:70:AD:30",
    })
    assert arp.find_ip(["dc:68:0c:70:ad:71", "dc:68:0c:70:ad:30"]) == "172.16.19.2"
    assert arp.find_ip(["00:11:22:33:44:55"]) == "" and arp.find_ip([]) == ""


def test_parse_cdp_frame():
    assert lldp_cdp.parse_frame(cdp_frame(), "en7") == Neighbor(
        interface="en7", protocol="CDP", name="access-sw1", port="FastEthernet0/7",
        vlan="30", address="10.0.0.3", platform="cisco WS-C2960-24TT-L",
        capabilities="Switch, IGMP", description="Cisco IOS Software, C2960 Version 15.2",
    )


def test_a_mac_port_id_is_shown_by_its_description():
    """HPE Comware sends the port's MAC as its ID; the description names it."""
    lldpdu = b"".join([
        _tlv(1, b"\x04" + bytes.fromhex("dc680c703c00")),
        _tlv(2, b"\x03" + bytes.fromhex("dc680c703cf2")),
        _tlv(4, b"GigabitEthernet1/0/24 Interface"),
        _tlv(5, b"AD-ACC-03"),
        _tlv(0, b""),
    ])
    n = lldp_cdp.parse_lldp(lldpdu, "en10")
    assert (n.port, n.port_id) == ("GigabitEthernet1/0/24 Interface", "dc:68:0c:70:3c:f2")
    n = lldp_cdp.parse_lldp(lldpdu.replace(_tlv(4, b"GigabitEthernet1/0/24 Interface"), b""))
    assert (n.port, n.port_id) == ("dc:68:0c:70:3c:f2", "")


def test_lldp_ids_and_minimal_frames():
    lldpdu = _tlv(1, b"\x05\x01" + bytes([192, 168, 1, 1])) + _tlv(2, b"\x03" + MAC) + _tlv(0, b"")
    n = lldp_cdp.parse_lldp(lldpdu)
    assert (n.chassis_id, n.name, n.port) == ("192.168.1.1", "192.168.1.1", "00:11:22:33:44:aa")
    assert lldp_cdp.parse_lldp(_tlv(3, b"\x00\x78")) is None  # no IDs
    assert lldp_cdp.parse_lldp(lldp_frame()[14:40]) is not None  # truncated: keeps what it has


def test_other_and_broken_frames_are_ignored():
    arp = b"\xff" * 6 + MAC + b"\x08\x06" + bytes(28)
    assert lldp_cdp.parse_frame(arp) is None
    assert lldp_cdp.parse_frame(b"\x01") is None
    frame = cdp_frame()
    assert lldp_cdp.parse_frame(frame[:30]) is None  # cut before the device ID
    tagged = frame[:12] + b"\x81\x00\x00\x14" + lldp_frame()[12:]
    assert lldp_cdp.parse_frame(tagged).protocol == "LLDP"


def _run_filter(frame):
    """Run the classic BPF program the kernel gets, on one frame."""
    pc = 0
    acc = 0
    while True:
        code, jt, jf, k = lldp_cdp._FILTER[pc]
        if code == 0x28:
            acc = int.from_bytes(frame[k:k + 2], "big")
        elif code == 0x20:
            acc = int.from_bytes(frame[k:k + 4], "big")
        elif code == 0x15:
            pc += jt if acc == k else jf
        elif code == 0x06:
            return k
        pc += 1


def test_kernel_filter_passes_only_lldp_and_cdp():
    assert _run_filter(lldp_frame()) > 0
    assert _run_filter(cdp_frame()) > 0
    assert _run_filter(b"\xff" * 6 + MAC + b"\x08\x00" + bytes(20)) == 0
    assert _run_filter(bytes.fromhex("01000ccccccd") + MAC + b"\x00\x40" + bytes(20)) == 0


def _bpf_record(frame):
    header = struct.pack("<iiIIH", 0, 0, len(frame), len(frame), 18)
    record = header + frame
    return record + bytes(-len(record) % 4)


def test_split_bpf_buffer():
    frames = [lldp_frame(), cdp_frame(), b"x"]
    assert lldp_cdp.split_bpf_buffer(b"".join(map(_bpf_record, frames))) == frames
    assert lldp_cdp.split_bpf_buffer(b"") == []


def test_listen_reports_each_switch_port_once(monkeypatch):
    read_end, write_end = os.pipe()
    os.write(write_end, b"".join(map(_bpf_record, [lldp_frame(), lldp_frame(), cdp_frame()])))
    os.write(write_end, _bpf_record(lldp_frame(port=b"Gi1/0/13")))

    def fake_open(interface):
        if interface == "en0":
            raise lldp_cdp.CaptureError("no permission")
        return read_end

    monkeypatch.setattr(lldp_cdp, "open_bpf", fake_open)
    heard, errors = [], []
    lldp_cdp.listen(["en0", "en7"], heard.append, seconds=0.3,
                    on_error=lambda i, m: errors.append((i, m)))
    os.close(write_end)
    assert [(n.interface, n.protocol, n.port) for n in heard] == [
        ("en7", "LLDP", "Gi1/0/12"), ("en7", "CDP", "FastEthernet0/7"),
        ("en7", "LLDP", "Gi1/0/13"),
    ]
    assert errors == [("en0", "no permission")]


def test_listen_stops_when_asked(monkeypatch):
    read_end, write_end = os.pipe()
    monkeypatch.setattr(lldp_cdp, "open_bpf", lambda interface: read_end)
    lldp_cdp.listen(["en7"], lambda n: None, seconds=60, stopped=lambda: True)
    os.close(write_end)


def test_window_checks_the_chosen_interface(qapp, monkeypatch):
    from NetInfoView.ui import lldp_cdp_window

    started = []
    monkeypatch.setattr(lldp_cdp_window, "ethernet_interfaces",
                        lambda: [_iface("en7", "USB 10/100/1000 LAN"), _iface("en0", "Wi-Fi")])
    monkeypatch.setattr(lldp_cdp_window.LldpCdpThread, "start", lambda self: started.append(self))
    window = lldp_cdp_window.LldpCdpWindow()
    assert not window.running and started == []  # waits for a choice
    assert [window.interface.itemText(i) for i in range(2)] == [
        "en7 (USB 10/100/1000 LAN)", "en0 (Wi-Fi)",
    ]
    assert window.button.text() == "Check" and window.button.isEnabled()
    window.interface.setCurrentIndex(1)
    window.refresh_interfaces()  # keeps the choice
    assert window.interface.currentData() == "en0"
    window.interface.setCurrentIndex(0)

    window.button.click()
    assert window.running and len(started) == 1
    assert started[0]._interfaces == ["en7"]
    assert not window.interface.isEnabled() and window.button.text() == "Stop"
    assert "Listening..." in window.lldp_label.text()
    window.start()  # already listening: no second capture
    assert len(started) == 1

    assert window.text.isReadOnly() and window.text.toPlainText() == ""
    window.add_neighbor(lldp_cdp.parse_frame(lldp_frame(), "en7"))
    assert "Received \u2014 core-sw.example port Gi1/0/12" in window.lldp_label.text()
    assert "Listening..." in window.cdp_label.text()
    assert window.text.toPlainText() == (
        "LLDP on en7 (USB 10/100/1000 LAN)\n"
        "  Switch:                 core-sw.example\n"
        "  Switch Port:            Gi1/0/12\n"
        "  Port Description:       GigabitEthernet1/0/12\n"
        "  VLAN:                   20\n"
        "  IP Address:             10.0.0.2\n"
        "  Platform:               Cisco IOS Software, C9300\n"
        "  Capabilities:           Bridge\n"
        "  Chassis ID:             a0:b1:c2:d3:e4:f5\n"
        "  Capabilities Supported: Bridge, Router\n"
        "  TTL:                    120 s\n"
        "  Description:            Copyright (c) Cisco"
    )
    window.add_neighbor(lldp_cdp.parse_frame(cdp_frame(), "en7"))
    assert window.text.toPlainText().count("\n\nCDP on en7 (USB 10/100/1000 LAN)\n") == 1

    window._elapsed = 65
    window._on_finished()
    assert not window.running and window.button.text() == "Check Again"
    assert window.interface.isEnabled()
    assert window.status.text() == "2 announcement(s) heard"
    window.close()


def test_interfaces_without_link_are_hidden(qapp, monkeypatch):
    from NetInfoView.ui import lldp_cdp_window

    links = {"en10": False}
    monkeypatch.setattr(lldp_cdp_window, "ethernet_interfaces", lambda: [
        _iface("en0", "Wi-Fi"), _iface("en10", "USB 10/100/1000 LAN", links["en10"]),
        _iface("en1", "Thunderbolt 1", False),
    ])
    monkeypatch.setattr(lldp_cdp_window.LldpCdpThread, "start", lambda self: None)
    window = lldp_cdp_window.LldpCdpWindow()
    assert [window.interface.itemText(i) for i in range(window.interface.count())] == [
        "en0 (Wi-Fi)",
    ]
    links["en10"] = True  # cable plugged in
    window.refresh_interfaces()
    assert window.interface.count() == 2
    window.interface.setCurrentIndex(1)
    links["en10"] = False  # and pulled out again before Check
    window.start()  # Check re-reads the list and falls back to what's up
    assert window.running and window._label == "en0 (Wi-Fi)"
    window._on_finished()
    window.close()


def test_ethernet_interfaces_order(monkeypatch):
    from NetInfoView.ping import network_interfaces as ni

    ifconfig = "".join(
        f"{name}: flags=8863<UP> mtu 1500\n\tstatus: {state}\n"
        for name, state in [("en0", "active"), ("en1", "inactive"), ("en4", "inactive"),
                            ("en10", "inactive"), ("en11", "active"), ("awdl0", "active")]
    )
    monkeypatch.setattr(ni.subprocess, "run", lambda *a, **k: type("R", (), {"stdout": ifconfig})())
    monkeypatch.setattr(ni, "hardware_ports", lambda: {
        "en0": "Wi-Fi", "en1": "Thunderbolt 1", "en4": "Ethernet Adapter (en4)",
        "en10": "USB 10/100/1000 LAN", "en11": "Thunderbolt Ethernet Slot 0",
    })
    assert [i.label for i in ni.ethernet_interfaces()] == [
        "en11 (Thunderbolt Ethernet Slot 0)", "en0 (Wi-Fi)",
        "en10 (USB 10/100/1000 LAN)", "en1 (Thunderbolt 1)", "en4 (Ethernet Adapter (en4))",
    ]
    assert [i.active for i in ni.ethernet_interfaces()] == [True, True, False, False, False]


def test_window_without_an_active_port(qapp, monkeypatch):
    from NetInfoView.ui import lldp_cdp_window

    monkeypatch.setattr(lldp_cdp_window, "ethernet_interfaces", lambda: [])
    monkeypatch.setattr(lldp_cdp_window, "capture_unavailable", lambda: "")
    window = lldp_cdp_window.LldpCdpWindow()
    assert not window.running and window.interface.count() == 0
    assert not window.button.isEnabled()
    window.start()
    assert not window.running
    assert "No active interface" in window.status.text()
    window.close()


def test_button_opens_the_interface_picker(qapp, tmp_path, monkeypatch):
    from NetInfoView.settings import Settings
    from NetInfoView.ui import lldp_cdp_window
    from NetInfoView.ui.main_window import MainWindow

    monkeypatch.setattr(
        "NetInfoView.fileio.vendor_db.default_db_path", lambda: tmp_path / "v.sqlite"
    )
    monkeypatch.setattr(lldp_cdp_window, "ethernet_interfaces", lambda: [_iface("en7")])
    win = MainWindow(Settings())
    try:
        assert win.action_lldp_cdp in win._table.actions()
        discovery = next(
            b for b in win._dashboard.findChildren(QToolButton) if b.text() == "Discovery"
        )
        assert win.action_lldp_cdp in discovery.menu().actions()
        window = win.check_lldp_cdp()  # no host selected: fine
        assert window.isVisible() and not window.running
        assert window.interface.currentData() == "en7"
        monkeypatch.setattr(lldp_cdp_window, "ethernet_interfaces",
                            lambda: [_iface("en7"), _iface("en10")])
        assert win.check_lldp_cdp() is window  # same window, list refreshed
        assert window.interface.count() == 2
        window.close()
    finally:
        win.close()


def test_lldp_window_says_when_npcap_is_missing(qapp, monkeypatch):
    from NetInfoView.ping import npcap
    from NetInfoView.ui import lldp_cdp_window

    monkeypatch.setattr(lldp_cdp_window, "ethernet_interfaces", lambda: [])
    monkeypatch.setattr(lldp_cdp_window, "capture_unavailable", lambda: npcap.NOT_INSTALLED)
    window = lldp_cdp_window.LldpCdpWindow()
    assert not window.button.isEnabled()
    assert "npcap.com" in window.status.text()
    window.close()
