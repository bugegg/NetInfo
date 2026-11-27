"""Test SNMP (ping/snmp_test.py and its window, ui/snmp_test_window.py)."""

import socket
import threading

import pytest

from NetInfoView.ping import ber, snmp_test
from NetInfoView.ping.snmp_arp import decode_oid, encode_oid
from NetInfoView.ui import snmp_test_window
from test_main_window import window, qapp, _entries_with_statuses  # noqa: F401

SYSTEM = {
    (1, 3, 6, 1, 2, 1, 1, 1, 0): (ber.OCTET_STRING, b"HPE Comware Platform Software\r\nV1910"),
    (1, 3, 6, 1, 2, 1, 1, 2, 0): (ber.OID, encode_oid((1, 3, 6, 1, 4, 1, 25506, 11, 1, 90))),
    (1, 3, 6, 1, 2, 1, 1, 3, 0): (0x43, (100 * (2 * 86400 + 3 * 3600 + 4 * 60 + 5)).to_bytes(4, "big")),
    (1, 3, 6, 1, 2, 1, 1, 4, 0): (ber.OCTET_STRING, b"noc@example.com"),
    (1, 3, 6, 1, 2, 1, 1, 5, 0): (ber.OCTET_STRING, b"FTM-ACC-01"),
    (1, 3, 6, 1, 2, 1, 1, 6, 0): (ber.OCTET_STRING, b"Floor 3"),
}


@pytest.fixture
def agent():
    """A fake SNMP agent on localhost answering GETs for SYSTEM, only to
    community "s3cret" and only in the versions in `versions`."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("127.0.0.1", 0))
    state = {"versions": {0, 1}, "seen": [], "mib": dict(SYSTEM)}

    def serve():
        while True:
            try:
                message, peer = sock.recvfrom(65535)
            except OSError:
                return
            _, start, end = ber.read(message)
            (_, v_start, v_end), (_, c_start, c_end), (pdu_tag, pdu_start, pdu_end) = list(
                ber.children(message, start, end))
            version = ber.decode_int(message, v_start, v_end)
            state["seen"].append(version)
            if message[c_start:c_end] != b"s3cret" or version not in state["versions"]:
                continue  # agents stay silent
            (_, id_start, id_end), _, _, (_, b_start, b_end) = list(
                ber.children(message, pdu_start, pdu_end))
            request_id = ber.decode_int(message, id_start, id_end)
            binds = b""
            for _, bind_start, bind_end in ber.children(message, b_start, b_end):
                (_, o_start, o_end), _ = ber.children(message, bind_start, bind_end)
                oid = decode_oid(message[o_start:o_end])
                if pdu_tag == 0xA1:  # GETNEXT: the first OID after it
                    oid = next((o for o in sorted(state["mib"]) if o > oid), oid)
                tag, value = state["mib"].get(oid, (0x80 if pdu_tag == 0xA0 else 0x82, b""))
                binds += ber.encode(ber.SEQUENCE, ber.encode(ber.OID, encode_oid(oid)) + ber.encode(tag, value))
            pdu = ber.encode(0xA2, ber.encode_int(request_id) + ber.encode_int(0) + ber.encode_int(0)
                             + ber.encode(ber.SEQUENCE, binds))
            sock.sendto(ber.encode(ber.SEQUENCE, ber.encode_int(version)
                                   + ber.encode(ber.OCTET_STRING, b"s3cret") + pdu), peer)

    threading.Thread(target=serve, daemon=True).start()
    state["port"] = sock.getsockname()[1]
    yield state
    sock.close()


def test_reads_the_system_group(agent):
    result = snmp_test.query_system("127.0.0.1", "s3cret", port=agent["port"], timeout=0.5)
    assert result.ok and result.version == snmp_test.VERSION_2C
    values = dict(result.values)
    assert values["Name"] == "FTM-ACC-01"
    assert values["Object ID"] == "1.3.6.1.4.1.25506.11.1.90"
    assert values["Uptime"] == "2 days, 03:04:05"
    assert values["Location"] == "Floor 3"
    text = snmp_test.format_result(result)
    assert "answered SNMPv2c" in text
    assert "V1910" in text  # every line of a multi-line description


def test_auto_falls_back_to_v1(agent):
    agent["versions"] = {0}
    result = snmp_test.query_system("127.0.0.1", "s3cret", port=agent["port"], timeout=0.3)
    assert result.ok and result.version == snmp_test.VERSION_1
    assert agent["seen"][0] == snmp_test.VERSION_2C


def test_wrong_community_gets_no_answer(agent):
    result = snmp_test.query_system("127.0.0.1", "public", port=agent["port"], timeout=0.2)
    assert not result.ok
    assert "community is wrong" in result.error
    assert 'tried SNMP v2c and v1' in snmp_test.format_result(result)


def test_value_formats():
    assert snmp_test.format_uptime(100 * 59) == "00:00:59"
    assert snmp_test.format_uptime(100 * 86400) == "1 day, 00:00:00"
    assert snmp_test.format_value(0x40, bytes([10, 0, 0, 1])) == "10.0.0.1"
    assert snmp_test.format_value(ber.OCTET_STRING, b"\x00\x1a\x2b") == "00:1a:2b"
    assert snmp_test.format_value(0x81, b"") == "(no such instance)"


def test_menu_opens_test_snmp_for_the_selected_host(window, monkeypatch):
    started = []
    monkeypatch.setattr(snmp_test_window.SnmpTestWindow, "start", lambda self: started.append(self))
    entries = _entries_with_statuses(window, "10.0.0.7")
    entries[0].ip_address = "10.0.0.7"
    window._table.selectRow(0)
    window.settings.snmp_community = "s3cret"

    window.action_snmp_test.trigger()
    test_window = started[0]
    assert test_window.host.text() == "10.0.0.7"
    assert test_window.community.text() == "s3cret"
    assert window.action_snmp_test in window._table.actions()
    test_window.close()


def test_use_this_community_saves_it(window, monkeypatch):
    saved = []
    monkeypatch.setattr(window.settings, "save", lambda: saved.append(True))
    test_window = window.test_snmp()
    test_window.community.setText("s3cret")
    test_window._show(snmp_test.SnmpResult(ip="10.0.0.7", community="s3cret", ok=True))
    assert not test_window.save_button.isHidden()
    test_window.save_button.click()
    assert window.settings.snmp_community == "s3cret" and saved
    test_window.close()


ENT = (1, 3, 6, 1, 2, 1, 47, 1, 1, 1, 1)


def test_serial_and_model_from_entity_mib(agent):
    agent["mib"].update({
        ENT + (11, 1): (ber.OCTET_STRING, b""),  # a part with no serial is skipped
        ENT + (11, 2): (ber.OCTET_STRING, b"FOC1234X0AB"),
        ENT + (13, 2): (ber.OCTET_STRING, b"WS-C2960X-24TS-L"),
    })
    result = snmp_test.query_system("127.0.0.1", "s3cret", port=agent["port"], timeout=0.5)
    values = dict(result.values)
    assert values["Serial"] == "FOC1234X0AB" and values["Model"] == "WS-C2960X-24TS-L"
    assert "Serial:" in snmp_test.format_result(result)


def test_serial_from_a_vendor_mib(agent):
    agent["mib"][(1, 3, 6, 1, 4, 1, 14988, 1, 1, 7, 3, 0)] = (ber.OCTET_STRING, b"HD3088ABC12")
    agent["mib"][(1, 3, 6, 1, 4, 1, 14988, 1, 1, 7, 8, 0)] = (ber.OCTET_STRING, b"RB5009UG+S+")
    values = dict(snmp_test.query_system("127.0.0.1", "s3cret", port=agent["port"],
                                         timeout=0.5).values)
    assert values["Serial"] == "HD3088ABC12" and values["Model"] == "RB5009UG+S+"


def test_no_serial_says_so(agent):
    values = dict(snmp_test.query_system("127.0.0.1", "s3cret", port=agent["port"],
                                         timeout=0.5).values)
    assert values["Serial"] == snmp_test.NO_SERIAL and "Model" not in values


def test_lookup_serial_for_the_grid(agent):
    agent["mib"][ENT + (11, 1)] = (ber.OCTET_STRING, b"SN-001")
    assert snmp_test.lookup_serial("127.0.0.1", ["public", "s3cret"], 0.3,
                                   agent["port"]) == ("SN-001", "")
    assert snmp_test.lookup_serial("127.0.0.1", ["public"], 0.2, agent["port"]) is None


def test_device_sweep_fills_serial(monkeypatch):
    from NetInfoView.ping import device_info
    monkeypatch.setattr(device_info.arp, "lookup", lambda ip: "00:11:22:33:44:55")
    monkeypatch.setattr(device_info, "lookup_serial",
                        lambda ip, communities: ("SN-9", "Model-X") if ip == "10.0.0.1" else None)

    class Vendors:
        def lookup(self, mac):
            return "Acme"
    jobs = [device_info.DeviceInfoJob(key=1, ip="10.0.0.1", needs_serial=True),
            device_info.DeviceInfoJob(key=2, ip="10.0.0.2", needs_serial=True)]
    results = {r.key: r for r in device_info.resolve_batch(jobs, Vendors())}
    assert (results[1].serial, results[1].model, results[1].serial_looked_up) == (
        "SN-9", "Model-X", True)
    assert not results[2].serial_looked_up  # no SNMP: asked again next sweep


def test_a_stack_gives_every_members_serial(agent):
    agent["mib"].update({
        ENT + (5, 1): (ber.INTEGER, b"\x0b"),  # stack(11)
        ENT + (5, 1000): (ber.INTEGER, b"\x03"),  # chassis: switch 1
        ENT + (5, 1001): (ber.INTEGER, b"\x09"),  # module
        ENT + (5, 2000): (ber.INTEGER, b"\x03"),  # chassis: switch 2
        ENT + (11, 1000): (ber.OCTET_STRING, b"JAE1111AAAA"),
        ENT + (11, 1001): (ber.OCTET_STRING, b"MOD-SN"),
        ENT + (11, 2000): (ber.OCTET_STRING, b"JAE2222BBBB"),
        ENT + (13, 1000): (ber.OCTET_STRING, b"C9200L-24T-4X"),
        ENT + (13, 2000): (ber.OCTET_STRING, b"C9200L-24T-4X"),
    })
    values = dict(snmp_test.query_system("127.0.0.1", "s3cret", port=agent["port"],
                                         timeout=0.5).values)
    assert values["Serial"] == "JAE1111AAAA, JAE2222BBBB"
    assert values["Model"] == "C9200L-24T-4X"
