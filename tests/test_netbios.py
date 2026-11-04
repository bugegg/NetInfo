import socket
import struct
import threading

from NetInfoView.ping import netbios


def _response(query_id, names):
    """A node-status reply listing (name, suffix, flags) entries."""
    header = struct.pack("!HHHHHH", query_id, 0x8400, 0, 1, 0, 0)
    rr_name = netbios._encode_wildcard()
    body = bytes([len(names)]) + b"".join(
        name.encode("ascii").ljust(15) + bytes([suffix]) + struct.pack("!H", flags)
        for name, suffix, flags in names
    ) + b"\0" * 46  # adapter statistics
    return header + rr_name + struct.pack("!HHIH", netbios.TYPE_NBSTAT, 1, 0, len(body)) + body


def test_query_asks_for_node_status_of_the_wildcard_name():
    query = netbios.build_query(0x1234)
    assert query[:2] == b"\x12\x34"
    assert query[12] == 32 and query[13:15] == b"CK"  # "*" encodes as CK
    assert query[-4:] == struct.pack("!HH", netbios.TYPE_NBSTAT, 1)


def test_parse_picks_the_unique_workstation_name():
    reply = _response(7, [
        ("WORKGROUP", 0x00, 0x8400),  # group name: skipped
        ("PENS-SV01", 0x20, 0x0400),  # server service: skipped
        ("PENS-SV01", 0x00, 0x0400),
    ])
    assert netbios.parse_node_status(reply, 7) == "PENS-SV01"


def test_parse_rejects_someone_elses_reply():
    assert netbios.parse_node_status(_response(7, [("PC", 0x00, 0)]), 8) == ""


def test_lookup_against_a_local_fake_responder(monkeypatch):
    server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server.bind(("127.0.0.1", 0))
    monkeypatch.setattr(netbios, "NETBIOS_PORT", server.getsockname()[1])

    def answer():
        query, addr = server.recvfrom(512)
        query_id = struct.unpack("!H", query[:2])[0]
        server.sendto(_response(query_id, [("NAS01", 0x00, 0x0400)]), addr)

    thread = threading.Thread(target=answer, daemon=True)
    thread.start()
    try:
        assert netbios.lookup("127.0.0.1") == "NAS01"
    finally:
        thread.join(2)
        server.close()


def test_lookup_gives_up_quietly():
    assert netbios.lookup("127.0.0.1", timeout=0.2) == ""
    assert netbios.lookup("::1", timeout=0.2) == ""
