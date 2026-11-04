"""Tests for the direct-to-server PTR lookup (ping/dns_ptr.py)."""

import socket
import struct
import threading

from NetInfoView.ping import dns_ptr


def _reply(query: bytes, name: str | None, rcode: int = 0) -> bytes:
    """A server's answer to `query`: the question echoed back, then one PTR
    answer whose owner is a compression pointer to that question."""
    query_id = query[:2]
    question = query[12:]
    answers = 0 if name is None else 1
    header = query_id + struct.pack("!HHHHH", 0x8180 | rcode, 1, answers, 0, 0)
    body = question
    if name is not None:
        rdata = b"".join(bytes([len(p)]) + p.encode() for p in name.split(".")) + b"\0"
        body += b"\xc0\x0c" + struct.pack("!HHIH", 12, 1, 300, len(rdata)) + rdata
    return header + body


def test_reverse_name():
    assert dns_ptr.reverse_name("192.168.1.5") == "5.1.168.192.in-addr.arpa"


def test_parses_a_ptr_answer_with_name_compression():
    query = dns_ptr.build_query("5.1.168.192.in-addr.arpa", 0x1234)
    assert dns_ptr.parse_ptr_answer(_reply(query, "pc1.corp.local"), 0x1234) == "pc1.corp.local"


def test_nxdomain_or_someone_elses_reply_gives_nothing():
    query = dns_ptr.build_query("5.1.168.192.in-addr.arpa", 0x1234)
    assert dns_ptr.parse_ptr_answer(_reply(query, None, rcode=3), 0x1234) == ""
    assert dns_ptr.parse_ptr_answer(_reply(query, "x.local"), 0x9999) == ""


def test_query_ptr_against_a_local_fake_server():
    server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server.bind(("127.0.0.1", 0))
    port = server.getsockname()[1]

    def answer():
        query, client = server.recvfrom(512)
        server.sendto(_reply(query, "nas.home.arpa"), client)

    threading.Thread(target=answer, daemon=True).start()
    original = dns_ptr.DNS_PORT
    dns_ptr.DNS_PORT = port
    try:
        assert dns_ptr.query_ptr("192.168.1.20", "127.0.0.1") == "nas.home.arpa"
    finally:
        dns_ptr.DNS_PORT = original
        server.close()


def test_query_ptr_gives_up_quietly():
    assert dns_ptr.query_ptr("192.168.1.20", "not-an-ip") == ""
    assert dns_ptr.query_ptr("192.168.1.20", "127.0.0.1", timeout=0.2) == ""


SCUTIL = """DNS configuration

resolver #1
  search domain[0] : corp.local
  nameserver[0] : 172.16.10.1
  nameserver[1] : 8.8.8.8

resolver #2
  domain   : local
  options  : mdns

resolver #3
  domain   : corp.local
  nameserver[0] : 172.16.10.1

DNS configuration (for scoped queries)

resolver #1
  nameserver[0] : 192.168.1.1
"""


def test_system_nameservers_come_from_the_main_scutil_section():
    assert dns_ptr.parse_scutil_nameservers(SCUTIL) == ["172.16.10.1", "8.8.8.8"]


def test_lookup_tries_each_server_until_one_has_a_name(monkeypatch):
    asked = []

    def query(ip, server):
        asked.append(server)
        return "pc1.corp.local" if server == "10.0.0.2" else ""

    monkeypatch.setattr(dns_ptr, "query_ptr", query)
    assert dns_ptr.lookup("10.0.0.5", ["10.0.0.1", "10.0.0.2", "10.0.0.3"]) == "pc1.corp.local"
    assert asked == ["10.0.0.1", "10.0.0.2"]
