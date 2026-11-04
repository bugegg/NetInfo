"""The ping engine's ICMP socket: parsing replies and matching them to pings."""

import asyncio
import socket
import struct

from NetInfoView.ping import icmp


def _ip(payload, source="8.8.8.8"):
    return struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(payload), 0, 0, 57, 1, 0,
                       socket.inet_aton(source), socket.inet_aton("192.168.1.2")) + payload


def test_parse_reply_gives_the_identifier_of_replies_and_errors():
    reply = _ip(struct.pack("!BBHHH", icmp.ICMP_ECHO_REPLY, 0, 0, 0x4242, 7))
    assert icmp.parse_reply(reply) == (7, 0, 0, 57, 0x4242)
    probe = icmp.build_echo(0x1111, 9, 8)
    exceeded = _ip(struct.pack("!BBHI", 11, 0, 0, 0) + _ip(probe)[:28], "10.0.0.1")
    assert icmp.parse_reply(exceeded) == (9, 11, 0, 57, 0x1111)


class FakeSocket:
    def __init__(self, packets):
        self.packets = list(packets)

    def recvfrom(self, size):
        if not self.packets:
            raise BlockingIOError
        return self.packets.pop(0), ("8.8.8.8", 0)


def test_replies_to_another_pinger_are_not_taken_for_ours():
    async def run():
        pinger = icmp.IcmpPinger()
        loop = asyncio.get_running_loop()
        ours = loop.create_future()
        pinger._pending[5] = ours
        foreign = _ip(struct.pack("!BBHHH", 0, 0, 0, (pinger._ident + 1) & 0xFFFF, 5))
        pinger._socket = FakeSocket([foreign])
        pinger._on_readable()
        assert not ours.done()  # same sequence, someone else's identifier
        mine = _ip(struct.pack("!BBHHH", 0, 0, 0, pinger._ident, 5))
        pinger._socket = FakeSocket([mine])
        pinger._on_readable()
        assert ours.done() and ours.result()[0] == icmp.ICMP_ECHO_REPLY
        pinger._socket = None

    asyncio.run(run())
