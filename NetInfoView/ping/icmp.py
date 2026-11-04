"""ICMP echo over an unprivileged datagram socket.

macOS lets any user open ``SOCK_DGRAM``/``IPPROTO_ICMP``, so no root or setuid is
needed. Two details of that socket shape this module:

* The kernel hands back the **full IP header** with each reply (unlike Linux,
  which strips it), so the TTL of the reply is readable at IP offset 8.
* The echo identifier is **not** rewritten, so a single shared socket can demux
  replies for every host by sequence number.
* The default receive buffer is only ``net.inet.raw.recvspace`` (8 KB on macOS),
  which silently drops replies as soon as a few hundred pings are in flight, so
  :meth:`IcmpPinger.open` enlarges it.
"""

from __future__ import annotations

import asyncio
import os
import socket
import struct
import time

from .result import PingResult, PingStatus, status_for_icmp

ICMP_ECHO_REQUEST = 8
ICMP_ECHO_REPLY = 0

_ICMP_HEADER = struct.Struct("!BBHHH")  # type, code, checksum, id, sequence

#: macOS defines IP_DONTFRAG but Python does not always export it. It is rejected
#: with EINVAL on an unprivileged ICMP datagram socket; we probe for it at open
#: time and let the UI grey the option out.
_IP_DONTFRAG = getattr(socket, "IP_DONTFRAG", 67)

#: Receive/send buffer we ask for, large enough to hold the replies from a full
#: round of the default 500 concurrent pings without the kernel dropping any.
_WANTED_SOCKET_BUFFER = 1 << 20


def checksum(data: bytes) -> int:
    """The standard RFC 1071 one's-complement sum used by ICMP."""
    if len(data) % 2:
        data += b"\x00"
    total = sum(struct.unpack("!%dH" % (len(data) // 2), data))
    total = (total >> 16) + (total & 0xFFFF)
    total += total >> 16
    return ~total & 0xFFFF


def build_echo(ident: int, sequence: int, payload_size: int) -> bytes:
    """An ICMP echo request with ``payload_size`` bytes of filler."""
    payload = bytes((ord("a") + (i % 23)) for i in range(max(0, payload_size)))
    header = _ICMP_HEADER.pack(ICMP_ECHO_REQUEST, 0, 0, ident, sequence)
    return _ICMP_HEADER.pack(
        ICMP_ECHO_REQUEST, 0, checksum(header + payload), ident, sequence
    ) + payload


def _ip_header_length(data: bytes) -> int:
    """Length of a leading IPv4 header, or 0 if the buffer does not start with one."""
    if not data or data[0] >> 4 != 4:
        return 0
    length = (data[0] & 0x0F) * 4
    return length if 20 <= length <= len(data) else 0


def parse_reply(data: bytes) -> tuple[int, int, int, int | None, int] | None:
    """Pull ``(sequence, icmp_type, icmp_code, ttl, identifier)`` out of a
    received packet.

    Echo replies carry the sequence in their own header. Error reports (type 3,
    11, ...) instead quote the IP header and first 8 bytes of the datagram that
    provoked them, so the sequence is recovered from that embedded copy — this
    is what distinguishes a real "host unreachable" from a plain timeout.
    """
    offset = _ip_header_length(data)
    ttl = data[8] if offset else None
    if len(data) < offset + _ICMP_HEADER.size:
        return None
    icmp_type, icmp_code, _, ident, sequence = _ICMP_HEADER.unpack_from(data, offset)

    if icmp_type == ICMP_ECHO_REPLY:
        return sequence, icmp_type, icmp_code, ttl, ident

    # An error report: step over its 8-byte header into the quoted datagram.
    quoted = data[offset + _ICMP_HEADER.size :]
    inner_offset = _ip_header_length(quoted)
    if not inner_offset or len(quoted) < inner_offset + _ICMP_HEADER.size:
        return None
    _, _, _, inner_ident, inner_sequence = _ICMP_HEADER.unpack_from(quoted, inner_offset)
    return inner_sequence, icmp_type, icmp_code, ttl, inner_ident


class IcmpPinger:
    """Shares one ICMP socket across every concurrent ping."""

    def __init__(self, ttl: int = 64, dont_fragment: bool = False) -> None:
        self.ttl = ttl
        self.dont_fragment = dont_fragment
        #: False once the kernel has rejected IP_DONTFRAG, so the UI can grey it out.
        self.dont_fragment_supported = True
        self._socket: socket.socket | None = None
        self._loop: asyncio.AbstractEventLoop | None = None
        self._ident = os.getpid() & 0xFFFF
        self._sequence = 0
        self._pending: dict[int, asyncio.Future] = {}

    # -- lifecycle ---------------------------------------------------------

    def open(self) -> None:
        if self._socket is not None:
            return
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_ICMP)
        sock.setblocking(False)
        _enlarge_buffers(sock)
        self._socket = sock
        self._apply_socket_options()
        self._loop = asyncio.get_running_loop()
        self._loop.add_reader(sock.fileno(), self._on_readable)

    def close(self) -> None:
        if self._socket is None:
            return
        if self._loop is not None:
            self._loop.remove_reader(self._socket.fileno())
        self._socket.close()
        self._socket = None
        for future in self._pending.values():
            if not future.done():
                future.cancel()
        self._pending.clear()

    def _apply_socket_options(self) -> None:
        sock = self._socket
        if sock is None:
            return
        try:
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, self.ttl)
        except OSError:
            pass
        try:
            sock.setsockopt(socket.IPPROTO_IP, _IP_DONTFRAG, int(self.dont_fragment))
        except OSError:
            self.dont_fragment_supported = False

    def configure(self, ttl: int | None = None, dont_fragment: bool | None = None) -> None:
        """Change outgoing packet options on the live socket."""
        if ttl is not None:
            self.ttl = ttl
        if dont_fragment is not None:
            self.dont_fragment = dont_fragment
        self._apply_socket_options()

    # -- sending and receiving --------------------------------------------

    def _next_sequence(self) -> int:
        for _ in range(0x10000):
            self._sequence = (self._sequence + 1) & 0xFFFF
            if self._sequence not in self._pending:
                return self._sequence
        raise RuntimeError("no free ICMP sequence numbers")

    def _on_readable(self) -> None:
        sock = self._socket
        if sock is None:
            return
        while True:
            try:
                data, address = sock.recvfrom(2048)
            except (BlockingIOError, InterruptedError):
                return
            except OSError:
                return
            parsed = parse_reply(data)
            if parsed is None:
                continue
            sequence, icmp_type, icmp_code, ttl, ident = parsed
            # Every ICMP socket sees every reply: skip the ones to other
            # pingers (Net Path, /sbin/ping) that happen to share a sequence.
            if ident != self._ident:
                continue
            future = self._pending.get(sequence)
            if future is None or future.done():
                continue
            future.set_result((icmp_type, icmp_code, ttl, address[0]))

    async def ping(self, ip: str, timeout_ms: int, payload_size: int = 32) -> PingResult:
        """Send one echo request to ``ip`` and wait for its reply."""
        if self._socket is None:
            self.open()
        assert self._socket is not None and self._loop is not None

        sequence = self._next_sequence()
        future: asyncio.Future = self._loop.create_future()
        self._pending[sequence] = future
        packet = build_echo(self._ident, sequence, payload_size)

        started = time.perf_counter()
        try:
            try:
                self._socket.sendto(packet, (ip, 0))
            except OSError as exc:
                return PingResult(_status_for_send_error(exc))

            try:
                icmp_type, icmp_code, ttl, reply_ip = await asyncio.wait_for(
                    future, timeout_ms / 1000.0
                )
            except asyncio.TimeoutError:
                return PingResult(PingStatus.TIMEOUT)

            rtt_ms = (time.perf_counter() - started) * 1000.0
            if icmp_type == ICMP_ECHO_REPLY:
                return PingResult(PingStatus.SUCCEEDED, rtt_ms, reply_ip, ttl)
            return PingResult(status_for_icmp(icmp_type, icmp_code), None, reply_ip, ttl)
        finally:
            self._pending.pop(sequence, None)


def _enlarge_buffers(sock: socket.socket) -> None:
    """Raise the socket buffers, halving the request until the kernel accepts it."""
    for option in (socket.SO_RCVBUF, socket.SO_SNDBUF):
        size = _WANTED_SOCKET_BUFFER
        while size >= 32768:
            try:
                sock.setsockopt(socket.SOL_SOCKET, option, size)
                break
            except OSError:
                size //= 2


def _status_for_send_error(exc: OSError) -> PingStatus:
    import errno

    if exc.errno in (errno.ENETUNREACH, errno.ENETDOWN):
        return PingStatus.NET_UNREACHABLE
    if exc.errno in (errno.EHOSTUNREACH, errno.EHOSTDOWN):
        return PingStatus.HOST_UNREACHABLE
    if exc.errno in (errno.ENOBUFS, errno.EAGAIN):
        return PingStatus.NO_RESOURCES
    return PingStatus.GENERAL_FAILURE
