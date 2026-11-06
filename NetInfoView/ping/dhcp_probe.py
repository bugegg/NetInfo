"""Is there a DHCP server on UDP 67? Ask it as a relay agent would.

A DHCP server never answers the port a request came from: it replies to a
client on UDP 68, or to a relay agent on UDP 67, and an empty datagram gets
nothing back at all. So this sends a DHCPINFORM the way a relay agent
forwards one — giaddr (the relay address) set to this computer's own
address on the way to the server — and listens on UDP 67 for the DHCPACK.
INFORM asks only for configuration; unlike DISCOVER/REQUEST it makes the
server neither offer nor lease an address, so probing changes nothing on
it. Tried against a home router: DHCPACK in a few milliseconds.

Binding UDP 67 needs no root on macOS (10.14+) or Windows, but only one
socket on the machine can hold it, so the many probes of a grid sweep share
one: it's opened on the first probe, a reader thread hands each reply to
the probe waiting for its transaction ID, and it's closed again as soon as
no probe is waiting. If 67 can't be had (Internet Sharing's bootpd holds
it, say) ask() returns None and the caller falls back to a plain probe.
"""

from __future__ import annotations

import random
import socket
import struct
import threading

from ..osinfo import IS_WINDOWS

SERVER_PORT = 67
MAGIC_COOKIE = b"\x63\x82\x53\x63"
DHCPINFORM = 8
MESSAGE_TYPES = {1: "DISCOVER", 2: "OFFER", 3: "REQUEST", 4: "DECLINE", 5: "ACK",
                 6: "NAK", 7: "RELEASE", 8: "INFORM"}
#: A made-up, locally administered client MAC: the server only echoes it.
CLIENT_MAC = bytes.fromhex("02000000ce11")
_HEADER = struct.Struct("!BBBBIHH4s4s4s4s16s64s128s")


def local_address(ip: str) -> str:
    """This computer's address on the route to `ip`."""
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.connect((ip, SERVER_PORT))  # no packet is sent
        return sock.getsockname()[0]


def build_inform(xid: int, relay_ip: str) -> bytes:
    """A DHCPINFORM as a relay agent at `relay_ip` would forward it."""
    address = socket.inet_aton(relay_ip)
    header = _HEADER.pack(
        1, 1, 6, 1,  # BOOTREQUEST, Ethernet, 6-byte MAC, one relay hop
        xid, 0, 0,
        address,  # ciaddr: the client asking (this computer)
        b"\0" * 4, b"\0" * 4,
        address,  # giaddr: the relay the answer goes back to, on UDP 67
        CLIENT_MAC + b"\0" * 10, b"", b"",
    )
    options = bytes([53, 1, DHCPINFORM, 55, 3, 1, 3, 6, 255])  # subnet, router, DNS
    return header + MAGIC_COOKIE + options


def parse_reply(data: bytes, xid: int) -> dict[int, bytes] | None:
    """The options of a BOOTREPLY to `xid`, or None if it isn't one."""
    if len(data) < _HEADER.size + 4 or data[0] != 2:
        return None
    if struct.unpack_from("!I", data, 4)[0] != xid:
        return None
    if data[_HEADER.size:_HEADER.size + 4] != MAGIC_COOKIE:
        return {}
    options: dict[int, bytes] = {}
    offset = _HEADER.size + 4
    while offset < len(data):
        code = data[offset]
        if code == 255:
            break
        if code == 0:
            offset += 1
            continue
        if offset + 1 >= len(data):
            break
        length = data[offset + 1]
        options[code] = data[offset + 2:offset + 2 + length]
        offset += 2 + length
    return options


def describe(options: dict[int, bytes]) -> str:
    """"DHCP ACK · server 192.168.1.1" from a reply's options."""
    kind = MESSAGE_TYPES.get(options.get(53, b"\0")[0], "reply")
    text = f"DHCP {kind}"
    server = options.get(54)
    if server and len(server) == 4:
        text += f" · server {socket.inet_ntoa(server)}"
    return text


class _Listener:
    """The one UDP 67 socket every probe shares while any is waiting."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._sock: socket.socket | None = None
        self._waiting: dict[int, tuple[threading.Event, list[bytes]]] = {}

    def _open(self) -> socket.socket:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            if not IS_WINDOWS:
                # On Windows SO_REUSEADDR would let this socket take UDP 67
                # from one already holding it (Internet Connection Sharing's
                # DHCP server for Hyper-V/WSL); there, if 67 is taken the
                # bind fails and the plain probe is used instead.
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind(("0.0.0.0", SERVER_PORT))
        except OSError:
            sock.close()
            raise
        threading.Thread(target=self._read, args=(sock,), daemon=True,
                         name="dhcp-probe").start()
        return sock

    def _read(self, sock: socket.socket) -> None:
        while True:
            try:
                data, _ = sock.recvfrom(4096)
            except OSError:
                return  # closed: no probe is waiting any more
            if len(data) < 8:
                continue
            xid = struct.unpack_from("!I", data, 4)[0]
            with self._lock:
                waiter = self._waiting.get(xid)
            if waiter is not None:
                waiter[1].append(data)
                waiter[0].set()

    def ask(self, ip: str, timeout: float, attempts: int = 2) -> dict[int, bytes] | None:
        """The options of the server's reply, {} if a reply had none, or
        None for no reply (or UDP 67 couldn't be bound here)."""
        try:
            relay_ip = local_address(ip)
        except OSError:
            return None
        xid = random.randrange(1, 1 << 32)
        event, replies = threading.Event(), []
        with self._lock:
            if self._sock is None:
                try:
                    self._sock = self._open()
                except OSError:
                    return None
            self._waiting[xid] = (event, replies)
            sock = self._sock
        try:
            packet = build_inform(xid, relay_ip)
            for _ in range(attempts):
                try:
                    sock.sendto(packet, (ip, SERVER_PORT))
                except OSError:
                    return None
                if event.wait(timeout / attempts):
                    for reply in replies:
                        options = parse_reply(reply, xid)
                        if options is not None:
                            return options
                    event.clear()
            return None
        finally:
            with self._lock:
                self._waiting.pop(xid, None)
                if not self._waiting and self._sock is not None:
                    self._sock.close()
                    self._sock = None


_listener = _Listener()


def ask(ip: str, timeout: float = 1.0) -> dict[int, bytes] | None:
    """Ask `ip`'s DHCP server (UDP 67) for configuration, as a relay would."""
    if ":" in ip:
        return None  # DHCPv4 only
    return _listener.ask(ip, timeout)
