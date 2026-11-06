"""TCP probes for Net Path, the way SolarWinds NetPath traces: a TCP SYN to
the service's own port (443 by default), with the TTL cut short so a router
on the way answers "Time exceeded" instead. Firewalls that drop ICMP echo let
these through, and load-balancing routers hash them like the application's
real traffic, so the routes found are the ones that traffic takes.

Every probe gets a source port of its own. Reusing one for the next TTL
(as Paris traceroute does to pin a flow to one route) doesn't work here:
NATs, a home router's or a carrier's, pass the ICMP errors for the first
probe of a port and drop the rest, and they rewrite the source port anyway,
so a flow can't be pinned behind them. Like ``mtr --tcp``, each probe is a
sample: the routers that answer at each hop are every route a load balancer
offers, but which hop of one route follows which of the next is inferred.

The SYN goes out through an ordinary non-blocking connect() with IP_TTL set,
so no privileges are needed to send it. What comes back:

* a SYN-ACK (the connect completes) or a RST (refused): the host itself
  answered;
* an ICMP Time Exceeded from a router, quoting the SYN's ports: read on
  macOS from an unprivileged ICMP datagram socket, which is handed the ICMP
  errors about this host's TCP packets too; on Windows through Npcap, or
  else a raw ICMP socket (run as administrator; Windows Firewall may keep
  the errors from it).
"""

from __future__ import annotations

import errno
import random
import select
import socket
import struct
import time

from ..osinfo import IS_WINDOWS
from .netpath import Answer

DEFAULT_PORT = 443
#: How long a probe waits for its answer. Under a second: the system sends
#: an unanswered SYN again after one (macOS), and a router's answer to that
#: copy would be timed from the first, a second too slow. A hop that hasn't
#: answered by then is asked again with a new probe (netpath.sweep).
WAIT_MS = 900
ICMP_TIME_EXCEEDED = 11
ICMP_UNREACHABLE = 3
TCP = 6
#: Source ports are taken from here in turn, one per probe, from a random start.
PORT_RANGE = (40000, 60000)
#: How long one Npcap read waits for a packet (Windows).
NPCAP_READ_TIMEOUT_MS = 5
#: Windows' "connection refused", reported for a RST.
_WSAECONNREFUSED = 10061


class TcpUnavailable(OSError):
    """TCP probes can't be used on this computer, and why."""


#: Why a TCP trace that heard nothing at all is taken for a local block.
UNHEARD = ("No router answered the TCP probes, not even the first: "
           + ("Windows Firewall may be blocking the routers' ICMP replies "
              "(installing Npcap avoids it)" if IS_WINDOWS
              else "something on this computer may be blocking ICMP"))


def quoted_tcp(packet: bytes) -> tuple[int, int, int, int] | None:
    """(icmp type, icmp code, source port, destination port) of an ICMP error
    about a TCP segment; `packet` starts at the IP header. None for anything
    else."""
    if len(packet) < 20 or packet[0] >> 4 != 4:
        return None
    offset = (packet[0] & 0x0F) * 4
    if len(packet) < offset + 8:
        return None
    kind, code = packet[offset], packet[offset + 1]
    if kind not in (ICMP_TIME_EXCEEDED, ICMP_UNREACHABLE):
        return None
    inner = packet[offset + 8:]
    if len(inner) < 20 or inner[0] >> 4 != 4 or inner[9] != TCP:
        return None
    inner_offset = (inner[0] & 0x0F) * 4
    if len(inner) < inner_offset + 4:
        return None
    source_port, destination_port = struct.unpack_from("!HH", inner, inner_offset)
    return kind, code, source_port, destination_port


# -- hearing the ICMP errors -------------------------------------------------

class _SocketListener:
    """ICMP packets, IP header first, from a socket."""

    def __init__(self, sock: socket.socket) -> None:
        sock.setblocking(False)
        self._sock = sock

    def packets(self, wait: float) -> list[tuple[bytes, str]]:
        if not select.select([self._sock], [], [], max(0.0, wait))[0]:
            return []
        found = []
        while True:
            try:
                data, (source, _) = self._sock.recvfrom(4096)
            except (BlockingIOError, InterruptedError):
                return found
            except OSError:
                return found
            found.append((data, source))

    def close(self) -> None:
        self._sock.close()


class _NpcapListener:
    """ICMP packets captured by Npcap on the adapter the probes leave by."""

    def __init__(self, adapter: str) -> None:
        from . import npcap

        # Immediate, and a short read timeout: an answer is timed by when it's
        # read, and while a read waits the probes' SYN-ACKs aren't checked.
        self._capture = npcap.Capture(adapter, _icmp_filter(),
                                      read_timeout_ms=NPCAP_READ_TIMEOUT_MS, immediate=True)

    def packets(self, wait: float) -> list[tuple[bytes, str]]:
        found = []
        deadline = time.monotonic() + max(0.0, wait)
        while True:
            frame = self._capture.next_frame()
            if frame is not None and len(frame) > 14 + 20:
                packet = frame[14:]
                found.append((packet, socket.inet_ntoa(packet[12:16])))
                continue
            if found or time.monotonic() >= deadline:
                return found

    def close(self) -> None:
        self._capture.close()


_ICMP_FILTER = (
    (0x28, 0, 0, 12),  # ldh [12]      EtherType
    (0x15, 0, 3, 0x0800),  # jeq IPv4, else drop
    (0x30, 0, 0, 23),  # ldb [23]      IP protocol
    (0x15, 0, 1, 1),  # jeq ICMP -> accept, else drop
    (0x06, 0, 0, 0x40000),  # ret: accept
    (0x06, 0, 0, 0),  # ret: drop
)


def _icmp_filter():
    from .lldp_cdp import _BpfInsn, _BpfProgram

    insns = (_BpfInsn * len(_ICMP_FILTER))(*(_BpfInsn(*insn) for insn in _ICMP_FILTER))
    program = _BpfProgram(len(_ICMP_FILTER), insns)
    program._insns = insns
    return program


def local_address(ip: str) -> str:
    """The address this computer sends to `ip` from."""
    probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        probe.connect((ip, 9))
        return probe.getsockname()[0]
    except OSError:
        return ""
    finally:
        probe.close()


def open_listener(ip: str):
    """Something to hear the routers' ICMP errors with, or TcpUnavailable.

    On Windows Npcap comes first: it captures below Windows Firewall, which
    keeps the routers' Time Exceeded for a TCP SYN from a raw socket (the
    socket opens fine, then hears nothing). The raw socket is the fallback
    for an administrator without Npcap, heard only if the firewall lets
    those errors in."""
    if not IS_WINDOWS:
        try:
            return _SocketListener(socket.socket(socket.AF_INET, socket.SOCK_DGRAM,
                                                 socket.IPPROTO_ICMP))
        except OSError as error:
            raise TcpUnavailable(f"Can't open an ICMP socket: {error}") from error
    from . import npcap

    local = local_address(ip)
    reason = npcap.available()
    if not reason:
        try:
            adapter = next((d.name for d in npcap.devices() if local in d.ipv4), "")
        except OSError as error:
            adapter, reason = "", f"Npcap couldn't list the adapters: {error}"
        if adapter:
            try:
                return _NpcapListener(adapter)
            except OSError as error:
                reason = f"Npcap couldn't open the adapter: {error}"
        elif not reason:
            reason = f"Npcap has no adapter with the address {local or '?'}"
    try:  # a raw ICMP socket: Windows allows it to administrators
        raw = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
        raw.bind((local, 0))
        return _SocketListener(raw)
    except OSError:
        pass
    raise TcpUnavailable("TCP probes need Npcap, or NetInfoView run as administrator: "
                         + reason)


def unavailable(ip: str = "8.8.8.8") -> str:
    """"" when TCP probes can be used here, otherwise why not."""
    try:
        open_listener(ip).close()
    except TcpUnavailable as error:
        return str(error)
    return ""


# -- the probes ----------------------------------------------------------------

class TcpProber:
    """Net Path's probe(ip, ttl, flows) over TCP to `port`, each probe from
    a source port not used before in this sweep."""

    def __init__(self, port: int = DEFAULT_PORT, wait_ms: int = WAIT_MS, listener=None) -> None:
        self.port = port
        self.wait_ms = wait_ms
        self._listener = listener
        self._next = random.randrange(*PORT_RANGE)

    def next_port(self) -> int:
        port = self._next
        self._next = PORT_RANGE[0] + (port + 1 - PORT_RANGE[0]) % (PORT_RANGE[1] - PORT_RANGE[0])
        return port

    def __call__(self, ip: str, ttl: int, flows: list[int]) -> dict[int, Answer]:
        if self._listener is None:
            self._listener = open_listener(ip)
        listener = self._listener
        sent: dict[int, tuple[socket.socket, int, float]] = {}  # port -> (socket, flow, sent)
        answers: dict[int, Answer] = {}
        try:
            for flow in flows:
                port = sock = None
                for _ in range(4):  # a port some other program holds: the next
                    port = self.next_port()
                    sock = self._open(ttl, port)
                    if sock is not None:
                        break
                if sock is None:
                    continue
                started = time.perf_counter()
                try:
                    sock.connect((ip, self.port))
                except (BlockingIOError, InterruptedError):
                    pass
                except OSError:  # e.g. no route at all
                    sock.close()
                    continue
                sent[port] = (sock, flow, started)
            deadline = time.perf_counter() + self.wait_ms / 1000
            while len(answers) < len(sent):
                left = deadline - time.perf_counter()
                if left <= 0:
                    break
                for packet, source in listener.packets(min(left, 0.02)):
                    quoted = quoted_tcp(packet)
                    if quoted is None:
                        continue
                    kind, _, source_port, destination_port = quoted
                    entry = sent.get(source_port)
                    if entry is None or destination_port != self.port or entry[1] in answers:
                        continue
                    _, flow, started = entry
                    from_host = source == ip
                    answers[flow] = Answer(
                        source, (time.perf_counter() - started) * 1000,
                        reached=from_host,
                        unreachable=kind == ICMP_UNREACHABLE and not from_host,
                    )
                self._check_connects(sent, answers, ip)
        finally:
            for sock, _, _ in sent.values():
                sock.close()
        return answers

    @staticmethod
    def _open(ttl: int, port: int) -> socket.socket | None:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            # Close with a RST, not a FIN, so a host that answered isn't
            # left half-open and the port isn't held in TIME_WAIT.
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, ttl)
            sock.bind(("", port))
            sock.setblocking(False)
            return sock
        except OSError:
            sock.close()
            return None

    @staticmethod
    def _check_connects(sent, answers, ip: str) -> None:
        """A connect that completed (SYN-ACK) or was refused (RST): the
        host answered."""
        pending = [entry[0] for entry in sent.values() if entry[1] not in answers]
        if not pending:
            return
        _, writable, failed = select.select([], pending, pending, 0)
        for sock in set(writable) | set(failed):
            entry = next(e for e in sent.values() if e[0] is sock)
            _, flow, started = entry
            try:
                sock.getpeername()
            except OSError:
                error = sock.getsockopt(socket.SOL_SOCKET, socket.SO_ERROR)
                if error not in (errno.ECONNREFUSED, _WSAECONNREFUSED):
                    continue  # e.g. an ICMP error, heard on the listener
            answers[flow] = Answer(ip, (time.perf_counter() - started) * 1000, reached=True)

    def close(self) -> None:
        if self._listener is not None:
            self._listener.close()
            self._listener = None

