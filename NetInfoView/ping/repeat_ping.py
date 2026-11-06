"""Repeat Ping: a Cisco IOS-style extended ping to one host.

Like IOS, each echo is sent the moment the previous one is answered (or
times out), with no interval in between, so the rate is set by the round
trip alone: about 1000 a second on a LAN, which is what makes a 100000-echo
run to shake out CRC errors, a bad SFP or a duplex mismatch practical.
Options and output follow IOS too: datagram size counts the IP and ICMP
headers (100 bytes by default), an optional DF bit, a 16-bit data pattern
(0xABCD), a size sweep, and one character per echo — ``!`` reply, ``.``
timeout, ``U`` unreachable, ``M`` could not fragment, ``Q`` source quench,
``&`` TTL expired, ``?`` anything else — 70 to a line, then IOS's
"Success rate is ... percent" summary.

On macOS it uses its own unprivileged ICMP datagram socket (no root), with
an identifier of its own so replies to the main grid's pings, which share
the kernel's ICMP traffic, are never mistaken for its own; on Windows,
IcmpSendEcho (ping/icmp_windows.py).
"""

from __future__ import annotations

import errno
import random
import socket
import time
from collections.abc import Callable
from dataclasses import dataclass, field

from ..osinfo import IS_WINDOWS
from .icmp import _ICMP_HEADER, _IP_DONTFRAG as IP_DONTFRAG, ICMP_ECHO_REPLY, ICMP_ECHO_REQUEST
from .icmp import checksum, parse_reply
from .result import PingStatus, status_for_icmp

#: IP + ICMP headers, which IOS counts in the datagram size.
HEADER_BYTES = 28
MIN_SIZE = 36
DEFAULT_SIZE = 100
#: macOS caps an unprivileged ICMP datagram at net.inet.raw.maxdgram (8192
#: bytes of ICMP); Windows' IcmpSendEcho takes up to 65500 bytes of data.
MAX_SIZE = 65500 + HEADER_BYTES if IS_WINDOWS else 8192 + 20
DEFAULT_COUNT = 5
#: IOS's own ceiling for a repeat count.
MAX_COUNT = 2147483647
DEFAULT_TIMEOUT = 2.0
DEFAULT_PATTERN = 0xABCD
#: IOS wraps the result characters at this width.
LINE_WIDTH = 70

SUCCESS = "!"
_CHAR_FOR_STATUS = {
    PingStatus.SUCCEEDED: "!",
    PingStatus.TIMEOUT: ".",
    PingStatus.NET_UNREACHABLE: "U",
    PingStatus.HOST_UNREACHABLE: "U",
    PingStatus.PROTOCOL_UNREACHABLE: "U",
    PingStatus.PORT_UNREACHABLE: "U",
    PingStatus.ADMIN_PROHIBITED: "U",
    PingStatus.FRAGMENTATION_NEEDED: "M",
    PingStatus.SOURCE_QUENCH: "Q",
    PingStatus.TTL_EXPIRED: "&",
}

#: What each character means, for the window's legend.
LEGEND = (
    ("!", "reply"), (".", "timeout"), ("U", "unreachable"), ("Q", "source quench"),
    ("&", "TTL expired"), ("?", "other / send error"),
)


def char_for(status: PingStatus) -> str:
    return _CHAR_FOR_STATUS.get(status, "?")


@dataclass(slots=True)
class RepeatOptions:
    count: int = DEFAULT_COUNT
    #: Datagram size in bytes, IP and ICMP headers included (IOS style).
    size: int = DEFAULT_SIZE
    #: Seconds to wait for each reply; 0 sends without waiting (IOS's
    #: "timeout 0": every echo shows as ".", the target still gets them).
    timeout: float = DEFAULT_TIMEOUT
    dont_fragment: bool = False
    pattern: int = DEFAULT_PATTERN
    #: (min, max, step) sizes to sweep, each sent `count` times; None for one size.
    sweep: tuple[int, int, int] | None = None

    def sizes(self) -> list[int]:
        if self.sweep is None:
            return [self.size]
        low, high, step = self.sweep
        return list(range(low, high + 1, max(1, step)))

    @property
    def total(self) -> int:
        return self.count * len(self.sizes())


@dataclass(slots=True)
class RepeatStats:
    sent: int = 0
    received: int = 0
    min_ms: float | None = None
    max_ms: float | None = None
    total_ms: float = 0.0
    started: float = field(default_factory=time.monotonic)
    elapsed_s: float = 0.0
    #: Result character -> how many times it came up.
    counts: dict[str, int] = field(default_factory=dict)
    #: Sizes that failed with "could not fragment" (M), for a DF sweep.
    largest_ok_size: int | None = None
    smallest_failed_size: int | None = None

    def add(self, char: str, rtt_ms: float | None, size: int) -> None:
        self.sent += 1
        self.counts[char] = self.counts.get(char, 0) + 1
        if char == SUCCESS and rtt_ms is not None:
            self.received += 1
            self.total_ms += rtt_ms
            self.min_ms = rtt_ms if self.min_ms is None else min(self.min_ms, rtt_ms)
            self.max_ms = rtt_ms if self.max_ms is None else max(self.max_ms, rtt_ms)
            if self.largest_ok_size is None or size > self.largest_ok_size:
                self.largest_ok_size = size
        elif char == "M":
            if self.smallest_failed_size is None or size < self.smallest_failed_size:
                self.smallest_failed_size = size
        self.elapsed_s = time.monotonic() - self.started

    @property
    def avg_ms(self) -> float | None:
        return self.total_ms / self.received if self.received else None

    @property
    def lost(self) -> int:
        return self.sent - self.received

    @property
    def success_percent(self) -> int:
        """Whole percent, rounded down like IOS (99999/100000 is 99)."""
        return self.received * 100 // self.sent if self.sent else 0

    @property
    def rate(self) -> float:
        return self.sent / self.elapsed_s if self.elapsed_s > 0 else 0.0


def payload(size: int, pattern: int) -> bytes:
    """ICMP data for an IOS datagram size, filled with the 16-bit pattern."""
    length = max(0, size - HEADER_BYTES)
    return (pattern.to_bytes(2, "big") * (length // 2 + 1))[:length]


def build_echo(ident: int, sequence: int, data: bytes) -> bytes:
    header = _ICMP_HEADER.pack(ICMP_ECHO_REQUEST, 0, 0, ident, sequence)
    return _ICMP_HEADER.pack(ICMP_ECHO_REQUEST, 0, checksum(header + data), ident, sequence) + data


def parse_pattern(text: str) -> int:
    """"0xABCD" or "ABCD" -> 0xABCD; ValueError unless 0-0xFFFF."""
    value = int(text.strip(), 16)
    if not 0 <= value <= 0xFFFF:
        raise ValueError(text)
    return value


def _status_for_send_error(exc: OSError) -> PingStatus:
    if exc.errno == errno.EMSGSIZE:
        return PingStatus.FRAGMENTATION_NEEDED  # bigger than the link, with DF
    if exc.errno in (errno.ENETUNREACH, errno.ENETDOWN):
        return PingStatus.NET_UNREACHABLE
    if exc.errno in (errno.EHOSTUNREACH, errno.EHOSTDOWN):
        return PingStatus.HOST_UNREACHABLE
    if exc.errno in (errno.ENOBUFS, errno.EAGAIN):
        return PingStatus.NO_RESOURCES
    return PingStatus.GENERAL_FAILURE


class SocketEcho:
    """Back-to-back echoes over one blocking unprivileged ICMP socket."""

    def __init__(self, dont_fragment: bool) -> None:
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_ICMP)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 1 << 20)
        self._sock.setsockopt(socket.IPPROTO_IP, IP_DONTFRAG, int(dont_fragment))
        # Not the engine's (pid-based) identifier: every ICMP socket sees
        # every reply, and the grid may be pinging the same host right now.
        self._ident = random.randrange(1, 0x10000)
        self._sequence = 0

    def close(self) -> None:
        self._sock.close()

    def _drain(self) -> None:
        self._sock.setblocking(False)
        try:
            while True:
                self._sock.recv(65535)
        except OSError:
            pass
        finally:
            self._sock.setblocking(True)

    def echo(self, ip: str, data: bytes, timeout: float) -> tuple[PingStatus, float | None]:
        self._sequence = (self._sequence + 1) & 0xFFFF
        sequence = self._sequence
        packet = build_echo(self._ident, sequence, data)
        started = time.perf_counter()
        try:
            self._sock.sendto(packet, (ip, 0))
        except OSError as exc:
            return _status_for_send_error(exc), None
        if timeout <= 0:
            self._drain()  # replies nobody waits for mustn't fill the buffer
            return PingStatus.TIMEOUT, None
        deadline = started + timeout
        while (left := deadline - time.perf_counter()) > 0:
            self._sock.settimeout(left)
            try:
                reply = self._sock.recv(65535)
            except (socket.timeout, TimeoutError):
                break
            except OSError as exc:
                return _status_for_send_error(exc), None
            parsed = parse_reply(reply)
            if parsed is None:
                continue
            reply_sequence, icmp_type, icmp_code, _, ident = parsed
            if ident != self._ident or reply_sequence != sequence:
                continue  # a late reply to an earlier echo, or someone else's
            if icmp_type == ICMP_ECHO_REPLY:
                return PingStatus.SUCCEEDED, (time.perf_counter() - started) * 1000
            return status_for_icmp(icmp_type, icmp_code), None
        return PingStatus.TIMEOUT, None


class WindowsEcho:
    """Back-to-back echoes through IcmpSendEcho."""

    def __init__(self, dont_fragment: bool) -> None:
        from . import icmp_windows
        self._icmp = icmp_windows
        self._api = icmp_windows._IcmpApi()
        self._dont_fragment = dont_fragment

    def close(self) -> None:
        pass

    def echo(self, ip: str, data: bytes, timeout: float) -> tuple[PingStatus, float | None]:
        result = self._icmp.send_echo(
            self._api, ip, max(1, int(timeout * 1000)), len(data), 64,
            self._dont_fragment, data=data,
        )
        if timeout <= 0:
            return PingStatus.TIMEOUT, None
        return result.status, result.rtt_ms


def open_echo(dont_fragment: bool):
    return WindowsEcho(dont_fragment) if IS_WINDOWS else SocketEcho(dont_fragment)


def run(
    ip: str,
    options: RepeatOptions,
    on_result: Callable[[str, float | None, int], None],
    should_stop: Callable[[], bool] = lambda: False,
    echo_factory: Callable[[bool], object] | None = None,
) -> bool:
    """Send every echo in `options`, back to back, calling on_result(char,
    rtt_ms, size) after each. False if stopped. echo_factory defaults to
    open_echo, looked up at call time so tests can replace it."""
    echo = (echo_factory or open_echo)(options.dont_fragment)
    try:
        for size in options.sizes():
            data = payload(size, options.pattern)
            for _ in range(options.count):
                if should_stop():
                    return False
                status, rtt_ms = echo.echo(ip, data, options.timeout)
                on_result(char_for(status), rtt_ms, size)
    finally:
        echo.close()
    return True


# -- IOS-style text -----------------------------------------------------------

def _format_ms(value: float | None) -> str:
    if value is None:
        return "-"
    return f"{value:.0f}" if value >= 10 else f"{value:.1f}"


def header_text(host: str, ip: str, options: RepeatOptions) -> str:
    target = ip if host == ip else f"{host} ({ip})"
    timeout = f"{options.timeout:g} second{'s' if options.timeout != 1 else ''}"
    if options.sweep is None:
        what = f"Sending {options.total:,}, {options.size}-byte ICMP Echos"
    else:
        low, high, _ = options.sweep
        what = f"Sending {options.total:,}, [{low}..{high}]-byte ICMP Echos"
    lines = [f"{what} to {target}, timeout is {timeout}:"]
    if options.dont_fragment:
        lines.append("Packet sent with the DF bit set")
    if options.pattern != DEFAULT_PATTERN:  # IOS only mentions one it was given
        lines.append(f"Packet has data pattern 0x{options.pattern:04X}")
    return "\n".join(lines)


def summary_text(stats: RepeatStats, stopped: bool = False) -> str:
    line = (f"Success rate is {stats.success_percent} percent "
            f"({stats.received:,}/{stats.sent:,})")
    if stats.received:
        line += (f", round-trip min/avg/max = {_format_ms(stats.min_ms)}/"
                 f"{_format_ms(stats.avg_ms)}/{_format_ms(stats.max_ms)} ms")
    lines = [line]
    if stopped:
        lines.append("Stopped.")
    if stats.smallest_failed_size is not None:
        largest = stats.largest_ok_size
        lines.append(
            f"Largest size through with DF: {largest} bytes" if largest
            else "No size got through with DF"
        )
    return "\n".join(lines)
