"""ICMP echo on Windows through the IP Helper API (``IcmpSendEcho``).

Windows won't give an unprivileged program an ICMP socket, and asyncio's
default Windows event loop can't watch raw sockets anyway, so instead of
icmp.IcmpPinger's one shared socket each ping is a blocking IcmpSendEcho call
on a worker thread. It needs no administrator rights: it's the same API
Windows' own ping.exe uses. The class mirrors IcmpPinger's interface so the
engine can use either.
"""

from __future__ import annotations

import asyncio
import ctypes
import socket
import struct
import time
from concurrent.futures import ThreadPoolExecutor
from ctypes import wintypes

from .result import PingResult, PingStatus

#: IP_STATUS codes (ipexport.h) -> how the grid words them.
IP_SUCCESS = 0
IP_REQ_TIMED_OUT = 11010
_STATUS: dict[int, PingStatus] = {
    11002: PingStatus.NET_UNREACHABLE,         # IP_DEST_NET_UNREACHABLE
    11003: PingStatus.HOST_UNREACHABLE,        # IP_DEST_HOST_UNREACHABLE
    11004: PingStatus.PROTOCOL_UNREACHABLE,    # IP_DEST_PROT_UNREACHABLE
    11005: PingStatus.PORT_UNREACHABLE,        # IP_DEST_PORT_UNREACHABLE
    11006: PingStatus.NO_RESOURCES,            # IP_NO_RESOURCES
    11009: PingStatus.FRAGMENTATION_NEEDED,    # IP_PACKET_TOO_BIG
    IP_REQ_TIMED_OUT: PingStatus.TIMEOUT,
    11013: PingStatus.TTL_EXPIRED,             # IP_TTL_EXPIRED_TRANSIT
    11014: PingStatus.TTL_EXPIRED,             # IP_TTL_EXPIRED_REASSEM
    11016: PingStatus.SOURCE_QUENCH,           # IP_SOURCE_QUENCH
    11018: PingStatus.BAD_DESTINATION,         # IP_BAD_DESTINATION
}

IP_FLAG_DF = 0x2

#: Threads blocked in IcmpSendEcho at once. Each ping holds one for up to the
#: timeout, so this caps how many can be in flight; the engine's own
#: max_concurrent limit queues the rest.
MAX_WORKERS = 256


def status_for_ip_status(code: int) -> PingStatus:
    if code == IP_SUCCESS:
        return PingStatus.SUCCEEDED
    return _STATUS.get(code, PingStatus.GENERAL_FAILURE)


class IP_OPTION_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("Ttl", ctypes.c_ubyte),
        ("Tos", ctypes.c_ubyte),
        ("Flags", ctypes.c_ubyte),
        ("OptionsSize", ctypes.c_ubyte),
        ("OptionsData", ctypes.c_void_p),
    ]


class ICMP_ECHO_REPLY(ctypes.Structure):
    _fields_ = [
        ("Address", ctypes.c_uint32),
        ("Status", ctypes.c_uint32),
        ("RoundTripTime", ctypes.c_uint32),
        ("DataSize", ctypes.c_uint16),
        ("Reserved", ctypes.c_uint16),
        ("Data", ctypes.c_void_p),
        ("Options", IP_OPTION_INFORMATION),
    ]


def ip_to_ipaddr(ip: str) -> int:
    """An IPv4 string as the IPAddr IcmpSendEcho takes: the in_addr bytes
    (network order) read as a native little-endian integer."""
    return struct.unpack("<I", socket.inet_aton(ip))[0]


def ipaddr_to_ip(value: int) -> str:
    return socket.inet_ntoa(struct.pack("<I", value))


def _payload(size: int) -> bytes:
    return bytes((ord("a") + (i % 23)) for i in range(max(0, size)))


class _IcmpApi:
    """The three iphlpapi calls, typed once."""

    def __init__(self) -> None:
        dll = ctypes.WinDLL("iphlpapi.dll", use_last_error=True)
        self.create = dll.IcmpCreateFile
        self.create.restype = wintypes.HANDLE
        self.create.argtypes = []
        self.close = dll.IcmpCloseHandle
        self.close.restype = wintypes.BOOL
        self.close.argtypes = [wintypes.HANDLE]
        self.send = dll.IcmpSendEcho
        self.send.restype = wintypes.DWORD
        self.send.argtypes = [
            wintypes.HANDLE, ctypes.c_uint32, ctypes.c_void_p, wintypes.WORD,
            ctypes.POINTER(IP_OPTION_INFORMATION), ctypes.c_void_p, wintypes.DWORD,
            wintypes.DWORD,
        ]


_INVALID_HANDLE = ctypes.c_void_p(-1).value


def send_echo(
    api: _IcmpApi, ip: str, timeout_ms: int, payload_size: int, ttl: int, dont_fragment: bool
) -> PingResult:
    """One blocking echo request; what IcmpWindowsPinger runs on a worker."""
    handle = api.create()
    if not handle or handle == _INVALID_HANDLE:
        return PingResult(PingStatus.NO_RESOURCES)
    try:
        payload = _payload(payload_size)
        options = IP_OPTION_INFORMATION(Ttl=ttl, Flags=IP_FLAG_DF if dont_fragment else 0)
        # Room for one reply, its echoed data, and an ICMP error's quoted header.
        reply_size = ctypes.sizeof(ICMP_ECHO_REPLY) + len(payload) + 8 + 64
        reply_buffer = ctypes.create_string_buffer(reply_size)
        started = time.perf_counter()
        count = api.send(
            handle, ip_to_ipaddr(ip), payload or None, len(payload),
            ctypes.byref(options), reply_buffer, reply_size, max(1, timeout_ms),
        )
        elapsed_ms = (time.perf_counter() - started) * 1000.0
        if count == 0:
            return PingResult(status_for_ip_status(ctypes.get_last_error()))
        reply = ICMP_ECHO_REPLY.from_buffer(reply_buffer)
        status = status_for_ip_status(reply.Status)
        reply_ip = ipaddr_to_ip(reply.Address)
        ttl_seen = reply.Options.Ttl or None
        if not status.succeeded:
            return PingResult(status, None, reply_ip, ttl_seen)
        # RoundTripTime is whole milliseconds (0 for anything under 1 ms);
        # the measured time keeps sub-millisecond replies distinguishable.
        rtt = float(reply.RoundTripTime) if reply.RoundTripTime else min(elapsed_ms, 0.99)
        return PingResult(PingStatus.SUCCEEDED, rtt, reply_ip, ttl_seen)
    finally:
        api.close(handle)


class IcmpWindowsPinger:
    """Same interface as icmp.IcmpPinger, backed by IcmpSendEcho."""

    def __init__(self, ttl: int = 64, dont_fragment: bool = False) -> None:
        self.ttl = ttl
        self.dont_fragment = dont_fragment
        #: IcmpSendEcho always honours the DF flag.
        self.dont_fragment_supported = True
        self._api: _IcmpApi | None = None
        self._pool: ThreadPoolExecutor | None = None

    def open(self) -> None:
        if self._pool is not None:
            return
        self._api = _IcmpApi()
        self._pool = ThreadPoolExecutor(max_workers=MAX_WORKERS, thread_name_prefix="icmp")

    def close(self) -> None:
        if self._pool is None:
            return
        self._pool.shutdown(wait=False, cancel_futures=True)
        self._pool = None

    def configure(self, ttl: int | None = None, dont_fragment: bool | None = None) -> None:
        if ttl is not None:
            self.ttl = ttl
        if dont_fragment is not None:
            self.dont_fragment = dont_fragment

    async def ping(self, ip: str, timeout_ms: int, payload_size: int = 32) -> PingResult:
        if self._pool is None:
            self.open()
        assert self._pool is not None and self._api is not None
        loop = asyncio.get_running_loop()
        try:
            return await loop.run_in_executor(
                self._pool, send_echo, self._api, ip, timeout_ms, payload_size,
                self.ttl, self.dont_fragment,
            )
        except RuntimeError:  # pool shut down mid-ping, i.e. stopping
            return PingResult(PingStatus.GENERAL_FAILURE)
