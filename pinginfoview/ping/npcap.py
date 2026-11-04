"""Packet capture on Windows through Npcap (https://npcap.com), for LLDP/CDP.

Windows has no /dev/bpf; Npcap is the capture driver Wireshark installs, and
its wpcap.dll speaks libpcap's C API, called here through ctypes. Nothing is
bundled: when Npcap isn't installed, available() says so and the LLDP/CDP
window tells the user where to get it.
"""

from __future__ import annotations

import ctypes
import os
import socket
from dataclasses import dataclass

#: pcap_if_t flags.
PCAP_IF_LOOPBACK = 0x1
PCAP_IF_UP = 0x2
PCAP_IF_RUNNING = 0x4
PCAP_IF_WIRELESS = 0x8
PCAP_IF_CONNECTION_STATUS = 0x30
PCAP_IF_CONNECTION_STATUS_UNKNOWN = 0x00
PCAP_IF_CONNECTION_STATUS_CONNECTED = 0x10

PCAP_D_IN = 1
PCAP_ERRBUF_SIZE = 256
DLT_EN10MB = 1
SNAPLEN = 65536
#: How long pcap_next_ex waits before returning "nothing yet", so a stop
#: request is noticed promptly.
READ_TIMEOUT_MS = 250

NOT_INSTALLED = (
    "Npcap isn't installed: get it from https://npcap.com (the same driver "
    "Wireshark uses), then press Refresh"
)


class NpcapError(OSError):
    pass


class _SockAddr(ctypes.Structure):
    _fields_ = [("sa_family", ctypes.c_ushort), ("sa_data", ctypes.c_ubyte * 14)]


class _PcapAddr(ctypes.Structure):
    pass


_PcapAddr._fields_ = [
    ("next", ctypes.POINTER(_PcapAddr)),
    ("addr", ctypes.POINTER(_SockAddr)),
    ("netmask", ctypes.POINTER(_SockAddr)),
    ("broadaddr", ctypes.POINTER(_SockAddr)),
    ("dstaddr", ctypes.POINTER(_SockAddr)),
]


class _PcapIf(ctypes.Structure):
    pass


_PcapIf._fields_ = [
    ("next", ctypes.POINTER(_PcapIf)),
    ("name", ctypes.c_char_p),
    ("description", ctypes.c_char_p),
    ("addresses", ctypes.POINTER(_PcapAddr)),
    ("flags", ctypes.c_uint32),
]


class _PcapPkthdr(ctypes.Structure):
    # struct timeval is two 32-bit longs on Windows, even in 64-bit builds.
    _fields_ = [
        ("tv_sec", ctypes.c_int32),
        ("tv_usec", ctypes.c_int32),
        ("caplen", ctypes.c_uint32),
        ("len", ctypes.c_uint32),
    ]


_dll: ctypes.CDLL | None = None
_load_error = ""


def _load() -> ctypes.CDLL:
    """wpcap.dll, typed once. Npcap puts it in System32\\Npcap unless it was
    installed in WinPcap-compatible mode, which puts it in System32."""
    global _dll, _load_error
    if _dll is not None:
        return _dll
    if _load_error:
        raise NpcapError(_load_error)
    system32 = os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "System32")
    npcap_dir = os.path.join(system32, "Npcap")
    candidates = [os.path.join(npcap_dir, "wpcap.dll"), "wpcap.dll"]
    for path in candidates:
        try:
            if os.path.isdir(npcap_dir):
                # Packet.dll, which wpcap.dll needs, sits next to it.
                os.add_dll_directory(npcap_dir)
            dll = ctypes.CDLL(path)
            break
        except (OSError, AttributeError):
            continue
    else:
        _load_error = NOT_INSTALLED
        raise NpcapError(NOT_INSTALLED)

    dll.pcap_findalldevs.argtypes = [ctypes.POINTER(ctypes.POINTER(_PcapIf)), ctypes.c_char_p]
    dll.pcap_findalldevs.restype = ctypes.c_int
    dll.pcap_freealldevs.argtypes = [ctypes.POINTER(_PcapIf)]
    dll.pcap_freealldevs.restype = None
    dll.pcap_open_live.argtypes = [
        ctypes.c_char_p, ctypes.c_int, ctypes.c_int, ctypes.c_int, ctypes.c_char_p,
    ]
    dll.pcap_open_live.restype = ctypes.c_void_p
    dll.pcap_datalink.argtypes = [ctypes.c_void_p]
    dll.pcap_datalink.restype = ctypes.c_int
    dll.pcap_setfilter.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
    dll.pcap_setfilter.restype = ctypes.c_int
    dll.pcap_setdirection.argtypes = [ctypes.c_void_p, ctypes.c_int]
    dll.pcap_setdirection.restype = ctypes.c_int
    dll.pcap_next_ex.argtypes = [
        ctypes.c_void_p,
        ctypes.POINTER(ctypes.POINTER(_PcapPkthdr)),
        ctypes.POINTER(ctypes.POINTER(ctypes.c_ubyte)),
    ]
    dll.pcap_next_ex.restype = ctypes.c_int
    dll.pcap_geterr.argtypes = [ctypes.c_void_p]
    dll.pcap_geterr.restype = ctypes.c_char_p
    dll.pcap_close.argtypes = [ctypes.c_void_p]
    dll.pcap_close.restype = None
    _dll = dll
    return dll


def available() -> str:
    """"" when Npcap can be used, otherwise why not."""
    try:
        _load()
    except NpcapError as error:
        return str(error)
    return ""


@dataclass(frozen=True)
class Device:
    name: str  # \Device\NPF_{GUID}
    description: str  # the adapter's model, e.g. "Intel(R) Ethernet I219-V"
    ipv4: tuple[str, ...]
    connected: bool
    wireless: bool


def _text(value: bytes | None) -> str:
    return value.decode("utf-8", "replace") if value else ""


def is_connected(flags: int) -> bool:
    status = flags & PCAP_IF_CONNECTION_STATUS
    if status == PCAP_IF_CONNECTION_STATUS_UNKNOWN:
        return bool(flags & PCAP_IF_UP and flags & PCAP_IF_RUNNING)
    return status == PCAP_IF_CONNECTION_STATUS_CONNECTED


def devices() -> list[Device]:
    """Every adapter Npcap can capture on, loopback left out."""
    dll = _load()
    errbuf = ctypes.create_string_buffer(PCAP_ERRBUF_SIZE)
    first = ctypes.POINTER(_PcapIf)()
    if dll.pcap_findalldevs(ctypes.byref(first), errbuf) != 0:
        raise NpcapError(_text(errbuf.value) or "Npcap couldn't list the adapters")
    found: list[Device] = []
    try:
        node = first
        while node:
            entry = node.contents
            if not entry.flags & PCAP_IF_LOOPBACK:
                found.append(Device(
                    name=_text(entry.name),
                    description=_text(entry.description),
                    ipv4=tuple(_ipv4_addresses(entry.addresses)),
                    connected=is_connected(entry.flags),
                    wireless=bool(entry.flags & PCAP_IF_WIRELESS),
                ))
            node = entry.next
    finally:
        if first:
            dll.pcap_freealldevs(first)
    return found


def _ipv4_addresses(node) -> list[str]:
    addresses = []
    while node:
        entry = node.contents
        if entry.addr and entry.addr.contents.sa_family == socket.AF_INET:
            # sockaddr_in: port (2 bytes), then the address.
            addresses.append(socket.inet_ntoa(bytes(entry.addr.contents.sa_data[2:6])))
        node = entry.next
    return addresses


class Capture:
    """One adapter opened for capture, with a kernel filter."""

    def __init__(self, name: str, program: ctypes.Structure) -> None:
        self._dll = _load()
        self.name = name
        errbuf = ctypes.create_string_buffer(PCAP_ERRBUF_SIZE)
        handle = self._dll.pcap_open_live(
            name.encode(), SNAPLEN, 1, READ_TIMEOUT_MS, errbuf,
        )
        if not handle:
            raise NpcapError(_text(errbuf.value) or f"Npcap couldn't open {name}")
        self._handle = handle
        try:
            if self._dll.pcap_datalink(handle) != DLT_EN10MB:
                raise NpcapError("Not an Ethernet adapter")
            if self._dll.pcap_setfilter(handle, ctypes.byref(program)) != 0:
                raise NpcapError(self._error())
            # Only what arrives, like BIOCSSEESENT 0 on macOS; not every
            # adapter supports it, and what's sent isn't LLDP/CDP anyway.
            self._dll.pcap_setdirection(handle, PCAP_D_IN)
        except NpcapError:
            self.close()
            raise

    def _error(self) -> str:
        return _text(self._dll.pcap_geterr(self._handle)) if self._handle else "closed"

    def next_frame(self) -> bytes | None:
        """The next frame, or None if none arrived within READ_TIMEOUT_MS."""
        header = ctypes.POINTER(_PcapPkthdr)()
        data = ctypes.POINTER(ctypes.c_ubyte)()
        result = self._dll.pcap_next_ex(self._handle, ctypes.byref(header), ctypes.byref(data))
        if result == 1:
            return ctypes.string_at(data, header.contents.caplen)
        if result == 0:
            return None
        raise NpcapError(self._error())

    def close(self) -> None:
        if self._handle:
            self._dll.pcap_close(self._handle)
            self._handle = None
