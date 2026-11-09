"""NetBIOS node-status lookups (UDP 137): the computer name a Windows PC,
Samba server, NAS or network printer announces for itself, asked of the
device directly. Used by ping/hostname.py as a last resort for hosts that
neither DNS nor mDNS can name. No dependencies, like ping/dns_ptr.py.

The same reply ends with the device's MAC address, which ping/device_info.py
uses when neither the ARP table nor an ARP scan (ping/arp_scan.py) has one
for a host, e.g. one beyond the router, or when BPF can't be opened.
"""

from __future__ import annotations

import random
import socket
import struct

NETBIOS_PORT = 137
TYPE_NBSTAT = 0x21
CLASS_IN = 1
DEFAULT_TIMEOUT = 1.0

_HEADER = struct.Struct("!HHHHHH")  # id, flags, qd, an, ns, ar counts
_RR = struct.Struct("!HHIH")  # type, class, ttl, rdlength
_NAME_ENTRY_SIZE = 18  # 15-char name, 1-byte suffix, 2-byte flags
_GROUP_FLAG = 0x8000
_WORKSTATION_SUFFIX = 0x00


def _encode_wildcard() -> bytes:
    """The wildcard name "*" in NetBIOS first-level encoding (RFC 1002)."""
    raw = b"*" + b"\0" * 15
    encoded = b"".join(bytes([0x41 + (b >> 4), 0x41 + (b & 0x0F)]) for b in raw)
    return bytes([len(encoded)]) + encoded + b"\0"


def build_query(query_id: int) -> bytes:
    header = _HEADER.pack(query_id, 0x0000, 1, 0, 0, 0)
    return header + _encode_wildcard() + struct.pack("!HH", TYPE_NBSTAT, CLASS_IN)


def _skip_name(message: bytes, offset: int) -> int:
    for _ in range(128):
        length = message[offset]
        if length & 0xC0 == 0xC0:
            return offset + 2
        offset += 1 + length
        if length == 0:
            return offset
    raise ValueError("NetBIOS name too long")


def parse_node_status_reply(message: bytes, query_id: int) -> tuple[str, str]:
    """(name, MAC) from a node-status response: the machine's own (unique,
    workstation) name and the MAC address after the name table, as
    ``AA:BB:CC:DD:EE:FF``. Either is "" if the reply doesn't hold it; an
    all-zero MAC, as Samba sends, counts as none."""
    ident, flags, _, answers, _, _ = _HEADER.unpack_from(message)
    if ident != query_id or not flags & 0x8000 or flags & 0x000F or not answers:
        return "", ""
    offset = _skip_name(message, _HEADER.size)
    rtype, _, _, _ = _RR.unpack_from(message, offset)
    if rtype != TYPE_NBSTAT:
        return "", ""
    offset += _RR.size
    count = message[offset]
    offset += 1
    name = ""
    for _ in range(count):
        entry = message[offset:offset + _NAME_ENTRY_SIZE]
        if len(entry) < _NAME_ENTRY_SIZE:
            return name, ""
        entry_name = entry[:15].decode("ascii", "replace").strip()
        suffix = entry[15]
        (name_flags,) = struct.unpack("!H", entry[16:18])
        if (not name and suffix == _WORKSTATION_SUFFIX
                and not name_flags & _GROUP_FLAG and entry_name):
            name = entry_name
        offset += _NAME_ENTRY_SIZE
    unit_id = message[offset:offset + 6]
    if len(unit_id) < 6 or not any(unit_id):
        return name, ""
    return name, ":".join(f"{byte:02X}" for byte in unit_id)


def parse_node_status(message: bytes, query_id: int) -> str:
    """The machine's own (unique, workstation) name from a node-status
    response, or "" if it holds none."""
    return parse_node_status_reply(message, query_id)[0]


def lookup(ip: str, timeout: float = DEFAULT_TIMEOUT) -> str:
    """The NetBIOS computer name `ip` reports, or "" if it doesn't answer."""
    return _query(ip, timeout)[0]


def lookup_mac(ip: str, timeout: float = DEFAULT_TIMEOUT) -> str:
    """The MAC address `ip` reports over NetBIOS, or "" if it doesn't answer
    or doesn't say (Samba usually doesn't)."""
    return _query(ip, timeout)[1]


def _query(ip: str, timeout: float) -> tuple[str, str]:
    query_id = random.randrange(1 << 16)
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.settimeout(timeout)
            sock.connect((ip, NETBIOS_PORT))
            sock.send(build_query(query_id))
            while True:
                reply = sock.recv(4096)
                if reply[:2] != struct.pack("!H", query_id):
                    continue  # not ours; wait for the real reply
                try:
                    return parse_node_status_reply(reply, query_id)
                except (ValueError, IndexError, struct.error):
                    return "", ""
    except OSError:  # includes the timeout, and an IPv6 address
        return "", ""
