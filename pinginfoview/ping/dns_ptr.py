"""Reverse-DNS (PTR) lookups asked of the DNS servers this Mac uses.

Fills the DNS Name column: unlike the Hostname column (ping/hostname.py),
which also takes names from Bonjour/mDNS and /etc/hosts, this is only what
DNS itself says — the name the network's DNS (an Active Directory or router
DNS holding the DHCP leases, say) has registered for the address. The
servers are the system's own, as `scutil --dns` lists them, so a VPN that
brings its own DNS is used while it's up. Speaks just enough DNS over UDP to
ask for a PTR record, with no dependencies.
"""

from __future__ import annotations

import ipaddress
import random
import re
import socket
import struct
import subprocess
import time

DNS_PORT = 53
TYPE_PTR = 12
CLASS_IN = 1
DEFAULT_TIMEOUT = 2.0
#: How long the system's server list is reused before asking again, so a
#: network or VPN change is noticed without running scutil for every host.
SERVERS_TTL_SECONDS = 30

_NAMESERVER = re.compile(r"^\s*nameserver\[\d+\]\s*:\s*(\S+)", re.MULTILINE)
_servers_cache: tuple[float, list[str]] = (0.0, [])

_HEADER = struct.Struct("!HHHHHH")  # id, flags, qd, an, ns, ar counts
_RR = struct.Struct("!HHIH")  # type, class, ttl, rdlength


def reverse_name(ip: str) -> str:
    """``192.168.1.5`` -> ``5.1.168.192.in-addr.arpa`` (IPv6 too)."""
    return ipaddress.ip_address(ip).reverse_pointer


def build_query(name: str, query_id: int) -> bytes:
    # Flags 0x0100: a standard query with recursion desired.
    header = _HEADER.pack(query_id, 0x0100, 1, 0, 0, 0)
    labels = b"".join(
        bytes([len(part)]) + part.encode("ascii") for part in name.rstrip(".").split(".")
    )
    return header + labels + b"\0" + struct.pack("!HH", TYPE_PTR, CLASS_IN)


def _read_name(message: bytes, offset: int) -> tuple[str, int]:
    """A possibly-compressed name at `offset`, and the offset just past it."""
    labels: list[str] = []
    end: int | None = None
    for _ in range(128):  # bounds a malicious pointer loop
        length = message[offset]
        if length & 0xC0 == 0xC0:  # pointer to a name elsewhere
            if end is None:
                end = offset + 2
            offset = ((length & 0x3F) << 8) | message[offset + 1]
            continue
        offset += 1
        if length == 0:
            return ".".join(labels), offset if end is None else end
        labels.append(message[offset:offset + length].decode("ascii", "replace"))
        offset += length
    raise ValueError("DNS name too long or looping")


def parse_ptr_answer(message: bytes, query_id: int) -> str:
    """The first PTR name in a response, or "" if it holds none."""
    ident, flags, questions, answers, _, _ = _HEADER.unpack_from(message)
    if ident != query_id or not flags & 0x8000 or flags & 0x000F:
        return ""  # not our reply, not a reply, or an error (e.g. NXDOMAIN)
    offset = _HEADER.size
    for _ in range(questions):
        _, offset = _read_name(message, offset)
        offset += 4  # qtype, qclass
    for _ in range(answers):
        _, offset = _read_name(message, offset)
        rtype, _, _, length = _RR.unpack_from(message, offset)
        offset += _RR.size
        if rtype == TYPE_PTR:
            name, _ = _read_name(message, offset)
            return name
        offset += length
    return ""


def query_ptr(
    ip: str, server: str, timeout: float = DEFAULT_TIMEOUT, port: int | None = None
) -> str:
    """The name `server` holds for `ip`, or "" if it has none or doesn't
    answer in time. `port` defaults to DNS_PORT; 5353 asks a device's own
    mDNS responder directly (a "legacy unicast" query)."""
    try:
        name = reverse_name(ip)
        family = socket.AF_INET6 if ipaddress.ip_address(server).version == 6 else socket.AF_INET
    except ValueError:
        return ""
    query_id = random.randrange(1 << 16)
    try:
        with socket.socket(family, socket.SOCK_DGRAM) as sock:
            sock.settimeout(timeout)
            sock.connect((server, DNS_PORT if port is None else port))
            sock.send(build_query(name, query_id))
            while True:
                reply = sock.recv(4096)
                try:
                    found = parse_ptr_answer(reply, query_id)
                except (ValueError, IndexError, struct.error):
                    continue  # garbled; wait for a proper reply
                if reply[:2] == struct.pack("!H", query_id):
                    return found.rstrip(".")
    except OSError:  # includes the timeout
        return ""


def parse_scutil_nameservers(output: str) -> list[str]:
    """Nameservers from `scutil --dns`, in order, without repeats. Only the
    main section counts: the scoped one repeats the same servers per
    interface."""
    main = output.split("DNS configuration (for scoped queries)")[0]
    servers: list[str] = []
    for server in _NAMESERVER.findall(main):
        if server not in servers:
            servers.append(server)
    return servers


def system_nameservers() -> list[str]:
    """The DNS servers macOS is using right now (briefly cached)."""
    global _servers_cache
    fetched_at, servers = _servers_cache
    if servers and time.monotonic() - fetched_at < SERVERS_TTL_SECONDS:
        return servers
    try:
        output = subprocess.run(
            ["/usr/sbin/scutil", "--dns"], capture_output=True, text=True, timeout=3
        ).stdout
        servers = parse_scutil_nameservers(output)
    except (OSError, subprocess.SubprocessError):
        servers = []
    if not servers:  # not macOS, or scutil failed
        try:
            with open("/etc/resolv.conf", encoding="utf-8") as handle:
                servers = parse_scutil_nameservers(
                    "\n".join(
                        f"nameserver[{i}] : {line.split()[1]}"
                        for i, line in enumerate(handle)
                        if line.startswith("nameserver") and len(line.split()) > 1
                    )
                )
        except OSError:
            servers = []
    _servers_cache = (time.monotonic(), servers)
    return servers


def lookup(ip: str, servers: list[str] | None = None) -> str:
    """The DNS name for `ip` from the first of `servers` (default: the
    system's) that has one, or ""."""
    for server in system_nameservers() if servers is None else servers:
        name = query_ptr(ip, server)
        if name:
            return name
    return ""
