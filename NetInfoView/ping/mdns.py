"""Reverse lookups over mDNS (Bonjour/Avahi) and LLMNR, asked straight of
the network rather than through macOS's resolver, which often comes back
empty for these even when the device would answer.

Each is a PTR query in plain DNS format (ping/dns_ptr.py builds and parses
it), sent from an ordinary port so responders answer us with a unicast
reply — a "legacy unicast" query in mDNS terms.
"""

from __future__ import annotations

import random
import socket
import struct
import time

from . import dns_ptr

MDNS_PORT = 5353
MDNS_GROUP = "224.0.0.251"
LLMNR_PORT = 5355
DEFAULT_TIMEOUT = 1.0


def unicast_lookup(ip: str, timeout: float = DEFAULT_TIMEOUT) -> str:
    """Ask the device's own mDNS responder for its name."""
    return dns_ptr.query_ptr(ip, ip, timeout=timeout, port=MDNS_PORT)


def multicast_lookup(ip: str, timeout: float = DEFAULT_TIMEOUT) -> str:
    """Ask the whole link over the mDNS group; whichever responder owns the
    address answers. Catches devices that ignore a query sent to them
    directly but do answer one sent to the group."""
    try:
        query_id = random.randrange(1 << 16)
        query = dns_ptr.build_query(dns_ptr.reverse_name(ip), query_id)
    except ValueError:
        return ""
    deadline = time.monotonic() + timeout
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 255)
            sock.sendto(query, (MDNS_GROUP, MDNS_PORT))
            while (remaining := deadline - time.monotonic()) > 0:
                sock.settimeout(remaining)
                reply, _ = sock.recvfrom(9000)
                try:
                    name = dns_ptr.parse_ptr_answer(reply, query_id)
                except (ValueError, IndexError, struct.error):
                    continue
                if name:
                    return name.rstrip(".")
    except OSError:  # includes the timeout
        pass
    return ""


def llmnr_lookup(ip: str, timeout: float = DEFAULT_TIMEOUT) -> str:
    """Ask the device over LLMNR (Windows' successor to NetBIOS names);
    reverse LLMNR queries go to the address itself (RFC 4795 §2.4)."""
    return dns_ptr.query_ptr(ip, ip, timeout=timeout, port=LLMNR_PORT)
