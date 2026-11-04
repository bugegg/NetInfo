"""MAC addresses of hosts beyond the local link, read from a router's ARP
table over SNMP (ipNetToMediaPhysAddress, 1.3.6.1.2.1.4.22.1.2).

The Mac's own ARP table (ping/arp.py) only knows its own LAN, so a host
behind a router or a VPN never shows a MAC. The router that is that host's
gateway does know it, and a switch or router with SNMP read access (the
community in Settings.snmp_community) will hand the whole table over.
SNMPv2c GETBULK over UDP 161, built by hand with ping/ber.py like
ping/snmp.py; no dependencies.

Like ping/arp.py the tables are cached for a while: a sweep asks about many
hosts at once and one walk answers them all.
"""

from __future__ import annotations

import ipaddress
import random
import re
import socket
import time

from . import ber

SNMP_PORT = 161
DEFAULT_TIMEOUT = 2.0
#: Rows asked for per GETBULK: ~30 bytes each, so a reply stays one datagram.
MAX_REPETITIONS = 40
#: A walk gives up after this many requests (MAX_REPETITIONS rows each).
MAX_REQUESTS = 500
_CACHE_TTL_SECONDS = 60.0
#: A router that didn't answer (no SNMP, wrong community, not a router at
#: all) is left alone for longer, so a guessed one isn't asked every sweep.
_FAILED_TTL_SECONDS = 600.0
#: The host numbers a network's gateway usually has, in the order tried.
GATEWAY_HOSTS = (254, 1)

#: ipNetToMediaPhysAddress; each row's index is <ifIndex>.<a>.<b>.<c>.<d>.
ARP_TABLE_OID = (1, 3, 6, 1, 2, 1, 4, 22, 1, 2)

_VERSION_2C = 1
_GET_BULK = 0xA5
_GET_RESPONSE = 0xA2
#: Exception values a GETBULK may return in place of a value.
_NO_MORE = (0x80, 0x81, 0x82)  # noSuchObject, noSuchInstance, endOfMibView

_cache: dict[tuple[str, str], tuple[float, dict[str, str]]] = {}


def parse_routers(text: str) -> list[str]:
    """The router addresses in a comma/space-separated list, in order."""
    return [part for part in re.split(r"[\s,;]+", text) if part]


def guess_gateways(ips: list[str]) -> list[str]:
    """The likely gateways of the /24 each of `ips` is in (.254, then .1),
    for when no router is configured: the usual places a router sits."""
    gateways: list[str] = []
    for ip in ips:
        try:
            network = ipaddress.ip_network(f"{ip}/24", strict=False)
        except ValueError:
            continue
        if network.version != 4:
            continue
        for host in GATEWAY_HOSTS:
            gateway = str(network.network_address + host)
            if gateway != ip and gateway not in gateways:
                gateways.append(gateway)
    return gateways


def encode_oid(oid: tuple[int, ...]) -> bytes:
    raw = bytearray([oid[0] * 40 + oid[1]])
    for part in oid[2:]:
        chunk = [part & 0x7F]
        part >>= 7
        while part:
            chunk.append(0x80 | (part & 0x7F))
            part >>= 7
        raw.extend(reversed(chunk))
    return bytes(raw)


def decode_oid(raw: bytes) -> tuple[int, ...]:
    first = raw[0]
    oid = [min(first // 40, 2), first - 40 * min(first // 40, 2)]
    value = 0
    for byte in raw[1:]:
        value = (value << 7) | (byte & 0x7F)
        if not byte & 0x80:
            oid.append(value)
            value = 0
    return tuple(oid)


def build_get_bulk(request_id: int, oid: tuple[int, ...], community: bytes) -> bytes:
    varbind = ber.encode(ber.SEQUENCE, ber.encode(ber.OID, encode_oid(oid)) + ber.encode(ber.NULL, b""))
    pdu = ber.encode(
        _GET_BULK,
        ber.encode_int(request_id) + ber.encode_int(0) + ber.encode_int(MAX_REPETITIONS)
        + ber.encode(ber.SEQUENCE, varbind),
    )
    return ber.encode(
        ber.SEQUENCE,
        ber.encode_int(_VERSION_2C) + ber.encode(ber.OCTET_STRING, community) + pdu,
    )


def parse_response(message: bytes, request_id: int) -> list[tuple[tuple[int, ...], int, bytes]] | None:
    """Each (OID, value tag, value) in a GetResponse, or None if it isn't
    the answer to `request_id` or reports an error."""
    _, start, end = ber.read(message)
    _, _, (pdu_tag, pdu_start, pdu_end) = list(ber.children(message, start, end))[:3]
    if pdu_tag != _GET_RESPONSE:
        return None
    (_, id_start, id_end), (_, err_start, err_end), _, (_, binds_start, binds_end) = (
        list(ber.children(message, pdu_start, pdu_end))
    )
    if ber.decode_int(message, id_start, id_end) != request_id:
        return None
    if ber.decode_int(message, err_start, err_end) != 0:
        return None
    binds = []
    for _, bind_start, bind_end in ber.children(message, binds_start, binds_end):
        (_, oid_start, oid_end), (value_tag, value_start, value_end) = (
            ber.children(message, bind_start, bind_end)
        )
        binds.append((decode_oid(message[oid_start:oid_end]), value_tag, message[value_start:value_end]))
    return binds


def _request(sock: socket.socket, oid: tuple[int, ...], community: bytes):
    """One GETBULK from `oid`, sent up to twice; None if nothing answers."""
    for _ in range(2):
        request_id = random.randrange(1, 1 << 31)
        sock.send(build_get_bulk(request_id, oid, community))
        try:
            while True:
                try:
                    binds = parse_response(sock.recv(65535), request_id)
                except (ValueError, IndexError):
                    continue  # garbled; wait for a proper reply
                if binds is not None:
                    return binds
        except socket.timeout:
            continue
    return None


def walk(router: str, community: str, timeout: float = DEFAULT_TIMEOUT) -> dict[str, str]:
    """{IP: MAC} from `router`'s ARP table, or {} if it doesn't answer."""
    table: dict[str, str] = {}
    oid = ARP_TABLE_OID
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.settimeout(timeout)
            sock.connect((router, SNMP_PORT))
            for _ in range(MAX_REQUESTS):
                binds = _request(sock, oid, community.encode())
                if not binds:
                    break
                for bind_oid, tag, value in binds:
                    if bind_oid[:len(ARP_TABLE_OID)] != ARP_TABLE_OID or tag in _NO_MORE:
                        return table  # walked off the end of the table
                    if bind_oid <= oid:
                        return table  # an agent going round in circles
                    oid = bind_oid
                    if tag == ber.OCTET_STRING and len(value) == 6 and len(bind_oid) >= 4:
                        ip = ".".join(map(str, bind_oid[-4:]))
                        table[ip] = ":".join(f"{b:02X}" for b in value)
    except OSError:  # includes an IPv6 or unresolvable router address
        pass
    return table


def table(router: str, community: str) -> dict[str, str]:
    """walk(), cached for _CACHE_TTL_SECONDS per router and community."""
    key = (router, community)
    loaded_at, cached = _cache.get(key, (0.0, {}))
    ttl = _CACHE_TTL_SECONDS if cached else _FAILED_TTL_SECONDS
    if not loaded_at or time.monotonic() - loaded_at > ttl:
        cached = walk(router, community)
        _cache[key] = (time.monotonic(), cached)
    return cached


def lookup_many(ips: list[str], routers: list[str], community: str) -> dict[str, str]:
    """{IP: MAC} for each of `ips` that any of `routers` has an entry for;
    the first router listed wins. A router is only walked if some IP is
    still missing by the time it's reached."""
    found: dict[str, str] = {}
    for router in routers:
        missing = [ip for ip in ips if ip not in found]
        if not missing:
            break
        entries = table(router, community)
        found.update((ip, entries[ip]) for ip in missing if ip in entries)
    return found
