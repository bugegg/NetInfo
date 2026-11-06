"""SNMP `sysName` (1.3.6.1.2.1.1.5.0): the name a printer, switch, NAS, UPS
or Linux box running snmpd was given, asked with the community from
Settings (set_community) and, if that's another, the near-universal
read-only "public". SNMPv2c and v1 are asked at once, since plenty of gear
(HP V1910 / Comware among it) only answers one of them. UDP 161, built by
hand with ping/ber.py.
"""

from __future__ import annotations

import random
import socket
import time

from . import ber

SNMP_PORT = 161
COMMUNITY = b"public"
DEFAULT_TIMEOUT = 1.0
VERSION_1, VERSION_2C = 0, 1

#: The community from Settings (snmp_community); see set_community.
_community = COMMUNITY


def set_community(community: str) -> None:
    """Use `community` (Settings' SNMP community) as well as "public"."""
    global _community
    _community = community.encode() if community else COMMUNITY


def communities() -> list[bytes]:
    return [_community] + ([COMMUNITY] if _community != COMMUNITY else [])

_SYS_NAME_OID = bytes.fromhex("2b06010201010500")  # 1.3.6.1.2.1.1.5.0
_GET_REQUEST = 0xA0
_GET_RESPONSE = 0xA2


def build_get(request_id: int, community: bytes = COMMUNITY, version: int = VERSION_1) -> bytes:
    varbind = ber.encode(ber.SEQUENCE, ber.encode(ber.OID, _SYS_NAME_OID) + ber.encode(ber.NULL, b""))
    pdu = ber.encode(
        _GET_REQUEST,
        ber.encode_int(request_id) + ber.encode_int(0) + ber.encode_int(0)
        + ber.encode(ber.SEQUENCE, varbind),
    )
    return ber.encode(
        ber.SEQUENCE, ber.encode_int(version) + ber.encode(ber.OCTET_STRING, community) + pdu
    )


def parse_response(message: bytes, request_id: int) -> str:
    """The sysName string in a GetResponse, or "" for an error or no value."""
    _, start, end = ber.read(message)
    _, _, (pdu_tag, pdu_start, pdu_end) = list(ber.children(message, start, end))[:3]
    if pdu_tag != _GET_RESPONSE:
        return ""
    (_, id_start, id_end), (_, err_start, err_end), _, (_, binds_start, binds_end) = (
        list(ber.children(message, pdu_start, pdu_end))
    )
    if ber.decode_int(message, id_start, id_end) != request_id:
        return ""
    if ber.decode_int(message, err_start, err_end) != 0:
        return ""
    for _, bind_start, bind_end in ber.children(message, binds_start, binds_end):
        _, (value_tag, value_start, value_end) = ber.children(message, bind_start, bind_end)
        if value_tag == ber.OCTET_STRING:
            return message[value_start:value_end].decode("utf-8", "replace").strip()
    return ""


def _request_id(message: bytes) -> int:
    _, start, end = ber.read(message)
    _, _, (_, pdu_start, pdu_end) = list(ber.children(message, start, end))[:3]
    _, id_start, id_end = next(ber.children(message, pdu_start, pdu_end))
    return ber.decode_int(message, id_start, id_end)


def lookup(ip: str, timeout: float = DEFAULT_TIMEOUT) -> str:
    """sysName, from whichever request (each community, v2c and v1) is
    answered first with a name; "" if none is within `timeout`."""
    requests = [
        (random.randrange(1, 1 << 31), community, version)
        for community in communities() for version in (VERSION_2C, VERSION_1)
    ]
    ids = {request_id for request_id, _, _ in requests}
    deadline = time.monotonic() + timeout
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.connect((ip, SNMP_PORT))
            for request_id, community, version in requests:
                sock.send(build_get(request_id, community, version))
            while ids:
                left = deadline - time.monotonic()
                if left <= 0:
                    return ""
                sock.settimeout(left)
                message = sock.recv(4096)
                try:
                    request_id = _request_id(message)
                    if request_id not in ids:
                        continue
                    ids.discard(request_id)
                    name = parse_response(message, request_id)
                except (ValueError, IndexError, StopIteration):
                    continue  # garbled; wait for a proper reply
                if name:
                    return name
            return ""
    except OSError:  # includes the timeout, and an IPv6 address
        return ""
