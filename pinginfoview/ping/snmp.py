"""SNMP `sysName` (1.3.6.1.2.1.1.5.0): the name a printer, switch, NAS, UPS
or Linux box running snmpd was given, asked with the near-universal
read-only community "public". SNMPv1 over UDP 161, built by hand with
ping/ber.py.
"""

from __future__ import annotations

import random
import socket

from . import ber

SNMP_PORT = 161
COMMUNITY = b"public"
DEFAULT_TIMEOUT = 1.0

_SYS_NAME_OID = bytes.fromhex("2b06010201010500")  # 1.3.6.1.2.1.1.5.0
_GET_REQUEST = 0xA0
_GET_RESPONSE = 0xA2


def build_get(request_id: int, community: bytes = COMMUNITY) -> bytes:
    varbind = ber.encode(ber.SEQUENCE, ber.encode(ber.OID, _SYS_NAME_OID) + ber.encode(ber.NULL, b""))
    pdu = ber.encode(
        _GET_REQUEST,
        ber.encode_int(request_id) + ber.encode_int(0) + ber.encode_int(0)
        + ber.encode(ber.SEQUENCE, varbind),
    )
    return ber.encode(
        ber.SEQUENCE, ber.encode_int(0) + ber.encode(ber.OCTET_STRING, community) + pdu
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


def lookup(ip: str, timeout: float = DEFAULT_TIMEOUT) -> str:
    request_id = random.randrange(1, 1 << 31)
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.settimeout(timeout)
            sock.connect((ip, SNMP_PORT))
            sock.send(build_get(request_id))
            while True:
                try:
                    return parse_response(sock.recv(4096), request_id)
                except (ValueError, IndexError):
                    continue  # garbled; wait for a proper reply
    except OSError:  # includes the timeout, and an IPv6 address
        return ""
