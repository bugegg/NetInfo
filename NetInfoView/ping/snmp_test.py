"""Test SNMP: ask one host for its MIB-II "system" group (name, description,
uptime, contact, location) with a given community, to check that SNMP is
on and the community is right. One GET over UDP 161, built by hand with
ping/ber.py like ping/snmp.py and ping/snmp_arp.py.
"""

from __future__ import annotations

import random
import socket
import time
from dataclasses import dataclass, field

from . import ber
from .snmp_arp import decode_oid, encode_oid

SNMP_PORT = 161
DEFAULT_TIMEOUT = 2.0
#: Tries per version before it counts as no answer.
ATTEMPTS = 2

VERSION_1, VERSION_2C = 0, 1
VERSION_NAMES = {VERSION_1: "v1", VERSION_2C: "v2c"}

#: The MIB-II system group (1.3.6.1.2.1.1.x.0), in the order shown.
SYSTEM_OIDS: tuple[tuple[str, tuple[int, ...]], ...] = (
    ("Name", (1, 3, 6, 1, 2, 1, 1, 5, 0)),
    ("Description", (1, 3, 6, 1, 2, 1, 1, 1, 0)),
    ("Object ID", (1, 3, 6, 1, 2, 1, 1, 2, 0)),
    ("Uptime", (1, 3, 6, 1, 2, 1, 1, 3, 0)),
    ("Contact", (1, 3, 6, 1, 2, 1, 1, 4, 0)),
    ("Location", (1, 3, 6, 1, 2, 1, 1, 6, 0)),
)

_GET_REQUEST = 0xA0
_GET_RESPONSE = 0xA2
_IP_ADDRESS, _COUNTER32, _GAUGE32, _TIMETICKS, _COUNTER64 = 0x40, 0x41, 0x42, 0x43, 0x46
_NO_VALUE = {0x80: "(no such object)", 0x81: "(no such instance)", 0x82: "(end of MIB view)"}
_ERRORS = {1: "tooBig", 2: "noSuchName", 3: "badValue", 4: "readOnly", 5: "genErr"}


@dataclass
class SnmpResult:
    ip: str
    community: str
    #: The version that answered, or the last one tried when none did.
    version: int = VERSION_2C
    ok: bool = False
    #: Why there's no answer, when not ok.
    error: str = ""
    elapsed_ms: float = 0.0
    values: list[tuple[str, str]] = field(default_factory=list)
    #: The versions asked, in order ("v2c", "v1").
    tried: list[str] = field(default_factory=list)


def build_get(request_id: int, oids: list[tuple[int, ...]], community: bytes,
              version: int) -> bytes:
    binds = b"".join(
        ber.encode(ber.SEQUENCE, ber.encode(ber.OID, encode_oid(oid)) + ber.encode(ber.NULL, b""))
        for oid in oids
    )
    pdu = ber.encode(
        _GET_REQUEST,
        ber.encode_int(request_id) + ber.encode_int(0) + ber.encode_int(0)
        + ber.encode(ber.SEQUENCE, binds),
    )
    return ber.encode(
        ber.SEQUENCE,
        ber.encode_int(version) + ber.encode(ber.OCTET_STRING, community) + pdu,
    )


def format_uptime(ticks: int) -> str:
    """TimeTicks (hundredths of a second) as "12 days, 03:04:05"."""
    seconds = ticks // 100
    days, rest = divmod(seconds, 86400)
    hours, rest = divmod(rest, 3600)
    minutes, seconds = divmod(rest, 60)
    clock = f"{hours:02}:{minutes:02}:{seconds:02}"
    if days:
        return f"{days} day{'s' if days != 1 else ''}, {clock}"
    return clock


def format_value(tag: int, raw: bytes) -> str:
    if tag in _NO_VALUE:
        return _NO_VALUE[tag]
    if tag == ber.OCTET_STRING:
        text = raw.decode("utf-8", "replace")
        if all(ch.isprintable() or ch in "\r\n\t" for ch in text):
            return text.strip()
        return raw.hex(":")
    if tag == ber.OID:
        return ".".join(str(part) for part in decode_oid(raw)) if raw else ""
    if tag == _TIMETICKS:
        return format_uptime(int.from_bytes(raw, "big"))
    if tag == _IP_ADDRESS and len(raw) == 4:
        return ".".join(str(b) for b in raw)
    if tag in (_COUNTER32, _GAUGE32, _COUNTER64):
        return str(int.from_bytes(raw, "big"))
    if tag == ber.INTEGER:
        return str(int.from_bytes(raw, "big", signed=True))
    if tag == ber.NULL:
        return ""
    return raw.hex(":")


def parse_response(message: bytes, request_id: int) -> tuple[int, list[tuple[tuple[int, ...], int, bytes]]] | None:
    """(error status, each (OID, tag, value)) of the GetResponse to
    `request_id`, or None if this message isn't it."""
    _, start, end = ber.read(message)
    _, _, (pdu_tag, pdu_start, pdu_end) = list(ber.children(message, start, end))[:3]
    if pdu_tag != _GET_RESPONSE:
        return None
    (_, id_start, id_end), (_, err_start, err_end), _, (_, binds_start, binds_end) = (
        list(ber.children(message, pdu_start, pdu_end))
    )
    if ber.decode_int(message, id_start, id_end) != request_id:
        return None
    binds = []
    for _, bind_start, bind_end in ber.children(message, binds_start, binds_end):
        (_, oid_start, oid_end), (tag, value_start, value_end) = (
            ber.children(message, bind_start, bind_end)
        )
        binds.append((decode_oid(message[oid_start:oid_end]), tag, message[value_start:value_end]))
    return ber.decode_int(message, err_start, err_end), binds


def _ask(ip: str, community: str, version: int, timeout: float, port: int) -> SnmpResult:
    result = SnmpResult(ip=ip, community=community, version=version)
    oids = [oid for _, oid in SYSTEM_OIDS]
    labels = {oid: label for label, oid in SYSTEM_OIDS}
    started = time.monotonic()
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.settimeout(timeout)
            sock.connect((ip, port))
            for _ in range(ATTEMPTS):
                request_id = random.randrange(1, 1 << 31)
                started = time.monotonic()
                sock.send(build_get(request_id, oids, community.encode(), version))
                try:
                    while True:
                        try:
                            answer = parse_response(sock.recv(65535), request_id)
                        except (ValueError, IndexError):
                            continue  # garbled; wait for a proper reply
                        if answer is not None:
                            break
                except socket.timeout:
                    continue
                result.elapsed_ms = (time.monotonic() - started) * 1000
                status, binds = answer
                if status:
                    result.error = f"The agent answered with an error: {_ERRORS.get(status, status)}"
                    return result
                result.ok = True
                result.values = [(labels.get(oid, ".".join(map(str, oid))), format_value(tag, raw))
                                 for oid, tag, raw in binds]
                return result
    except ConnectionRefusedError:
        result.error = "Port UDP 161 is closed (ICMP port unreachable): SNMP is not running"
        return result
    except OSError as error:
        result.error = f"Could not send: {error.strerror or error}"
        return result
    result.error = (
        "No answer: SNMP is off, the community is wrong, "
        "or an ACL doesn't allow this computer"
    )
    return result


def query_system(ip: str, community: str, version: int | None = None,
                 timeout: float = DEFAULT_TIMEOUT, port: int = SNMP_PORT) -> SnmpResult:
    """Ask `ip` for its system group. `version` None tries v2c, then v1."""
    versions = [version] if version is not None else [VERSION_2C, VERSION_1]
    result = SnmpResult(ip=ip, community=community)
    for each in versions:
        result = _ask(ip, community, each, timeout, port)
        result.tried = [VERSION_NAMES[v] for v in versions[:versions.index(each) + 1]]
        if result.ok or "closed" in result.error or "Could not send" in result.error:
            return result
    return result


def format_result(result: SnmpResult) -> str:
    """The result as the "Field: value" text shown in the window."""
    version = VERSION_NAMES.get(result.version, str(result.version))
    if not result.ok:
        tried = " and ".join(result.tried) or version
        return f"✗ {result.ip} — {result.error}\n  (community \"{result.community}\", tried SNMP {tried})"
    lines = [f"✓ {result.ip} answered SNMP{version} in {result.elapsed_ms:.0f} ms", ""]
    width = max(len(label) for label, _ in result.values) + 1 if result.values else 0
    for label, value in result.values:
        first, *rest = value.splitlines() or [""]
        lines.append(f"{label + ':':<{width}} {first}")
        lines += [f"{'':<{width}} {line}" for line in rest]
    return "\n".join(lines)
