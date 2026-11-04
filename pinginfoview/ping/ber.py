"""Just enough ASN.1 BER/DER to build and walk the few messages the hostname
probes need: SNMP (ping/snmp.py), SPNEGO and CredSSP wrappers around NTLM
(ping/ntlm.py) and X.509 certificates (ping/tls_cert.py). No dependencies.
"""

from __future__ import annotations

from collections.abc import Iterator

SEQUENCE = 0x30
OCTET_STRING = 0x04
INTEGER = 0x02
OID = 0x06
NULL = 0x05


def encode(tag: int, content: bytes) -> bytes:
    """One TLV, with a short- or long-form length as needed."""
    length = len(content)
    if length < 0x80:
        return bytes([tag, length]) + content
    raw = length.to_bytes((length.bit_length() + 7) // 8, "big")
    return bytes([tag, 0x80 | len(raw)]) + raw + content


def encode_int(value: int) -> bytes:
    raw = value.to_bytes(max(1, (value.bit_length() + 8) // 8), "big", signed=True)
    return encode(INTEGER, raw)


def read(data: bytes, offset: int = 0) -> tuple[int, int, int]:
    """The TLV at `offset`: (tag, start of its value, end of its value)."""
    tag = data[offset]
    length = data[offset + 1]
    offset += 2
    if length & 0x80:
        count = length & 0x7F
        if not count or count > 4:
            raise ValueError("unsupported BER length")
        length = int.from_bytes(data[offset:offset + count], "big")
        offset += count
    end = offset + length
    if end > len(data):
        raise ValueError("BER value runs past the end of the data")
    return tag, offset, end


def children(data: bytes, start: int, end: int) -> Iterator[tuple[int, int, int]]:
    """Each TLV directly inside the constructed value data[start:end]."""
    offset = start
    while offset < end:
        tag, value_start, value_end = read(data, offset)
        yield tag, value_start, value_end
        offset = value_end


def decode_int(data: bytes, start: int, end: int) -> int:
    return int.from_bytes(data[start:end], "big", signed=True)
