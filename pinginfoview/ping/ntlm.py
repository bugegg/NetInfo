"""The computer name a Windows (or Samba, or macOS) machine gives away in an
NTLM challenge, before any login: start an NTLM authentication over SMB
(TCP 445) or RDP (TCP 3389) and read the name out of the server's reply,
then hang up. Works where NetBIOS (UDP 137) is firewalled, as it is by
default on recent Windows. No dependencies.
"""

from __future__ import annotations

import os
import socket
import ssl
import struct

from . import ber
from .tls_cert import name_from_certificate, open_tls

SMB_PORT = 445
RDP_PORT = 3389
DEFAULT_TIMEOUT = 2.0

_SIGNATURE = b"NTLMSSP\0"
_CHALLENGE = _SIGNATURE + struct.pack("<I", 2)
#: Unicode, request target, NTLM, always sign, extended session security,
#: target info, 128-bit, key exchange, 56-bit — what Windows clients send.
_NEGOTIATE_FLAGS = 0xE0088297
_AV_NB_COMPUTER = 1
_AV_DNS_COMPUTER = 3

#: 1.3.6.1.5.5.2 (SPNEGO) and 1.3.6.1.4.1.311.2.2.10 (NTLMSSP).
_SPNEGO_OID = bytes.fromhex("2b0601050502")
_NTLMSSP_OID = bytes.fromhex("2b06010401823702020a")

_SMB2_HEADER = struct.Struct("<4sHHIHHIIQIIQ16s")
_SMB2_NEGOTIATE = 0
_SMB2_SESSION_SETUP = 1
_SMB2_DIALECTS = (0x0202, 0x0210, 0x0300, 0x0302)

_RDP_PROTOCOL_SSL = 0x1
_RDP_PROTOCOL_HYBRID = 0x2


def negotiate_message() -> bytes:
    """An NTLM NEGOTIATE with no domain or workstation."""
    return _SIGNATURE + struct.pack("<II", 1, _NEGOTIATE_FLAGS) + b"\0" * 16


def parse_challenge(blob: bytes) -> str:
    """The computer name in the NTLM CHALLENGE somewhere inside `blob` (its
    DNS name if it has one, else its NetBIOS name), or ""."""
    start = blob.find(_CHALLENGE)
    if start < 0:
        return ""
    message = blob[start:]
    if len(message) < 48:
        return ""
    info_length, _, info_offset = struct.unpack_from("<HHI", message, 40)
    info = message[info_offset:info_offset + info_length]
    names: dict[int, str] = {}
    offset = 0
    while offset + 4 <= len(info):
        av_id, av_length = struct.unpack_from("<HH", info, offset)
        offset += 4
        if av_id == 0:
            break
        names[av_id] = info[offset:offset + av_length].decode("utf-16-le", "replace")
        offset += av_length
    return names.get(_AV_DNS_COMPUTER) or names.get(_AV_NB_COMPUTER) or ""


def _spnego_init(token: bytes) -> bytes:
    mech_types = ber.encode(0xA0, ber.encode(ber.SEQUENCE, ber.encode(ber.OID, _NTLMSSP_OID)))
    mech_token = ber.encode(0xA2, ber.encode(ber.OCTET_STRING, token))
    init = ber.encode(0xA0, ber.encode(ber.SEQUENCE, mech_types + mech_token))
    return ber.encode(0x60, ber.encode(ber.OID, _SPNEGO_OID) + init)


def _recv_exact(sock: socket.socket, count: int) -> bytes:
    data = b""
    while len(data) < count:
        chunk = sock.recv(count - len(data))
        if not chunk:
            raise ConnectionError("connection closed")
        data += chunk
    return data


def _smb2(command: int, message_id: int, body: bytes) -> bytes:
    header = _SMB2_HEADER.pack(
        b"\xfeSMB", 64, 0, 0, command, 1, 0, 0, message_id, 0, 0, 0, b"\0" * 16
    )
    packet = header + body
    return struct.pack(">I", len(packet)) + packet  # direct-TCP framing


def _smb2_exchange(sock: socket.socket, packet: bytes) -> bytes:
    sock.sendall(packet)
    (length,) = struct.unpack(">I", _recv_exact(sock, 4))
    return _recv_exact(sock, length & 0xFFFFFF)


def smb_lookup(ip: str, timeout: float = DEFAULT_TIMEOUT) -> str:
    """The computer name from an SMB2 session setup's NTLM challenge."""
    negotiate = struct.pack(
        "<HHHHI16sQ", 36, len(_SMB2_DIALECTS), 1, 0, 0, os.urandom(16), 0
    ) + b"".join(struct.pack("<H", d) for d in _SMB2_DIALECTS)
    token = _spnego_init(negotiate_message())
    setup = struct.pack("<HBBIIHHQ", 25, 0, 1, 0, 0, 64 + 24, len(token), 0) + token
    try:
        with socket.create_connection((ip, SMB_PORT), timeout=timeout) as sock:
            reply = _smb2_exchange(sock, _smb2(_SMB2_NEGOTIATE, 0, negotiate))
            if reply[:4] != b"\xfeSMB":
                return ""  # SMB1-only, or not SMB at all
            reply = _smb2_exchange(sock, _smb2(_SMB2_SESSION_SETUP, 1, setup))
            return parse_challenge(reply)
    except (OSError, ValueError, struct.error):
        return ""


def _x224_connection_request(protocols: int) -> bytes:
    negotiation = struct.pack("<BBHI", 0x01, 0, 8, protocols)
    x224 = bytes([6 + len(negotiation), 0xE0, 0, 0, 0, 0, 0]) + negotiation
    return struct.pack(">BBH", 3, 0, 4 + len(x224)) + x224


def _ts_request(token: bytes) -> bytes:
    """A CredSSP TSRequest carrying one SPNEGO-less NTLM token."""
    nego_data = ber.encode(ber.SEQUENCE, ber.encode(
        ber.SEQUENCE, ber.encode(0xA0, ber.encode(ber.OCTET_STRING, token))
    ))
    return ber.encode(ber.SEQUENCE, ber.encode(0xA0, ber.encode_int(2)) + ber.encode(0xA1, nego_data))


def rdp_lookup(ip: str, timeout: float = DEFAULT_TIMEOUT) -> str:
    """The computer name from RDP: the NTLM challenge of its Network Level
    Authentication if it uses NLA, else the name on its TLS certificate."""
    try:
        with socket.create_connection((ip, RDP_PORT), timeout=timeout) as sock:
            sock.sendall(_x224_connection_request(_RDP_PROTOCOL_SSL | _RDP_PROTOCOL_HYBRID))
            tpkt = _recv_exact(sock, 4)
            (length,) = struct.unpack(">H", tpkt[2:4])
            confirm = _recv_exact(sock, length - 4)
            if len(confirm) < 15 or confirm[7] != 0x02:
                return ""  # no negotiation response, or a failure code
            (selected,) = struct.unpack_from("<I", confirm, 11)
            if not selected & (_RDP_PROTOCOL_SSL | _RDP_PROTOCOL_HYBRID):
                return ""  # legacy RDP security: no TLS, no NTLM
            with open_tls(sock) as tls:
                cert_name = name_from_certificate(tls.getpeercert(binary_form=True) or b"", ip)
                if not selected & _RDP_PROTOCOL_HYBRID:
                    return cert_name
                tls.sendall(_ts_request(negotiate_message()))
                reply = b""
                while _CHALLENGE not in reply and len(reply) < 16384:
                    chunk = tls.recv(4096)
                    if not chunk:
                        break
                    reply += chunk
                return parse_challenge(reply) or cert_name
    except (OSError, ssl.SSLError, ValueError, struct.error):
        return ""
