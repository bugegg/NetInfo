"""Names off a device's TLS certificate: the admin web page of a NAS,
hypervisor, router or printer usually serves one issued to its own host
name. The certificate is read, never trusted — there is nothing to verify a
self-signed device certificate against, and only its name is wanted.
"""

from __future__ import annotations

import ipaddress
import re
import socket
import ssl
import warnings
from functools import partial

from . import ber
from .parallel import first_answer

TLS_PORTS = (443, 8443)
DEFAULT_TIMEOUT = 2.0

#: 2.5.4.3 (commonName) and 2.5.29.17 (subjectAltName).
_CN_OID = bytes.fromhex("550403")
_SAN_OID = bytes.fromhex("551d11")
_SAN_DNS_NAME = 0x82
_HOST_NAME = re.compile(r"^[A-Za-z0-9_](?:[A-Za-z0-9_-]{0,62})(?:\.[A-Za-z0-9_-]{1,63})*\.?$")
#: Placeholder names device makers put on every unit they ship.
_GENERIC_NAMES = {"localhost", "localhost.localdomain", "router", "gateway", "device", "default"}


def _context() -> ssl.SSLContext:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    try:  # old embedded devices still speak only TLS 1.0 with weak ciphers
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", DeprecationWarning)
            context.minimum_version = ssl.TLSVersion.TLSv1
        context.set_ciphers("DEFAULT:@SECLEVEL=0")
    except (ValueError, ssl.SSLError):
        pass
    return context


def open_tls(sock: socket.socket) -> ssl.SSLSocket:
    """A TLS client session over an already-connected socket."""
    return _context().wrap_socket(sock)


def plausible_host_name(name: str, ip: str) -> bool:
    """Whether `name` looks like a real host name for the device at `ip`
    rather than an address, a wildcard or a factory placeholder."""
    name = name.strip().rstrip(".")
    if not name or name.lower() in _GENERIC_NAMES or not _HOST_NAME.match(name):
        return False
    try:
        ipaddress.ip_address(name)
        return False
    except ValueError:
        return name != ip


def certificate_names(der: bytes) -> tuple[str, list[str]]:
    """(subject commonName, subjectAltName DNS names) of a DER certificate."""
    _, cert_start, cert_end = ber.read(der)
    _, tbs_start, tbs_end = next(ber.children(der, cert_start, cert_end))
    fields = list(ber.children(der, tbs_start, tbs_end))
    if fields and fields[0][0] == 0xA0:
        fields = fields[1:]  # explicit version
    # serial, signature algorithm, issuer, validity, subject, key, extensions...
    common_name = ""
    _, subject_start, subject_end = fields[4]
    for _, set_start, set_end in ber.children(der, subject_start, subject_end):
        for _, pair_start, pair_end in ber.children(der, set_start, set_end):
            (_, oid_start, oid_end), (_, value_start, value_end) = ber.children(der, pair_start, pair_end)
            if der[oid_start:oid_end] == _CN_OID:
                common_name = der[value_start:value_end].decode("utf-8", "replace")
    alt_names: list[str] = []
    for tag, start, end in fields[6:]:
        if tag != 0xA3:
            continue
        _, extensions_start, extensions_end = ber.read(der, start)
        for _, ext_start, ext_end in ber.children(der, extensions_start, extensions_end):
            parts = list(ber.children(der, ext_start, ext_end))
            if der[parts[0][1]:parts[0][2]] != _SAN_OID:
                continue
            _, value_start, _ = parts[-1]
            _, names_start, names_end = ber.read(der, value_start)
            for name_tag, name_start, name_end in ber.children(der, names_start, names_end):
                if name_tag == _SAN_DNS_NAME:
                    alt_names.append(der[name_start:name_end].decode("ascii", "replace"))
    return common_name, alt_names


def name_from_certificate(der: bytes, ip: str) -> str:
    """The best host name on a certificate, or "" if it holds none."""
    try:
        common_name, alt_names = certificate_names(der)
    except (ValueError, IndexError, StopIteration):
        return ""
    for name in [*alt_names, common_name]:
        if plausible_host_name(name, ip):
            return name.strip().rstrip(".")
    return ""


def lookup(ip: str, timeout: float = DEFAULT_TIMEOUT) -> str:
    """A host name from the certificate on the first TLS port that has one.
    The ports are tried at once: a host that drops the connections would
    otherwise cost a full timeout per port."""
    return first_answer([partial(_name_on_port, ip, port, timeout) for port in TLS_PORTS])


def _name_on_port(ip: str, port: int, timeout: float) -> str:
    try:
        with socket.create_connection((ip, port), timeout=timeout) as sock:
            with open_tls(sock) as tls:
                return name_from_certificate(tls.getpeercert(binary_form=True) or b"", ip)
    except (OSError, ssl.SSLError):
        return ""
