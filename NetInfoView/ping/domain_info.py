"""DNS Check's two checks that aren't DNS: the website's TLS certificate
(trusted? for this name? when does it expire?) and the domain's registration
(registrar, created, expires), from RDAP with a WHOIS fallback for the
registries without RDAP (many country domains, .th among them)."""

from __future__ import annotations

import json
import re
import socket
import ssl
import urllib.error
from datetime import datetime, timezone

from . import ber, tls_cert, whois
from .dns_check import FAIL, INFO, NOTICE, PASS, CheckResult, Resolver
from ..https import ssl_context, urlopen

HTTPS_PORT = 443
TLS_TIMEOUT = 5.0
RDAP_URL = "https://rdap.org/domain/{}"
RDAP_TIMEOUT = 8.0
#: Days before expiry from which a certificate or registration is a notice.
CERT_WARN_DAYS = 14
DOMAIN_WARN_DAYS = 30

_O_OID = bytes.fromhex("55040a")
_CN_OID = bytes.fromhex("550403")


# -- TLS certificate -----------------------------------------------------------


def _time(der: bytes, tag: int, start: int, end: int) -> datetime:
    text = der[start:end].decode("ascii").rstrip("Z")
    if tag == 0x17:  # UTCTime: YYMMDDHHMM[SS]
        year = int(text[:2])
        text = f"{1900 + year if year >= 50 else 2000 + year}{text[2:]}"
    return datetime.strptime(text[:14].ljust(14, "0"), "%Y%m%d%H%M%S").replace(tzinfo=timezone.utc)


def _name(der: bytes, start: int, end: int) -> dict[bytes, str]:
    found: dict[bytes, str] = {}
    for _, set_start, set_end in ber.children(der, start, end):
        for _, pair_start, pair_end in ber.children(der, set_start, set_end):
            (_, oid_start, oid_end), (_, value_start, value_end) = ber.children(
                der, pair_start, pair_end)
            found.setdefault(der[oid_start:oid_end], der[value_start:value_end].decode(
                "utf-8", "replace"))
    return found


def certificate_info(der: bytes) -> tuple[str, datetime, datetime, list[str]]:
    """(issuer, not before, not after, DNS names) of a DER certificate."""
    _, cert_start, cert_end = ber.read(der)
    _, tbs_start, tbs_end = next(ber.children(der, cert_start, cert_end))
    fields = list(ber.children(der, tbs_start, tbs_end))
    if fields and fields[0][0] == 0xA0:
        fields = fields[1:]
    issuer = _name(der, fields[2][1], fields[2][2])
    (b_tag, b_start, b_end), (a_tag, a_start, a_end) = ber.children(der, fields[3][1], fields[3][2])
    common_name, alt_names = tls_cert.certificate_names(der)
    names = alt_names or ([common_name] if common_name else [])
    issuer_name = issuer.get(_O_OID) or issuer.get(_CN_OID, "")
    if issuer.get(_O_OID) and issuer.get(_CN_OID):
        issuer_name = f"{issuer[_O_OID]} ({issuer[_CN_OID]})"
    return issuer_name, _time(der, b_tag, b_start, b_end), _time(der, a_tag, a_start, a_end), names


def fetch_certificate(host: str, address: str, verify: bool,
                      timeout: float = TLS_TIMEOUT) -> bytes:
    """The server certificate `address` presents for `host` (SNI). With
    `verify`, raises ssl.SSLCertVerificationError if the system doesn't
    trust it for `host`."""
    if verify:
        context = ssl_context()
    else:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
    with socket.create_connection((address, HTTPS_PORT), timeout=timeout) as sock:
        with context.wrap_socket(sock, server_hostname=host) as tls:
            return tls.getpeercert(binary_form=True) or b""


def check_ssl(domain: str, resolver: Resolver, now: datetime | None = None) -> CheckResult:
    now = now or datetime.now(timezone.utc)
    host, addresses = domain, resolver.addresses(domain)
    if not addresses:
        host, addresses = f"www.{domain}", resolver.addresses(f"www.{domain}")
    if not addresses:
        return CheckResult("ssl", INFO, "No website (no address)",
                           details=[f"Neither {domain} nor www.{domain} has an address."])
    address = addresses[0]
    problem = ""
    try:
        der = fetch_certificate(host, address, verify=True)
    except ssl.SSLCertVerificationError as error:
        problem = error.verify_message or str(error)
        try:
            der = fetch_certificate(host, address, verify=False)
        except (OSError, ssl.SSLError):
            der = b""
    except ssl.SSLError as error:
        return CheckResult("ssl", FAIL, "TLS handshake failed",
                           details=[f"{host} ({address}): {error.reason or error}"])
    except OSError as error:
        reason = "port 443 is closed" if isinstance(error, ConnectionRefusedError) else (
            "no answer on port 443" if isinstance(error, (socket.timeout, TimeoutError))
            else str(error.strerror or error))
        return CheckResult("ssl", NOTICE, "No HTTPS", details=[f"{host} ({address}): {reason}"])
    details = [f"{host} ({address})"]
    try:
        issuer, not_before, not_after, names = certificate_info(der)
    except (ValueError, IndexError, StopIteration, UnicodeDecodeError):
        return CheckResult("ssl", FAIL if problem else NOTICE,
                           "Certificate not trusted" if problem else "Certificate unreadable",
                           details=details + ([problem] if problem else []))
    days = (not_after - now).days
    details += [f"Issuer: {issuer}",
                f"Valid {not_before:%Y-%m-%d} to {not_after:%Y-%m-%d} ({days} days left)"]
    records = [f"Names: {', '.join(names[:12])}{' …' if len(names) > 12 else ''}"] if names else []
    if problem:
        return CheckResult("ssl", FAIL, f"Not trusted: {problem}", records, details)
    if not_after < now:
        return CheckResult("ssl", FAIL, f"Expired {not_after:%Y-%m-%d}", records, details)
    if days < CERT_WARN_DAYS:
        return CheckResult("ssl", NOTICE, f"Certificate expires in {days} days", records, details)
    return CheckResult("ssl", PASS, f"Certificate expires in {days} days", records, details)


# -- registration ----------------------------------------------------------------


def _parse_date(text: str) -> datetime | None:
    text = text.strip()
    match = re.search(r"(\d{4})[-./](\d{1,2})[-./](\d{1,2})", text)
    if match:
        year, month, day = map(int, match.groups())
    else:
        match = re.search(r"(\d{1,2})[- ]([A-Za-z]{3})[a-z]*[- ,]+(\d{4})", text)
        if not match:
            return None
        try:
            month = datetime.strptime(match.group(2).title(), "%b").month
        except ValueError:
            return None
        day, year = int(match.group(1)), int(match.group(3))
    try:
        return datetime(year, month, day, tzinfo=timezone.utc)
    except ValueError:
        return None


def parse_rdap(data: dict) -> dict:
    """registrar, created, expires (datetimes), status and nameservers from
    an RDAP domain object."""
    events = {event.get("eventAction"): _parse_date(event.get("eventDate", ""))
              for event in data.get("events", [])}
    registrar = ""
    for entity in data.get("entities", []):
        if "registrar" in entity.get("roles", []):
            for item in (entity.get("vcardArray") or [None, []])[1]:
                if item and item[0] == "fn":
                    registrar = item[3]
    return {
        "registrar": registrar,
        "created": events.get("registration"),
        "expires": events.get("expiration"),
        "status": list(data.get("status", [])),
    }


_WHOIS_FIELDS = {
    "expires": r"(?:Registry Expiry Date|Registrar Registration Expiration Date|Expiration Date|"
               r"Expiry Date|Exp date|paid-till|Expiration Time|Expire Date|expires|Expiry)",
    "created": r"(?:Creation Date|Created Date|Created|Registered on|Registration Time|"
               r"registered|Domain Registration Date)",
    "registrar": r"(?:Registrar|Sponsoring Registrar|registrar name)",
}


def parse_whois(output: str) -> dict:
    found: dict = {"registrar": "", "created": None, "expires": None, "status": []}
    for key, label in _WHOIS_FIELDS.items():
        match = re.search(rf"^\s*{label}\s*:\s*(\S.*?)\s*$", output, re.IGNORECASE | re.MULTILINE)
        if match:
            found[key] = match.group(1) if key == "registrar" else _parse_date(match.group(1))
    return found


def _rdap(domain: str) -> dict | None:
    try:
        with urlopen(RDAP_URL.format(domain), RDAP_TIMEOUT) as response:
            return parse_rdap(json.loads(response.read().decode("utf-8", "replace")))
    except (urllib.error.URLError, OSError, ValueError, TimeoutError):
        return None


def lookup_registration(domain: str) -> tuple[str, dict] | None:
    """(the registered name, its data) for `domain` or the nearest parent
    that has registration data (mail.example.co.th -> example.co.th)."""
    labels = domain.split(".")
    candidates = [".".join(labels[i:]) for i in range(len(labels) - 1)]
    for name in candidates:
        data = _rdap(name)
        if data and (data["expires"] or data["registrar"]):
            return name, data
    for name in candidates:
        data = parse_whois(whois.query_direct(name))
        if data["expires"] or data["registrar"]:
            return name, data
    return None


def check_registration(domain: str, now: datetime | None = None) -> CheckResult:
    now = now or datetime.now(timezone.utc)
    found = lookup_registration(domain)
    if found is None:
        return CheckResult("whois", INFO, "Registration data not available",
                           details=["Neither RDAP nor WHOIS returned data for this domain."])
    name, data = found
    details = [f"Domain: {name}"]
    if data["registrar"]:
        details.append(f"Registrar: {data['registrar']}")
    if data["created"]:
        years = (now - data["created"]).days // 365
        details.append(f"Registered {data['created']:%Y-%m-%d}"
                       + (f" ({years} year{'s' if years != 1 else ''} ago)" if years else ""))
    if data["status"]:
        details.append(f"Status: {', '.join(data['status'][:6])}")
    expires = data["expires"]
    if expires is None:
        return CheckResult("whois", INFO, data["registrar"] or "Registered", details=details)
    days = (expires - now).days
    details.insert(1, f"Expires {expires:%Y-%m-%d}")
    if expires < now:
        return CheckResult("whois", FAIL, f"Expired {expires:%Y-%m-%d}", details=details)
    if days < DOMAIN_WARN_DAYS:
        return CheckResult("whois", NOTICE, f"Expires in {days} days", details=details)
    return CheckResult("whois", PASS, f"Expires {expires.day} {expires:%b %Y}", details=details)

