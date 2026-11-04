"""Who an IP address is registered to: the ``netname`` its regional registry
(APNIC, ARIN, RIPE, ...) has on file, such as "GOOGLE" or "AWN-CO-LTD-TH".

Used where an address has no name of its own, e.g. a router on the way to a
host that has no PTR record, so the row still says whose network it is in.
Drives the system's ``/usr/bin/whois``, which follows IANA's referral to the
right registry by itself. Windows has no whois command, so there the same
conversation (port 43, IANA first, then each referral) is held directly.
"""

from __future__ import annotations

import ipaddress
import re
import socket
import subprocess
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor

from ..osinfo import IS_WINDOWS

WHOIS = "/usr/bin/whois"
TIMEOUT_S = 10

#: ``netname:`` (RIPE, APNIC, ...) or ``NetName:`` (ARIN). The output may hold
#: several, from the broad IANA block down to the most specific allocation.
_NETNAME = re.compile(r"^netname:\s*(\S.*?)\s*$", re.MULTILINE | re.IGNORECASE)

#: Blocks no registry hands out, so whois has nothing on them: named by what
#: they're for instead (RFC 1918, RFC 6598, RFC 3927).
_RESERVED = [
    (ipaddress.ip_network(block), f"{name} ({block})")
    for block, name in (
        ("10.0.0.0/8", "Private"),
        ("172.16.0.0/12", "Private"),
        ("192.168.0.0/16", "Private"),
        ("100.64.0.0/10", "Carrier-grade NAT"),
        ("169.254.0.0/16", "Link-local"),
    )
]


def parse(output: str) -> str:
    """The most specific (last) netname in ``whois`` output, or ""."""
    names = _NETNAME.findall(output)
    return names[-1] if names else ""


def reserved_name(ip: str) -> str:
    """What ``ip``'s block is for if it's private or otherwise reserved,
    e.g. "Private (10.0.0.0/8)", or "" for an address whois knows."""
    try:
        address = ipaddress.ip_address(ip)
    except ValueError:
        return ""
    for network, name in _RESERVED:
        if address in network:
            return name
    return ""


def netname(ip: str) -> str:
    """The registry's netname for ``ip``, or "" if there is none to ask for
    (a private or reserved address) or the lookup fails."""
    return parse(query(ip)) if _is_global(ip) else ""


def _is_global(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_global
    except ValueError:
        return False


def query(ip: str, server: str = "") -> str:
    """The raw ``whois`` output for ``ip`` (from ``server`` if given), or ""."""
    if IS_WINDOWS:
        return query_direct(ip, server)
    command = [WHOIS, "-h", server, ip] if server else [WHOIS, ip]
    try:
        done = subprocess.run(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            errors="replace",
            timeout=TIMEOUT_S,
        )
    except (OSError, subprocess.TimeoutExpired):
        return ""
    return done.stdout


#: Where a lookup starts when no server is named: IANA knows which registry
#: holds every block and says so in a ``refer:`` line.
IANA = "whois.iana.org"
WHOIS_PORT = 43
MAX_REFERRALS = 3
#: ``refer: whois.apnic.net`` (IANA) or ``ReferralServer: whois://whois.ripe.net``
#: (ARIN, for a block it handed to another registry).
_REFERRAL = re.compile(
    r"^(?:refer|whois|ReferralServer):\s*(?:r?whois://)?([A-Za-z0-9.-]+)(?::(\d+))?\s*$",
    re.MULTILINE | re.IGNORECASE,
)

Ask = Callable[[str, str, int], str]


def ask(server: str, text: str, port: int = WHOIS_PORT) -> str:
    """One whois exchange: send ``text``, read until the server hangs up."""
    try:
        with socket.create_connection((server, port), timeout=TIMEOUT_S) as sock:
            sock.sendall(text.encode("utf-8", "replace") + b"\r\n")
            chunks = []
            while chunk := sock.recv(4096):
                chunks.append(chunk)
    except OSError:
        return ""
    return b"".join(chunks).decode("utf-8", "replace").replace("\r\n", "\n")


def referral(output: str) -> tuple[str, int] | None:
    """The (server, port) ``output`` sends the query on to, if any."""
    match = _REFERRAL.search(output)
    if match is None:
        return None
    return match.group(1).lower(), int(match.group(2) or WHOIS_PORT)


def query_direct(text: str, server: str = "", ask: Ask = ask) -> str:
    """What ``whois [-h server] text`` prints, without the whois command:
    the named server's answer, or IANA's followed by each referral's, as
    macOS's whois prints them."""
    text = text.strip()
    if server:
        return ask(server, text, WHOIS_PORT)
    outputs: list[str] = []
    visited: set[str] = set()
    target: tuple[str, int] | None = (IANA, WHOIS_PORT)
    while target is not None and target[0] not in visited and len(outputs) <= MAX_REFERRALS:
        visited.add(target[0])
        output = ask(target[0], text, target[1])
        if not output:
            break
        outputs.append(output)
        target = referral(output)
    return "\n".join(outputs)


# -- details, for a hop's Details window ----------------------------------

#: ``key: value`` lines of a whois object. Objects are separated by blank lines.
_FIELD = re.compile(r"^([A-Za-z][\w-]*):[ \t]*(.*?)\s*$", re.MULTILINE)
_BLANK_LINES = re.compile(r"\n[ \t]*\n")
#: Team Cymru's IP-to-ASN service: the AS that announces an address.
CYMRU = "whois.cymru.com"
_CYMRU_FIELDS = ("AS", "IP", "BGP Prefix", "CC", "Registry", "Allocated", "AS Name")


def _objects(output: str) -> list[list[tuple[str, str]]]:
    return [_FIELD.findall(block) for block in _BLANK_LINES.split(output)]


def _first(fields: list[tuple[str, str]], *keys: str, skip: tuple[str, ...] = ()) -> str:
    wanted = {key.lower() for key in keys}
    return next((value for key, value in fields
                 if key.lower() in wanted and value and value not in skip), "")


def parse_details(output: str) -> list[tuple[str, str]]:
    """(label, value) pairs describing the most specific network in
    ``whois`` output: the object holding its last netname, plus the
    organisation and abuse contact wherever the registry put them."""
    objects = _objects(output)
    network = next((fields for fields in reversed(objects)
                    if _first(fields, "netname")), [])
    everything = [field for fields in objects for field in fields]
    details = [
        ("Network", _first(network, "netname")),
        ("Range", _first(network, "inetnum", "NetRange")),
        ("CIDR", _first(network, "CIDR")),
        ("Description", "\n".join(v for k, v in network if k.lower() == "descr" and v)),
        ("Organization", _first(everything, "OrgName", "org-name")
            or _first(network, "Organization")),
        # A registry's abuse role object says "ZZ": not a country.
        ("Country", _first(network, "country") or _first(everything, "country", skip=("ZZ",))),
        ("Status", _first(network, "status", "NetType")),
        ("Abuse contact", _first(everything, "abuse-mailbox", "OrgAbuseEmail")),
        ("Last modified", _first(network, "last-modified", "Updated")),
    ]
    return [(label, value) for label, value in details if value]


def parse_cymru(output: str) -> dict[str, str]:
    """The fields of Team Cymru's verbose answer (``-v``), e.g.
    {"AS": "15169", "AS Name": "GOOGLE - Google LLC, US", ...}."""
    for line in reversed(output.strip().splitlines()):
        parts = [part.strip() for part in line.split("|")]
        if len(parts) == len(_CYMRU_FIELDS) and parts[0].isdigit():
            return dict(zip(_CYMRU_FIELDS, parts))
    return {}


def country(ip: str) -> str:
    """The two-letter code of the country ``ip`` is registered in (Team
    Cymru's answer: where the block was allocated, not where the device
    physically is), or "" for a private address or a failed lookup."""
    if not _is_global(ip):
        return ""
    code = parse_cymru(query(f" -v {ip}", CYMRU)).get("CC", "")
    return code if len(code) == 2 and code.isalpha() else ""


def details(ip: str) -> tuple[list[tuple[str, str]], str]:
    """Everything worth showing about who ``ip`` belongs to, as (label,
    value) pairs, and the raw whois output they came from. A private or
    reserved address is only described, no registry being asked."""
    reserved = reserved_name(ip)
    if not _is_global(ip):
        return ([("Network", reserved or "Not a public address"),
                 ("Note", "Not in any public registry: only its own network knows it")], "")
    # The registry and Team Cymru are asked at once: each takes a second or two.
    with ThreadPoolExecutor(max_workers=2) as pool:
        registry = pool.submit(query, ip)
        cymru = pool.submit(query, f" -v {ip}", CYMRU)
        raw, origin = registry.result(), parse_cymru(cymru.result())
    rows = parse_details(raw)
    if origin:
        rows += [
            ("AS", f"AS{origin['AS']} {origin['AS Name']}".strip()),
            ("BGP prefix", origin["BGP Prefix"]),
            ("Registry", f"{origin['Registry'].upper()} (allocated {origin['Allocated']})"
                if origin["Allocated"] else origin["Registry"].upper()),
        ]
    return rows, raw
