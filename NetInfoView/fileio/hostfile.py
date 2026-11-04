"""Reading and writing PingInfoView's host-list format.

::

    Group: Computers Group 1      group header, applies to the lines below it
    192.168.1.10 Main Server      host or IP, with an optional description
    192.168.1.30:443 HTTPS Site   a port makes it a TCP ping
    #192.168.1.14 Host 03         a leading '#' disables the entry
    192.168.0.10-192.168.0.20     inclusive address range
    192.168.0.10-20               short form of the same range
    192.168.0.0/24                CIDR block
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass

GROUP_PREFIX = "group:"

#: The most addresses one CIDR block or range may expand to (a /16). Expansion
#: is linear, so a typo like 192.168.1.0/2 — on the way to typing /24 — would
#: otherwise build a billion entries and hang the app.
MAX_RANGE_ADDRESSES = 65536

#: A trailing :port, but not the colons inside an IPv6 literal.
_PORT_RE = re.compile(r"^(?P<host>[^:\s]+):(?P<port>\d{1,5})$")
_CIDR_RE = re.compile(r"^(?P<network>\d{1,3}(?:\.\d{1,3}){3})/(?P<bits>\d{1,2})$")
_FULL_RANGE_RE = re.compile(
    r"^(?P<start>\d{1,3}(?:\.\d{1,3}){3})\s*-\s*(?P<end>\d{1,3}(?:\.\d{1,3}){3})$"
)
_SHORT_RANGE_RE = re.compile(
    r"^(?P<start>\d{1,3}(?:\.\d{1,3}){3})\s*-\s*(?P<last_octet>\d{1,3})$"
)


@dataclass(slots=True)
class ParsedHost:
    host: str
    port: int | None = None
    description: str = ""
    group: str = ""
    enabled: bool = True


class HostListError(ValueError):
    """A line that cannot be used, e.g. a range over MAX_RANGE_ADDRESSES."""


def _check_range_size(token: str, count: int) -> None:
    if count > MAX_RANGE_ADDRESSES:
        raise HostListError(
            f"{token} covers {count:,} addresses; the limit is "
            f"{MAX_RANGE_ADDRESSES:,} (a /16) per range."
        )


def has_hosts(text: str) -> bool:
    """Cheap check for at least one host line, without expanding any ranges."""
    for raw_line in text.splitlines():
        line = raw_line.strip().lstrip("#").strip()
        if line and not line.casefold().startswith(GROUP_PREFIX):
            return True
    return False


def parse_host_list(
    text: str, skip_first: bool = False, skip_last: bool = False
) -> list[ParsedHost]:
    """Expand a host-list document into one ParsedHost per address."""
    hosts: list[ParsedHost] = []
    group = ""

    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line:
            continue

        if line.casefold().startswith(GROUP_PREFIX):
            group = line[len(GROUP_PREFIX) :].strip()
            continue

        enabled = True
        if line.startswith("#"):
            enabled = False
            line = line[1:].strip()
            if not line:
                continue

        token, _, description = line.partition(" ")
        description = description.strip()
        hosts.extend(
            _expand(token, description, group, enabled, skip_first, skip_last)
        )

    return hosts


def _expand(
    token: str,
    description: str,
    group: str,
    enabled: bool,
    skip_first: bool,
    skip_last: bool,
) -> list[ParsedHost]:
    def make(host: str, port: int | None = None) -> ParsedHost:
        return ParsedHost(host, port, description, group, enabled)

    addresses = _expand_addresses(token, skip_first, skip_last)
    if addresses is not None:
        return [make(address) for address in addresses]

    match = _PORT_RE.match(token)
    if match:
        port = int(match.group("port"))
        if 0 < port <= 65535:
            return [make(match.group("host"), port)]

    return [make(token)]


def _expand_addresses(
    token: str, skip_first: bool, skip_last: bool
) -> list[str] | None:
    """Expand a CIDR block or address range, or return None if it is neither."""
    match = _CIDR_RE.match(token)
    if match:
        try:
            network = ipaddress.IPv4Network(token, strict=False)
        except ValueError:
            return None
        _check_range_size(token, network.num_addresses)
        # /31 and /32 have no network/broadcast pair to trim.
        addresses = (
            list(network.hosts()) if network.prefixlen < 31 else list(network)
        )
        return _trim([str(a) for a in addresses], skip_first, skip_last)

    match = _FULL_RANGE_RE.match(token)
    if match:
        return _trim(
            _range(token, match.group("start"), match.group("end")), skip_first, skip_last
        )

    match = _SHORT_RANGE_RE.match(token)
    if match:
        start = match.group("start")
        end = start.rsplit(".", 1)[0] + "." + match.group("last_octet")
        return _trim(_range(token, start, end), skip_first, skip_last)

    return None


def _range(token: str, start: str, end: str) -> list[str]:
    try:
        first = ipaddress.IPv4Address(start)
        last = ipaddress.IPv4Address(end)
    except ValueError:
        return []
    if int(last) < int(first):
        first, last = last, first
    _check_range_size(token, int(last) - int(first) + 1)
    return [str(ipaddress.IPv4Address(n)) for n in range(int(first), int(last) + 1)]


def _trim(addresses: list[str], skip_first: bool, skip_last: bool) -> list[str]:
    if skip_first:
        addresses = addresses[1:]
    if skip_last:
        addresses = addresses[:-1]
    return addresses


def format_host_list(entries) -> str:
    """Write entries back out, re-emitting group headers as they change."""
    lines: list[str] = []
    group = None
    for entry in entries:
        entry_group = getattr(entry, "group", "") or ""
        if entry_group != group:
            if entry_group:
                if lines:
                    lines.append("")
                lines.append(f"Group: {entry_group}")
            group = entry_group
        token = entry.host if entry.port is None else f"{entry.host}:{entry.port}"
        prefix = "" if entry.enabled else "#"
        description = f" {entry.description}" if entry.description else ""
        lines.append(f"{prefix}{token}{description}")
    return "\n".join(lines) + ("\n" if lines else "")
