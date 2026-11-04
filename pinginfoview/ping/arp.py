"""MAC address lookup from the system ARP table.

Only hosts on the local link have an ARP entry, so this is empty for anything
beyond the router — which is also true of the original.
"""

from __future__ import annotations

import re
import time

from ..osinfo import IS_WINDOWS, run_quietly

#: ``? (192.168.1.1) at 1:2:3:4:5:6 on en0 ...``
_ARP_LINE = re.compile(
    r"\((?P<ip>\d{1,3}(?:\.\d{1,3}){3})\)\s+at\s+(?P<mac>[0-9a-fA-F:]{11,17})"
)
#: Windows' ``arp -a`` row: ``  192.168.1.1     aa-bb-cc-dd-ee-ff     dynamic``.
#: Only the row shape is matched; the headers around it are localised.
_WINDOWS_ARP_LINE = re.compile(
    r"^\s*(?P<ip>\d{1,3}(?:\.\d{1,3}){3})\s+(?P<mac>[0-9a-fA-F]{2}(?:-[0-9a-fA-F]{2}){5})\s",
    re.MULTILINE,
)
_CACHE_TTL_SECONDS = 30.0

_cache: dict[str, str] = {}
_cache_loaded_at = 0.0


def _normalise(mac: str) -> str:
    """macOS prints ``1:2:3:4:5:6``; pad each octet to two digits."""
    return ":".join(part.rjust(2, "0").upper() for part in mac.split(":"))


def is_locally_administered(mac: str) -> bool:
    """True if mac's U/L bit is set, so it isn't a real vendor's OUI.

    Bit 1 (the 0x02 bit) of a MAC's first octet is 0 for a universally
    administered address (factory-assigned by the manufacturer, meaningful
    to look up) and 1 for a locally administered one — randomly generated
    by the OS, as with iOS/macOS/Android "Private Wi-Fi address", or
    manually set. A locally administered address was never assigned to any
    vendor, so no vendor lookup — however complete — will ever find one for
    it; that's a different situation from simply not knowing yet.
    """
    hex_digits = "".join(ch for ch in mac if ch in "0123456789abcdefABCDEF")
    if len(hex_digits) < 2:
        return False
    return bool(int(hex_digits[:2], 16) & 0x02)


def parse_windows_arp(output: str) -> dict[str, str]:
    """IP -> MAC from Windows' ``arp -a``, minus broadcast/multicast entries."""
    table = {}
    for match in _WINDOWS_ARP_LINE.finditer(output):
        mac = match.group("mac").replace("-", ":").upper()
        if mac == "FF:FF:FF:FF:FF:FF" or mac.startswith("01:00:5E"):
            continue
        table.setdefault(match.group("ip"), mac)
    return table


def _load_table() -> dict[str, str]:
    if IS_WINDOWS:
        return parse_windows_arp(run_quietly(["arp", "-a"], timeout=5))
    output = run_quietly(["/usr/sbin/arp", "-a", "-n"], timeout=5)
    table = {}
    for match in _ARP_LINE.finditer(output):
        mac = match.group("mac")
        if mac != "(incomplete)":
            table[match.group("ip")] = _normalise(mac)
    return table


def lookup(ip: str, force_refresh: bool = False) -> str:
    """The MAC for ``ip`` if it is on this link, else an empty string."""
    global _cache, _cache_loaded_at
    if not ip:
        return ""
    expired = time.monotonic() - _cache_loaded_at > _CACHE_TTL_SECONDS
    if force_refresh or expired or not _cache:
        _cache = _load_table()
        _cache_loaded_at = time.monotonic()
    return _cache.get(ip, "")


def find_ip(macs: list[str]) -> str:
    """The IP the ARP table has for any of `macs` (read afresh), else ""."""
    wanted = {_normalise(mac) for mac in macs}
    if not wanted:
        return ""
    return next((ip for ip, mac in sorted(_load_table().items()) if mac in wanted), "")
