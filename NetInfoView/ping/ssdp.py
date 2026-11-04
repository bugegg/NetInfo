"""UPnP `friendlyName`: smart TVs, media boxes, routers and a lot of IoT gear
announce themselves over SSDP (UDP 1900) with a link to a device
description whose <friendlyName> is the name they show the user.

One multicast M-SEARCH finds every device on the link at once, so its
answers are shared by every host's lookup for DISCOVERY_TTL_SECONDS rather
than flooding the network once per host; a device that missed it is asked
directly with a unicast M-SEARCH.
"""

from __future__ import annotations

import html
import re
import socket
import threading
import time
import urllib.parse
import urllib.request

SSDP_PORT = 1900
SSDP_GROUP = "239.255.255.250"
DISCOVERY_SECONDS = 2.0
DISCOVERY_TTL_SECONDS = 120
UNICAST_TIMEOUT = 1.0
FETCH_TIMEOUT = 2.0
MAX_DESCRIPTION_BYTES = 256 * 1024
#: A router may list a dozen services; their descriptions say the same.
MAX_LOCATIONS_PER_HOST = 3

_LOCATION = re.compile(r"^location:\s*(\S+)", re.IGNORECASE | re.MULTILINE)
_FRIENDLY_NAME = re.compile(r"<friendlyName>\s*(.*?)\s*</friendlyName>", re.IGNORECASE | re.DOTALL)

_lock = threading.Lock()
_discovered: tuple[float, dict[str, list[str]]] = (0.0, {})


def m_search(host: str, target: str = "upnp:rootdevice") -> bytes:
    return (
        "M-SEARCH * HTTP/1.1\r\n"
        f"HOST: {host}:{SSDP_PORT}\r\n"
        'MAN: "ssdp:discover"\r\n'
        "MX: 1\r\n"
        f"ST: {target}\r\n\r\n"
    ).encode("ascii")


def _collect(sock: socket.socket, seconds: float) -> dict[str, list[str]]:
    """LOCATION URLs from every reply within `seconds`, by sender address."""
    found: dict[str, list[str]] = {}
    deadline = time.monotonic() + seconds
    while (remaining := deadline - time.monotonic()) > 0:
        sock.settimeout(remaining)
        try:
            reply, (sender, _) = sock.recvfrom(4096)
        except OSError:
            break
        match = _LOCATION.search(reply.decode("utf-8", "replace"))
        if match and match.group(1) not in found.setdefault(sender, []):
            found[sender].append(match.group(1))
    return found


def _discover() -> dict[str, list[str]]:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)
            sock.sendto(m_search(SSDP_GROUP), (SSDP_GROUP, SSDP_PORT))
            return _collect(sock, DISCOVERY_SECONDS)
    except OSError:
        return {}


def discovered() -> dict[str, list[str]]:
    """Every device on the link that answered the last M-SEARCH (refreshed
    when older than DISCOVERY_TTL_SECONDS)."""
    global _discovered
    with _lock:
        found_at, found = _discovered
        if not found_at or time.monotonic() - found_at > DISCOVERY_TTL_SECONDS:
            found = _discover()
            _discovered = (time.monotonic(), found)
        return found


def _unicast_locations(ip: str) -> list[str]:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.sendto(m_search(ip), (ip, SSDP_PORT))
            return _collect(sock, UNICAST_TIMEOUT).get(ip, [])
    except OSError:
        return []


def friendly_name(description: str) -> str:
    match = _FRIENDLY_NAME.search(description)
    return " ".join(html.unescape(match.group(1)).split()) if match else ""


def _fetch_description(url: str) -> str:
    request = urllib.request.Request(url, headers={"User-Agent": "NetInfoView"})
    with urllib.request.urlopen(request, timeout=FETCH_TIMEOUT) as response:
        return response.read(MAX_DESCRIPTION_BYTES).decode("utf-8", "replace")


def lookup(ip: str) -> str:
    """The UPnP friendlyName of the device at `ip`, or ""."""
    locations = discovered().get(ip) or _unicast_locations(ip)
    for url in locations[:MAX_LOCATIONS_PER_HOST]:
        parsed = urllib.parse.urlsplit(url)
        if parsed.scheme != "http" or parsed.hostname != ip:
            continue  # only ever fetch from the device itself
        try:
            name = friendly_name(_fetch_description(url))
        except (OSError, ValueError):
            continue
        if name:
            return name
    return ""
