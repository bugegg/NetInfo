"""Path MTU discovery: the largest ping that gets through unfragmented.

macOS rejects IP_DONTFRAG on the unprivileged ICMP socket the engine pings
with (see ping/icmp.py), so this drives the system's own ``/sbin/ping -D``
instead, which may set Don't Fragment. Pings with DF set and a growing payload
find the biggest one that still gets a reply; the path MTU is that payload
plus the 20-byte IP and 8-byte ICMP headers.

Paths above standard Ethernet (jumbo frames) are measured too, up to
MAX_MTU: macOS caps an unprivileged ping's datagram at 8192 bytes
(sysctl net.inet.raw.maxdgram), so a 9000-byte path reads as ">=8212".
Nothing is probed above the MTU of the Mac's own outgoing interface: ping
waits out its full timeout even when the interface refuses the size at once.
"""

from __future__ import annotations

import subprocess
import time
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor, as_completed

PING = "/sbin/ping"
ROUTE = "/sbin/route"
#: IPv4 header + ICMP echo header around the payload.
HEADERS = 28
#: Standard Ethernet: most paths top out here, so it's tried first.
ETHERNET_MTU = 1500
ETHERNET_PAYLOAD = ETHERNET_MTU - HEADERS
#: The biggest payload /sbin/ping accepts without root: net.inet.raw.maxdgram
#: (8192) less the ICMP header. A path that carries it may carry more.
MAX_PAYLOAD = 8184
MAX_MTU = MAX_PAYLOAD + HEADERS
#: Each failed size is tried this many times, so one lost ping isn't taken
#: for "too big" and doesn't drag the answer down.
ATTEMPTS = 2
WAIT_MS = 1000
#: How long one ping may take in all, as ping's own options. "-t" (seconds,
#: for the whole run) rather than "-W" (per reply): with "-W" a ping that
#: gets no reply also sits out its one-second send interval, so every
#: too-big probe took twice WAIT_MS.
WAIT_ARGS = ("-t", str(max(1, WAIT_MS // 1000)))
MAX_WORKERS = 32

Probe = Callable[[str, int], bool]
LinkMtu = Callable[[str], int | None]


def route_mtu(ip: str) -> int | None:
    """The MTU of the interface the Mac would send to `ip` through, from
    ``route -n get``; None if it can't be found."""
    try:
        done = subprocess.run(
            [ROUTE, "-n", "get", ip],
            capture_output=True, text=True, timeout=2,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    lines = done.stdout.splitlines()
    for header, values in zip(lines, lines[1:]):
        names = header.split()
        if "mtu" in names:
            try:
                return int(values.split()[names.index("mtu")]) or None
            except (IndexError, ValueError):
                return None
    return None


#: route_mtu answers by address, so Check MTU (by hand or the automatic one)
#: doesn't run ``route`` again for a host it checked a moment ago.
_ROUTE_CACHE_SECONDS = 300.0
_route_cache: dict[str, tuple[float, int | None]] = {}


def cached_route_mtu(ip: str) -> int | None:
    """route_mtu, remembered per address for _ROUTE_CACHE_SECONDS. Per
    address, not per network: a VPN may route single addresses of a LAN
    through its tunnel."""
    now = time.monotonic()
    hit = _route_cache.get(ip)
    if hit is not None and now - hit[0] < _ROUTE_CACHE_SECONDS:
        return hit[1]
    mtu = route_mtu(ip)
    _route_cache[ip] = (now, mtu)
    return mtu


def ceiling_for(ip: str, link_mtu: LinkMtu = route_mtu) -> int:
    """The largest MTU worth probing toward `ip`."""
    return min(MAX_MTU, link_mtu(ip) or MAX_MTU)


def probe(ip: str, payload: int) -> bool:
    """True if a ping of `payload` bytes with Don't Fragment set got a reply."""
    for _ in range(ATTEMPTS):
        try:
            done = subprocess.run(
                [PING, "-D", "-n", "-q", "-c", "1", *WAIT_ARGS, "-s", str(payload), ip],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=WAIT_MS / 1000 + 2,
            )
        except (OSError, subprocess.TimeoutExpired):
            continue
        if done.returncode == 0:
            return True
    return False


def find_mtu(ip: str, probe: Probe = probe, link_mtu: LinkMtu = route_mtu) -> int | None:
    """The path MTU to `ip` in bytes, or None if it doesn't answer pings at
    all. MAX_MTU means "at least MAX_MTU": nothing bigger can be tried."""
    ceiling = ceiling_for(ip, link_mtu) - HEADERS
    first = min(ETHERNET_PAYLOAD, ceiling)
    if probe(ip, first):
        if first == ceiling:
            return ceiling + HEADERS
        # A jumbo-capable interface: one byte over Ethernet settles the
        # usual case before searching up to the ceiling.
        if not probe(ip, first + 1):
            return first + HEADERS
        if probe(ip, ceiling):
            return ceiling + HEADERS
        good, bad = first + 1, ceiling
    else:
        if not probe(ip, 0):
            return None
        good, bad = 0, first
    # Binary search between a size that got through and one that didn't.
    while bad - good > 1:
        middle = (good + bad) // 2
        if probe(ip, middle):
            good = middle
        else:
            bad = middle
    return good + HEADERS


def format_mtu(mtu: int | None) -> str:
    """Display text for a path MTU; the ceiling shows as a lower bound."""
    if mtu is None:
        return ""
    return f"\u2265{mtu}" if mtu >= MAX_MTU else str(mtu)


def find_many(
    targets: list[tuple[int, str]],
    on_result: Callable[[int, int | None], None],
    probe: Probe = probe,
    link_mtu: LinkMtu = cached_route_mtu,
) -> None:
    """find_mtu for each (key, ip), several at once, reporting each as it's
    found."""
    if not targets:
        return
    with ThreadPoolExecutor(max_workers=min(MAX_WORKERS, len(targets))) as pool:
        futures = {pool.submit(find_mtu, ip, probe, link_mtu): key for key, ip in targets}
        for future in as_completed(futures):
            on_result(futures[future], future.result())
