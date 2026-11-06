"""Best-effort device-type guess from a small, fixed list of TCP ports.

Not a general port scanner — deliberately checks only a short, well-known
list chosen for what each port reveals about a device's *kind* (a phone, a
printer, a Windows PC, a web-managed appliance, ...), never a full range.
This is the main thing that can say anything about a host whose MAC is
locally administered (ping.arp.is_locally_administered — an iOS/macOS/
Android "Private Wi-Fi address", say): such a MAC was never assigned to any
vendor, so no OUI lookup can ever identify it, but the services it runs can
still hint at what it is.
"""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
import socket

#: port -> short label. Order matters for guess_device_type: earlier entries
#: are more specific signals and are checked first.
STATIC_PORTS: dict[int, str] = {
    62078: "iOS Sync",
    3389: "RDP",
    9100: "RAW Print",
    631: "IPP",
    548: "AFP",
    445: "SMB",
    139: "NetBIOS",
    5900: "VNC",
    22: "SSH",
    23: "Telnet",
    80: "HTTP",
    443: "HTTPS",
    8080: "HTTP-alt",
    8443: "HTTPS-alt",
}

#: One best-effort label per signal port, checked in STATIC_PORTS order (the
#: dict above is already ordered most- to least-specific) so a phone's sync
#: port wins over a bare web server if both happen to be open.
_DEVICE_TYPE_BY_PORT: dict[int, str] = {
    62078: "Apple Mobile Device (iPhone/iPad)",
    3389: "Windows (RDP)",
    9100: "Printer (Raw/JetDirect)",
    # 631 (IPP/CUPS) and 445/139 (SMB) are each spoken by more than one OS
    # (CUPS runs on Mac and Linux too; macOS's own File Sharing uses SMB,
    # same as Windows) — this Mac itself answers on 445 during testing,
    # which is exactly the case a confident "it's Windows" label would get
    # wrong, so these stay deliberately hedged.
    631: "Printer or Print Server (IPP/CUPS)",
    548: "Mac (AFP File Sharing)",
    445: "File Sharing (SMB — Windows or macOS)",
    139: "File Sharing (SMB — Windows or macOS)",
    5900: "Remote Desktop/Screen Sharing (VNC)",
    22: "SSH-enabled (Unix/Linux/macOS/Network Device)",
    23: "Telnet-enabled (older/embedded device)",
}
_WEB_PORTS = {80, 443, 8080, 8443}

#: port -> short label for the default UDP probe list. UDP doesn't feed
#: guess_device_type (unlike STATIC_PORTS) — these are purely discovery
#: ports: the services most LAN/IoT devices (routers, printers, smart TVs,
#: phones) answer on by default, which is exactly the case a locally
#: administered MAC (no vendor to look up) benefits from most.
STATIC_UDP_PORTS: dict[int, str] = {
    5353: "mDNS",
    1900: "SSDP/UPnP",
    161: "SNMP",
    137: "NetBIOS Name Service",
    123: "NTP",
    67: "DHCP Server",
    53: "DNS",
}

#: The Options dialog's default text for the ports field: STATIC_PORTS
#: (TCP) plus STATIC_UDP_PORTS (UDP), one per line with a "# label" comment
#: naming the service — parse_ports ignores everything from "#" onward, so
#: this is purely for the person reading/editing the field, out of the box.
DEFAULT_PORTS_TEXT = "\n".join(
    [f"{port}  # {label}" for port, label in STATIC_PORTS.items()]
    + [f"{port}/udp  # {label}" for port, label in STATIC_UDP_PORTS.items()]
)

CONNECT_TIMEOUT_SECONDS = 0.6
#: How long a UDP port is given to reply to each of its two probes.
UDP_TIMEOUT_SECONDS = 0.6
#: TCP/UDP connects are cheap for the OS to have many in flight at once; this
#: just keeps a full-range scan (a /24, say) from opening thousands of
#: sockets at the same instant. Shared by the UDP jobs in the same sweep.
#: UDP in particular often pays its full timeout (a silent port is asked
#: twice — see _check_udp_port), so with the default port list now covering 21
#: ports (14 TCP + 7 UDP) a low worker count turns into many sequential
#: ~0.6s rounds for a sweep with more than a handful of hosts. 300 keeps a
#: comfortable margin under __main__.py's raised file-descriptor limit
#: while cutting a 50-host sweep from ~6.6s to ~2s (measured locally).
MAX_WORKERS = 300


@dataclass(slots=True)
class ParsedPorts:
    """TCP and UDP ports parsed from the Options dialog's free-text field."""

    tcp: dict[int, str] = field(default_factory=dict)
    udp: dict[int, str] = field(default_factory=dict)

    def __bool__(self) -> bool:
        return bool(self.tcp) or bool(self.udp)


def parse_ports(text: str) -> ParsedPorts:
    """Turn the Options dialog's free-text field into TCP/UDP port dicts.

    Accepts any mix of commas and whitespace (including newlines) as
    separators (``"22, 80 443"`` is fine). A bare number is a TCP port, same
    as before; suffix it with ``/udp`` (``"53/udp"``) for UDP, or ``/tcp``
    explicitly if you like. Anything from a ``#`` to the end of its line is
    a comment and is ignored (DEFAULT_PORTS_TEXT uses this to name each
    port's service, one per line). A token that isn't a valid port (not an
    integer, outside 1-65535, or an unrecognised protocol suffix) is
    silently skipped rather than rejecting the whole field — this runs on
    every keystroke-adjacent save, so a half-typed entry shouldn't block the
    rest from working. A known TCP port keeps its STATIC_PORTS label (so
    guess_device_type still recognises it) and a known UDP port its
    STATIC_UDP_PORTS label (for display only — UDP doesn't feed
    guess_device_type); anything else gets an empty label and simply won't
    produce a specific device-type guess, though it still shows up in Open
    Ports.
    """
    text = "\n".join(line.split("#", 1)[0] for line in text.splitlines())
    tcp: dict[int, str] = {}
    udp: dict[int, str] = {}
    for token in text.replace(",", " ").split():
        port_text, _, proto = token.partition("/")
        proto = proto.lower() or "tcp"
        try:
            port = int(port_text)
        except ValueError:
            continue
        if not (1 <= port <= 65535):
            continue
        if proto == "tcp":
            tcp[port] = STATIC_PORTS.get(port, "")
        elif proto == "udp":
            udp[port] = STATIC_UDP_PORTS.get(port, "")
    return ParsedPorts(tcp=tcp, udp=udp)


def _check_tcp_port(ip: str, port: int) -> bool:
    try:
        with socket.create_connection((ip, port), timeout=CONNECT_TIMEOUT_SECONDS) as sock:
            # A TCP "self-connect": when the OS happens to pick the target
            # port as this socket's own local port (Windows hands out
            # ephemeral ports sequentially, so it's easy to hit on
            # loopback), the connect succeeds with nothing listening.
            return sock.getsockname() != sock.getpeername()
    except OSError:
        return False


def _check_udp_port(ip: str, port: int) -> bool:
    """Open only if the port actually replies. Well-known services are sent
    a request of their own kind (a DNS query to 53, NTP to 123, SNMP to 161,
    SSDP M-SEARCH to 1900, ...), the same probes as the Port Scan window
    (ping/port_scanner.py), so a working service answers; anything else gets
    an empty datagram, twice. Silence is open|filtered there and not counted
    here: a port that never answered can't be told apart from one a firewall
    drops, and the grid shouldn't claim it's open.
    """
    from .port_scanner import OPEN, probe_udp
    return probe_udp(ip, port, timeout=UDP_TIMEOUT_SECONDS * 2).state == OPEN


def _sort_key(port: int | str) -> tuple[int, str]:
    port_text = str(port)
    number, _, proto = port_text.partition("/")
    return (int(number), proto)


def scan_many(
    ip_by_key: dict[int, str],
    ports: dict[int, str] | None = None,
    udp_ports: dict[int, str] | None = None,
) -> dict[int, list[int | str]]:
    """Ports found open, per host, for every (key -> ip) given.

    ``ports`` (TCP) defaults to the module-level STATIC_PORTS, looked up
    fresh on each call (rather than bound once at def time) so
    monkeypatching port_scan.STATIC_PORTS — e.g. to a single throwaway port
    in a test — actually takes effect. ``udp_ports`` defaults to none, so
    passing only ``ports`` behaves exactly as before UDP support existed.

    An open TCP port appears as a plain int, exactly as always; an open UDP
    port appears as ``"<port>/udp"`` so the two can't be confused once
    they're merged into one list.

    Every (host, port) pair across every host — TCP and UDP alike — is run
    through one shared thread pool rather than one pool per host, so
    scanning many hosts stays fast instead of serialising host by host.
    """
    if not ip_by_key:
        return {}
    ports = STATIC_PORTS if ports is None else ports
    udp_ports = udp_ports or {}
    tcp_jobs = [(key, ip, port) for key, ip in ip_by_key.items() if ip for port in ports]
    udp_jobs = [(key, ip, port) for key, ip in ip_by_key.items() if ip for port in udp_ports]
    open_by_key: dict[int, list[int | str]] = {key: [] for key in ip_by_key}
    if not tcp_jobs and not udp_jobs:
        return open_by_key

    with ThreadPoolExecutor(max_workers=min(MAX_WORKERS, len(tcp_jobs) + len(udp_jobs))) as pool:
        future_to_job: dict = {}
        for key, ip, port in tcp_jobs:
            future_to_job[pool.submit(_check_tcp_port, ip, port)] = (key, port)
        for key, ip, port in udp_jobs:
            future_to_job[pool.submit(_check_udp_port, ip, port)] = (key, f"{port}/udp")
        for future in as_completed(future_to_job):
            key, result_port = future_to_job[future]
            try:
                if future.result():
                    open_by_key[key].append(result_port)
            except Exception:
                pass

    for ports_found in open_by_key.values():
        ports_found.sort(key=_sort_key)
    return open_by_key


def guess_device_type(open_ports: list[int]) -> str:
    """A one-line, best-effort guess at the kind of device behind open_ports.

    A heuristic, not a fingerprint: it only ever reports what it saw (e.g.
    "has an SSH port open"), never claims a specific product or model.
    Returns "" when nothing matched, which is the common case — most
    consumer/IoT devices answer none of these ports at all.
    """
    open_set = set(open_ports)
    for port in STATIC_PORTS:
        if port in open_set and port in _DEVICE_TYPE_BY_PORT:
            return _DEVICE_TYPE_BY_PORT[port]
    if open_set & _WEB_PORTS:
        return "Has a Web Interface"
    return ""
