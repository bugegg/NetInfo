"""ARP scan over BPF: ask every wanted IP on a local subnet for its MAC by
sending ARP requests ourselves and reading the replies off the wire.

On macOS 27 the app gets an empty ARP table (``arp -a``, and the routing
sysctl behind it), and even its own interface's MAC reads as
02:00:00:00:00:00, while the hosts still answer ARP like always. So this
learns the Mac's real MAC from a frame it sends, then broadcasts a request
per IP through /dev/bpf (as ping/lldp_cdp.py listens: no root, as long as
the user is in the ``access_bpf`` group that Wireshark's ChmodBPF sets up).

Every failure (no BPF access, Windows, an interface that isn't Ethernet)
just means no MACs from here; ping/device_info.py moves on to its other
sources. Windows' ARP table can be read, so this isn't needed there.
"""

from __future__ import annotations

import ipaddress
import os
import select
import socket
import struct
import time

from ..osinfo import IS_WINDOWS
from . import network_interfaces
from .lldp_cdp import (
    BIOCIMMEDIATE,
    BIOCSBLEN,
    BIOCSETF,
    BIOCSETIF,
    BIOCSSEESENT,
    BUFFER_SIZE,
    _BpfInsn,
    _BpfProgram,
    split_bpf_buffer,
)

try:
    import fcntl
except ImportError:  # Windows
    fcntl = None

ARP_ETHERTYPE = 0x0806
IPV4_ETHERTYPE = 0x0800
#: How long replies are waited for after the last request goes out.
DEFAULT_TIMEOUT = 1.5
#: How long to wait for a frame of our own to learn our MAC from.
OWN_MAC_TIMEOUT = 1.0
#: Gap between requests, so a /24 doesn't hit the wire as one burst.
REQUEST_GAP_SECONDS = 0.001
#: UDP discard port: the probe sent to make the Mac emit a frame.
_DISCARD_PORT = 9

#: Classic BPF: ARP and IPv4 frames (ours included, to find our MAC).
_ARP_OR_IPV4 = (
    (0x28, 0, 0, 12),  # ldh [12]
    (0x15, 2, 0, ARP_ETHERTYPE),  # jeq 0x0806 -> accept
    (0x15, 1, 0, IPV4_ETHERTYPE),  # jeq 0x0800 -> accept
    (0x06, 0, 0, 0),  # ret 0
    (0x06, 0, 0, 0xFFFF),  # ret all
)
#: Then only ARP, while replies are collected.
_ARP_ONLY = (
    (0x28, 0, 0, 12),
    (0x15, 0, 1, ARP_ETHERTYPE),
    (0x06, 0, 0, 0xFFFF),
    (0x06, 0, 0, 0),
)


def build_request(src_mac: bytes, src_ip: str, target_ip: str) -> bytes:
    """A broadcast ARP "who has target_ip, tell src_ip" Ethernet frame."""
    return (
        b"\xff" * 6 + src_mac + struct.pack("!H", ARP_ETHERTYPE)
        + struct.pack("!HHBBH", 1, IPV4_ETHERTYPE, 6, 4, 1)
        + src_mac + socket.inet_aton(src_ip) + b"\0" * 6 + socket.inet_aton(target_ip)
    )


def parse_reply(frame: bytes) -> tuple[str, str] | None:
    """(sender IP, sender MAC as AA:BB:...) from an ARP reply frame, else None."""
    if len(frame) < 42 or frame[12:14] != struct.pack("!H", ARP_ETHERTYPE):
        return None
    if frame[20:22] != b"\x00\x02":
        return None
    mac = frame[22:28]
    if not any(mac):
        return None
    return socket.inet_ntoa(frame[28:32]), ":".join(f"{byte:02X}" for byte in mac)


def own_mac_from_frame(frame: bytes, own_ip: str) -> bytes | None:
    """Our MAC, if `frame` is one we sent: IPv4 from our address, or an ARP
    request the kernel made for us."""
    if len(frame) < 34:
        return None
    ip = socket.inet_aton(own_ip)
    ethertype = frame[12:14]
    if ethertype == struct.pack("!H", IPV4_ETHERTYPE) and frame[26:30] == ip:
        return frame[6:12]
    if ethertype == struct.pack("!H", ARP_ETHERTYPE) and frame[28:32] == ip:
        return frame[6:12]
    return None


def scan(ips: list[str], timeout: float = DEFAULT_TIMEOUT) -> dict[str, str]:
    """{IP: MAC} for each of `ips` on a local subnet that answers ARP.
    Empty when ARP scanning isn't possible here."""
    if IS_WINDOWS or fcntl is None or not ips:
        return {}
    found: dict[str, str] = {}
    for interface, wanted in _by_interface(ips):
        try:
            found.update(_scan_interface(interface, wanted, timeout))
        except OSError:
            continue  # no BPF access, not Ethernet, ...: no MACs from here
    return found


def _by_interface(ips: list[str]) -> list[tuple[network_interfaces.NetworkInterface, list[str]]]:
    """`ips` grouped by the interface whose subnet holds them; others dropped
    (ARP doesn't cross a router)."""
    groups = []
    remaining = set(ips)
    for interface in network_interfaces.list_interfaces():
        network = ipaddress.IPv4Network(interface.cidr, strict=False)
        wanted = []
        for ip in sorted(remaining):
            try:
                if ipaddress.IPv4Address(ip) in network and ip != interface.ip_address:
                    wanted.append(ip)
            except ValueError:
                continue
        if wanted:
            groups.append((interface, wanted))
            remaining -= set(wanted)
    return groups


def _set_filter(fd: int, program: tuple) -> None:
    insns = (_BpfInsn * len(program))(*(_BpfInsn(*insn) for insn in program))
    fcntl.ioctl(fd, BIOCSETF, bytes(_BpfProgram(len(program), insns)))


def _open(interface: str) -> int:
    for number in range(256):
        try:
            fd = os.open(f"/dev/bpf{number}", os.O_RDWR | os.O_NONBLOCK)
            break
        except FileNotFoundError:
            raise
        except PermissionError:
            raise
        except OSError:
            continue  # busy
    else:
        raise OSError("No free /dev/bpf device")
    try:
        fcntl.ioctl(fd, BIOCSBLEN, struct.pack("I", BUFFER_SIZE))
        fcntl.ioctl(fd, BIOCSETIF, interface.encode().ljust(32, b"\0"))
        fcntl.ioctl(fd, BIOCIMMEDIATE, struct.pack("I", 1))
        fcntl.ioctl(fd, BIOCSSEESENT, struct.pack("I", 1))
        _set_filter(fd, _ARP_OR_IPV4)
    except OSError:
        os.close(fd)
        raise
    return fd


def _frames(fd: int, wait: float) -> list[bytes]:
    ready, _, _ = select.select([fd], [], [], max(0.0, wait))
    if not ready:
        return []
    try:
        return split_bpf_buffer(os.read(fd, BUFFER_SIZE))
    except BlockingIOError:
        return []


def _own_mac(fd: int, own_ip: str, probe_ip: str) -> bytes | None:
    """Make the Mac send a frame (a UDP datagram to the discard port, or
    the ARP request the kernel sends first) and read our MAC off it."""
    deadline = time.monotonic() + OWN_MAC_TIMEOUT
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe:
        while time.monotonic() < deadline:
            try:
                probe.sendto(b"\0", (probe_ip, _DISCARD_PORT))
            except OSError:
                pass
            for frame in _frames(fd, 0.2):
                mac = own_mac_from_frame(frame, own_ip)
                if mac:
                    return mac
    return None


def _scan_interface(
    interface: network_interfaces.NetworkInterface, wanted: list[str], timeout: float
) -> dict[str, str]:
    fd = _open(interface.name)
    try:
        own_mac = _own_mac(fd, interface.ip_address, wanted[0])
        if own_mac is None:
            return {}
        _set_filter(fd, _ARP_ONLY)
        targets = set(wanted)
        found: dict[str, str] = {}

        def collect(wait: float) -> None:
            for frame in _frames(fd, wait):
                reply = parse_reply(frame)
                if reply and reply[0] in targets:
                    found[reply[0]] = reply[1]

        for ip in wanted:
            os.write(fd, build_request(own_mac, interface.ip_address, ip))
            collect(REQUEST_GAP_SECONDS)
        deadline = time.monotonic() + timeout
        while len(found) < len(targets) and time.monotonic() < deadline:
            collect(deadline - time.monotonic())
        return found
    finally:
        os.close(fd)
