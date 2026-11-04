"""Enumerates this Mac's active IPv4 network interfaces via `ifconfig`.

Used to offer "scan my whole network" when the host list is empty and the
user hits Start: picking an interface turns into a CIDR block that
fileio.hostfile already knows how to expand into one host per address, so
the user never has to look up their own subnet.
"""

from __future__ import annotations

import ipaddress
import re
import subprocess
from dataclasses import dataclass

#: One interface's block: its name, then every indented line until the next
#: top-level name or the end of the output.
_IFACE_BLOCK_RE = re.compile(r"^(\w+):.*?(?=^\w+:|\Z)", re.MULTILINE | re.DOTALL)
#: ifconfig prints the flags word in hex (e.g. "8a63"); \d+ alone looks
#: right for an interface whose hex digits are coincidentally all 0-9 (en0's
#: 8863, say) but silently fails to match for one with a-f in it (a bridge's
#: typical 8a63) — and search() then falls through to match a *nested*
#: "flags=" instead (a bridge member line's "flags=3<LEARNING,DISCOVER>"),
#: which doesn't carry UP and so looked like the interface was down.
_FLAGS_RE = re.compile(r"flags=[0-9a-fA-F]+<([^>]*)>")
_INET_RE = re.compile(r"\binet (\d{1,3}(?:\.\d{1,3}){3}) netmask (0x[0-9a-fA-F]+)")

#: Interfaces that are never a LAN to scan, regardless of their flags.
_EXCLUDED_NAMES = {"lo0"}


@dataclass(slots=True)
class NetworkInterface:
    name: str  # e.g. "en0"
    ip_address: str  # this Mac's own address on it, e.g. "192.168.1.105"
    netmask: str  # dotted form, e.g. "255.255.255.0"
    cidr: str  # the whole subnet, e.g. "192.168.1.0/24"

    @property
    def display_label(self) -> str:
        return f"{self.name}  —  {self.ip_address}  ({self.cidr})"


def list_interfaces() -> list[NetworkInterface]:
    """Every active, non-loopback IPv4 interface with a scannable subnet."""
    try:
        output = subprocess.run(
            ["/sbin/ifconfig"], capture_output=True, text=True, timeout=5
        ).stdout
    except (OSError, subprocess.SubprocessError):
        return []

    interfaces = []
    for match in _IFACE_BLOCK_RE.finditer(output):
        name = match.group(1)
        if name in _EXCLUDED_NAMES:
            continue
        block = match.group(0)

        flags_match = _FLAGS_RE.search(block)
        flags = {f.strip() for f in flags_match.group(1).split(",")} if flags_match else set()
        if "UP" not in flags:
            continue

        inet_match = _INET_RE.search(block)
        if not inet_match:
            continue
        ip_address, mask_hex = inet_match.groups()
        netmask = _hex_mask_to_dotted(mask_hex)

        try:
            network = ipaddress.IPv4Network(f"{ip_address}/{netmask}", strict=False)
        except ValueError:
            continue
        if network.prefixlen >= 31:
            continue  # a /31 or /32 (point-to-point, VPN) has nothing to scan

        interfaces.append(
            NetworkInterface(
                name=name,
                ip_address=ip_address,
                netmask=netmask,
                cidr=f"{network.network_address}/{network.prefixlen}",
            )
        )
    return interfaces


def _hex_mask_to_dotted(hex_mask: str) -> str:
    value = int(hex_mask, 16)
    return ".".join(str((value >> shift) & 0xFF) for shift in (24, 16, 8, 0))


@dataclass(slots=True)
class EthernetInterface:
    name: str  # e.g. "en10"
    port: str  # System Settings' name for it, e.g. "USB 10/100/1000 LAN"; may be ""
    active: bool  # a link is up ("status: active")

    @property
    def label(self) -> str:
        return f"{self.name} ({self.port})" if self.port else self.name


def ethernet_interfaces() -> list[EthernetInterface]:
    """Every ``enN`` interface with whether its link is up, for LLDP/CDP.
    Linked ones come first; within each, real wired ports, then Wi-Fi, then
    the rest (Thunderbolt bridge ports, Apple Silicon's internal "Ethernet
    Adapter (enN)"s)."""
    try:
        output = subprocess.run(
            ["/sbin/ifconfig"], capture_output=True, text=True, timeout=5
        ).stdout
    except (OSError, subprocess.SubprocessError):
        return []
    ports = hardware_ports()
    interfaces = [
        EthernetInterface(
            name=match.group(1),
            port=ports.get(match.group(1), ""),
            active="status: active" in match.group(0),
        )
        for match in _IFACE_BLOCK_RE.finditer(output)
        if re.fullmatch(r"en\d+", match.group(1))
    ]
    interfaces.sort(key=lambda i: (not i.active, _port_rank(i.port), int(i.name[2:])))
    return interfaces


def _port_rank(port: str) -> int:
    lowered = port.lower()
    if lowered == "wi-fi":
        return 1
    # "Thunderbolt 1" is a Thunderbolt Bridge port, not Ethernet; a dock's
    # "Thunderbolt Ethernet Slot 0" is real Ethernet.
    if not port or re.fullmatch(r"thunderbolt \d+", lowered):
        return 2
    if lowered.startswith("ethernet adapter ("):
        return 2
    return 0


def hardware_ports() -> dict[str, str]:
    """Interface name -> the port name System Settings shows ("Wi-Fi",
    "USB 10/100/1000 LAN", ...), from ``networksetup``."""
    try:
        output = subprocess.run(
            ["/usr/sbin/networksetup", "-listallhardwareports"],
            capture_output=True, text=True, timeout=5,
        ).stdout
    except (OSError, subprocess.SubprocessError):
        return {}
    return {
        device: port
        for port, device in re.findall(r"^Hardware Port: (.+)\nDevice: (\S+)", output, re.MULTILINE)
    }
