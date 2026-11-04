"""Resolve an IP to the device's own network name.

Mirrors ping/arp.py: the GUI's periodic refresh timer calls resolve() per host
and caches nothing here itself — unlike the vendor database this is cheap to
redo every run, and a fresh answer is more correct than a stale cached name if
a device gets renamed or re-leased.
"""

from __future__ import annotations

import ipaddress
import re
import socket
import subprocess
import time
from collections.abc import Callable
from functools import partial

from . import http_title, mdns, netbios, network_interfaces, ntlm, snmp, ssdp, tls_cert
from .parallel import first_answer

#: ``   name: some-device.local``, possibly several, on their own indented lines.
_DSCACHEUTIL_NAME = re.compile(r"^\s*name:\s*(\S+)", re.MULTILINE)
#: This Mac's own networks, from ifconfig, re-read after the TTL so a
#: change of network is noticed: (when read, networks).
_local_networks: tuple[float, list] = (0.0, [])
_LOCAL_NETWORKS_TTL_SECONDS = 60.0
#: What a device with no name of its own answers with; not worth showing.
_PLACEHOLDER_NAMES = {"localhost", "localhost.local", "localhost.localdomain"}


def resolve(ip: str) -> str:
    """The device's own name for ``ip``, or "" if nothing answers.

    Tries ``dscacheutil`` first: on macOS it checks DNS, /etc/hosts and
    Bonjour/mDNS in one call, which is why phones, IoT gear and routers that
    don't answer a plain reverse-DNS query often still resolve here. Falls
    back to a plain PTR lookup for anything dscacheutil misses (or on a
    platform that doesn't have it).

    The system resolver often names nothing at all off a network whose DNS
    lacks PTR records for its clients, so after that a host on a private
    network is asked directly, by every method in DEVICE_PROBES at once
    (see _ask_device). A public address is never probed like that: its
    owner didn't ask to be port-knocked, and it would only be slow.
    """
    if not ip:
        return ""
    name = _resolve_dscacheutil(ip) or _resolve_reverse_dns(ip)
    if not name and _is_private(ip):
        name = _ask_device(ip)
    return name.rstrip(".") if name else ""


def _is_private(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return False


def _ask_device(ip: str) -> str:
    """Run every probe in DEVICE_PROBES against ``ip`` in parallel and take
    the answer of the earliest one in that list that has any, so a slow but
    trustworthy source still beats a quick guess. Each probe has its own
    short timeout, so this takes about as long as the slowest one, not the
    sum of them all."""
    probes = DEVICE_PROBES
    if not _on_link(ip):
        # Multicast never leaves this Mac's own networks: asking the group
        # about a host behind a router or VPN only waits out its timeout.
        probes = tuple(p for p in probes if p not in LINK_ONLY_PROBES)
    return first_answer([partial(probe, ip) for probe in probes], _usable)


def _on_link(ip: str) -> bool:
    """True if ``ip`` is in a network one of this Mac's interfaces is on."""
    global _local_networks
    loaded_at, networks = _local_networks
    if not loaded_at or time.monotonic() - loaded_at > _LOCAL_NETWORKS_TTL_SECONDS:
        networks = []
        for interface in network_interfaces.list_interfaces():
            try:
                networks.append(ipaddress.ip_network(interface.cidr))
            except ValueError:
                continue
        _local_networks = (time.monotonic(), networks)
    try:
        address = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(address in network for network in networks)


def _usable(name: str) -> bool:
    name = name.rstrip(".")
    return bool(re.search(r"[A-Za-z0-9]", name)) and name.lower() not in _PLACEHOLDER_NAMES


def _resolve_dscacheutil(ip: str) -> str:
    try:
        output = subprocess.run(
            ["/usr/bin/dscacheutil", "-q", "host", "-a", "address", ip],
            capture_output=True,
            text=True,
            timeout=2,
        ).stdout
    except (OSError, subprocess.SubprocessError):
        return ""
    match = _DSCACHEUTIL_NAME.search(output)
    return match.group(1) if match else ""


def _resolve_reverse_dns(ip: str) -> str:
    try:
        name, _, _ = socket.gethostbyaddr(ip)
    except (OSError, socket.herror, socket.gaierror):
        return ""
    return name


#: Ways of asking a device its own name, most trustworthy first: names the
#: device announces for itself, then names on its Windows/Samba services
#: (SMB and RDP first: they give the full DNS name where NetBIOS gives just
#: the upper-cased short one), then what its admin configured (SNMP, UPnP),
#: and last the name on its
#: certificate or the title of its web page, which may just be a model name.
DEVICE_PROBES: tuple[Callable[[str], str], ...] = (
    mdns.unicast_lookup,      # UDP 5353 — Macs, iPhones, printers, Avahi
    mdns.multicast_lookup,    # UDP 5353 via 224.0.0.251
    ntlm.smb_lookup,          # TCP 445 — Windows, Samba, macOS file sharing
    ntlm.rdp_lookup,          # TCP 3389 — Windows with Remote Desktop
    netbios.lookup,           # UDP 137 — Windows, Samba, NAS, printers
    mdns.llmnr_lookup,        # UDP 5355 — Windows
    snmp.lookup,              # UDP 161 — printers, switches, NAS, UPS
    ssdp.lookup,              # UDP 1900 — smart TVs, media boxes, routers, IoT
    tls_cert.lookup,          # TCP 443/8443 — admin pages of NAS, ESXi, routers
    http_title.lookup,        # TCP 80/443 — printers, cameras, routers
)

#: Probes that only reach the local link (multicast), skipped for a host
#: beyond it.
LINK_ONLY_PROBES = (mdns.multicast_lookup,)
