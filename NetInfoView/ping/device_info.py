"""Resolves MAC, hostname, vendor, open ports and (for a named host) every
IP it resolves to — a batch at a time, off the GUI thread.

Each lookup here is blocking I/O — a subprocess call, a DNS query, or a TCP
connect attempt — that's cheap for one host but was previously run straight
on the Qt GUI thread once per host, every 30 seconds (ui/main_window.py's
device-info timer). Against a real /24 scan, most addresses don't answer,
and an unanswered reverse-DNS query is exactly the slow case for a resolver
(it waits out a timeout rather than failing fast) — multiplied by a couple
hundred hosts, that is the "freezes periodically" bug. resolve_batch() does
the same lookups but is meant to run inside ui/device_info_thread.py's
QThread, with the hostname queries, port scan and forward-DNS lookup (the
genuinely slow, networked parts) fanned out across thread pools so one
unresponsive host can't serialise behind another.
"""

from __future__ import annotations

import copy
import ipaddress
import socket
import time
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field

from ..fileio.vendor_db import PRIVATE_MAC_LABEL
from . import arp
from . import arp_scan
from . import dns_ptr
from . import hostname as hostname_lookup
from . import netbios
from . import port_scan
from . import snmp_arp

#: Reverse-DNS/dscacheutil calls, and forward lookups for every IP behind a
#: name, are I/O-bound (waiting on a socket or a subprocess), so a thread
#: pool larger than the CPU count is still a net win.
MAX_HOSTNAME_WORKERS = 24
#: While answers trickle in, they're reported at most this often, so each
#: shows up in the table as soon as it's found without flooding the GUI.
PROGRESS_INTERVAL_SECONDS = 0.25


@dataclass(slots=True)
class DeviceInfoJob:
    """One host's share of a sweep: what's already known, and what to look
    up. Named fields rather than a positional tuple — this module already
    grew past the point where that stayed easy to get right at every call
    site (ui/main_window.py builds a list of these each tick)."""

    key: int
    ip: str
    #: The host exactly as configured — may be a name, unlike ip (always an
    #: address). Needed to look up every IP a name resolves to; "" if the
    #: caller doesn't have it or the field isn't relevant.
    host: str = ""
    known_mac: str = ""
    needs_hostname: bool = False
    needs_dns_name: bool = False
    needs_ports: bool = False
    needs_all_ips: bool = False


@dataclass(slots=True)
class DeviceInfoResult:
    """What one sweep learned about one host. Named fields rather than a
    bare tuple, deliberately — same reasoning as DeviceInfoJob above."""

    key: int
    mac: str = ""
    hostname: str = ""
    #: The address's PTR name from the system's DNS servers.
    dns_name: str = ""
    vendor: str = ""
    #: Open TCP ports are plain ints; open UDP ports are "<port>/udp" strings
    #: (ping.port_scan.scan_many) so the two can't be confused once merged.
    open_ports: list[int | str] = field(default_factory=list)
    device_type: str = ""
    #: True once a port scan actually ran for this host, independent of
    #: whether open_ports came back empty (scanned, nothing open) or not
    #: attempted at all — the caller needs to tell those apart.
    ports_scanned: bool = False
    #: Every IPv4 address the host's name resolves to, sorted. Empty for a
    #: host that's already a literal IP (nothing to discover) as much as for
    #: one that failed to resolve — all_ips_looked_up distinguishes those.
    all_ips: list[str] = field(default_factory=list)
    all_ips_looked_up: bool = False


def _is_literal_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def resolve_all_ips(host: str) -> list[str]:
    """Every distinct IPv4 address `host`'s name resolves to, sorted.

    Empty for a host that's already a literal IP — there is nothing further
    to discover — or one whose name fails to resolve at all.
    """
    if not host or _is_literal_ip(host):
        return []
    try:
        infos = socket.getaddrinfo(
            host, None, family=socket.AF_INET, type=socket.SOCK_STREAM
        )
    except (OSError, UnicodeError):
        return []
    return sorted({info[4][0] for info in infos})


def resolve_batch(
    jobs: list[DeviceInfoJob],
    vendor_db,
    ports: port_scan.ParsedPorts | None = None,
    snmp_routers: list[str] | None = None,
    snmp_community: str = "public",
    snmp_auto: bool = False,
    report: Callable[[list[DeviceInfoResult]], None] | None = None,
) -> list[DeviceInfoResult]:
    """Resolve device info for every job in the batch.

    ``ports`` is the user-configurable TCP/UDP port list from the Options
    dialog (Settings.port_scan_ports, parsed by ping.port_scan.parse_ports);
    it applies to every host in the batch that opted into a port scan, same
    as scan_many's own default of STATIC_PORTS (TCP only) when this is left
    as None.

    MAC lookups reuse ping.arp's own cache and run sequentially (they're
    effectively free after the first host, since the whole ARP table is
    loaded once per cache window) and happen for every host with an IP.
    Hostname lookups, the port scan, and the all-IPs-for-a-name lookup are
    the expensive, networked parts, so the caller opts each host into each
    one individually (e.g. to back off a host that's never going to answer,
    or skip a host that's already been scanned) and only those run,
    concurrently.

    A host the Mac's ARP table has no MAC for (anything beyond the local
    link) is looked up in the ARP tables of ``snmp_routers`` over SNMP,
    one walk per router for the whole batch (ping.snmp_arp). With
    ``snmp_auto`` the usual gateway addresses of each host's network are
    tried as well, after the configured ones.

    ``report``, if given, is handed copies of the results so far after each
    stage (MAC and vendor, which take milliseconds; names; ports), so the
    caller can show what's known without waiting for the slowest stage.
    Fields only ever go from empty to filled between reports.
    """
    results: dict[int, DeviceInfoResult] = {}
    hostname_jobs: dict[int, str] = {}
    dns_name_jobs: dict[int, str] = {}
    port_jobs: dict[int, str] = {}
    all_ips_jobs: dict[int, str] = {}

    for job in jobs:
        mac = job.known_mac or (arp.lookup(job.ip) if job.ip else "")
        results[job.key] = DeviceInfoResult(key=job.key, mac=mac)
        if job.needs_hostname and job.ip:
            hostname_jobs[job.key] = job.ip
        if job.needs_dns_name and job.ip:
            dns_name_jobs[job.key] = job.ip
        if job.needs_ports and job.ip:
            port_jobs[job.key] = job.ip
        if job.needs_all_ips:
            all_ips_jobs[job.key] = job.host

    def fill_vendors() -> None:
        for result in results.values():
            if not result.mac or result.vendor:
                continue
            # A locally-administered MAC (e.g. a phone's "Private Wi-Fi
            # address") was never assigned to any vendor, so skip the
            # database rather than report it as simply unknown.
            if arp.is_locally_administered(result.mac):
                result.vendor = PRIVATE_MAC_LABEL
            else:
                result.vendor = vendor_db.lookup(result.mac) or ""

    last_report = 0.0

    def stage_done() -> None:
        nonlocal last_report
        fill_vendors()
        if report is not None:
            report([copy.copy(result) for result in results.values()])
        last_report = time.monotonic()

    def progress() -> None:
        """Report what's been found so far, if nothing was just reported."""
        if report is not None and time.monotonic() - last_report >= PROGRESS_INTERVAL_SECONDS:
            stage_done()

    # Names are the slowest part (each source waits out a timeout for a
    # host that doesn't answer it), so they start now and run alongside
    # the MAC lookups below. Both share one pool: (key, which field).
    name_jobs = [(key, ip, "hostname", hostname_lookup.resolve)
                 for key, ip in hostname_jobs.items()]
    if dns_name_jobs:
        servers = dns_ptr.system_nameservers()  # once for the whole batch
        name_jobs += [(key, ip, "dns_name", lambda ip: dns_ptr.lookup(ip, servers))
                      for key, ip in dns_name_jobs.items()]
    name_pool = None
    future_to_job = {}
    if name_jobs:
        name_pool = ThreadPoolExecutor(max_workers=min(MAX_HOSTNAME_WORKERS, len(name_jobs)))
        future_to_job = {
            name_pool.submit(lookup, ip): (key, field_name)
            for key, ip, field_name, lookup in name_jobs
        }

    # No ARP entry (on macOS 27, none at all: the app is handed an empty
    # table): ask the hosts on our own subnets for their MACs directly.
    missing = {job.key: job.ip for job in jobs if job.ip and not results[job.key].mac}
    if missing:
        found = arp_scan.scan(list(missing.values()))
        for key, ip in missing.items():
            results[key].mac = found.get(ip, "")
    stage_done()  # MAC and vendor from the ARP table and the ARP scan

    if snmp_routers or snmp_auto:
        missing = {job.key: job.ip for job in jobs if job.ip and not results[job.key].mac}
        if missing:
            routers = list(snmp_routers or [])
            if snmp_auto:
                routers += [gateway for gateway in snmp_arp.guess_gateways(list(missing.values()))
                            if gateway not in routers]
            found = snmp_arp.lookup_many(list(missing.values()), routers, snmp_community)
            for key, ip in missing.items():
                results[key].mac = found.get(ip, "")
            stage_done()

    # Still none (no ARP entry, or the OS hiding the table): a Windows PC or
    # server says its own MAC in reply to a NetBIOS node-status query.
    missing = {job.key: job.ip for job in jobs if job.ip and not results[job.key].mac}
    if missing:
        with ThreadPoolExecutor(max_workers=min(MAX_HOSTNAME_WORKERS, len(missing))) as pool:
            future_to_key = {pool.submit(netbios.lookup_mac, ip): key
                             for key, ip in missing.items()}
            for future in as_completed(future_to_key):
                try:
                    results[future_to_key[future]].mac = future.result() or ""
                except Exception:
                    continue
                progress()
        stage_done()  # every MAC this sweep will find

    if name_pool is not None:
        with name_pool:
            for future in as_completed(future_to_job):
                key, field_name = future_to_job[future]
                try:
                    name = future.result() or ""
                except Exception:
                    name = ""
                setattr(results[key], field_name, name)
                if name:
                    progress()
        stage_done()

    if port_jobs:
        tcp_ports = ports.tcp if ports is not None else None
        udp_ports = ports.udp if ports is not None else None
        open_by_key = port_scan.scan_many(port_jobs, ports=tcp_ports, udp_ports=udp_ports)
        for key, open_ports in open_by_key.items():
            results[key].open_ports = open_ports
            results[key].device_type = port_scan.guess_device_type(open_ports)
            results[key].ports_scanned = True

    if all_ips_jobs:
        worker_count = min(MAX_HOSTNAME_WORKERS, len(all_ips_jobs))
        with ThreadPoolExecutor(max_workers=worker_count) as pool:
            future_to_key = {
                pool.submit(resolve_all_ips, host): key
                for key, host in all_ips_jobs.items()
            }
            for future in as_completed(future_to_key):
                key = future_to_key[future]
                try:
                    results[key].all_ips = future.result()
                except Exception:
                    results[key].all_ips = []
                results[key].all_ips_looked_up = True

    return list(results.values())
