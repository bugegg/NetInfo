"""The grid's column definitions.

One table drives the view, the sort keys and every export format, so a column
added here shows up everywhere at once.
"""

from __future__ import annotations

import ipaddress
import time
from functools import lru_cache
from dataclasses import dataclass
from collections.abc import Callable
from typing import Any

from ..ping.mtu import format_mtu
from .host import HostEntry


def format_timestamp(value: float | None) -> str:
    if not value:
        return ""
    return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(value))


def format_duration(seconds: float) -> str:
    if seconds <= 0:
        return ""
    total = int(round(seconds))
    return f"{total // 3600}:{(total % 3600) // 60:02d}:{total % 60:02d}"


def format_ms(value: float | None) -> str:
    """Ping times render as whole milliseconds, as the original does."""
    return "" if value is None else str(int(round(value)))


@lru_cache(maxsize=1 << 16)
def ip_aware_key(text: str) -> tuple:
    """Sort key that orders dotted-quad IPv4 text numerically (octet by
    octet) instead of lexicographically, so .2 comes before .10. Anything
    that isn't a plain IPv4 address (a host name, or blank) sorts after
    every real address, alphabetically among itself.

    Cached: a live sort calls this for every comparison, several times a
    second, and parsing the address each time dominated the GUI thread.
    """
    try:
        return (0, int(ipaddress.IPv4Address(text)), "")
    except ValueError:
        return (1, 0, text.casefold())


@dataclass(frozen=True)
class Column:
    key: str
    title: str
    width: int
    numeric: bool
    #: Natural-typed value, used for sorting unless sort_value overrides it.
    value: Callable[[HostEntry], Any]
    #: Display string. Defaults to str() of the value.
    text: Callable[[HostEntry], str] | None = None
    #: Overrides the sort key when the display value isn't the right thing
    #: to compare by, e.g. ip_aware_key for a column of dotted-quad text.
    sort_value: Callable[[HostEntry], Any] | None = None

    def display(self, entry: HostEntry) -> str:
        if self.text is not None:
            return self.text(entry)
        value = self.value(entry)
        return "" if value is None else str(value)

    def sort_key(self, entry: HostEntry) -> Any:
        """Natural-typed value for sorting; None means "no value yet".

        The proxy sinks None to the bottom in both directions, so sorting by
        Last Ping Time descending shows the slowest host first rather than a
        block of hosts that have not been pinged.
        """
        if self.sort_value is not None:
            return self.sort_value(entry)
        return self.value(entry)


COLUMNS: tuple[Column, ...] = (
    Column("host_name", "Host Name", 150, False, lambda e: e.display_name,
           sort_value=lambda e: ip_aware_key(e.host)),
    Column("ip_address", "IP Address", 110, False, lambda e: e.ip_address,
           sort_value=lambda e: ip_aware_key(e.ip_address)),
    Column("all_resolved_ips", "All Resolved IPs", 220, False, lambda e: e.all_resolved_ips,
           lambda e: ", ".join(e.all_resolved_ips)),
    Column("reply_ip", "Reply IP Address", 120, False, lambda e: e.reply_ip,
           sort_value=lambda e: ip_aware_key(e.reply_ip)),
    Column("mac_address", "MAC Address", 130, False, lambda e: e.mac_address),
    Column("hostname", "Hostname", 160, False, lambda e: e.hostname),
    Column("dns_name", "DNS Name", 180, False, lambda e: e.dns_name),
    Column("vendor", "Vendor", 160, False, lambda e: e.vendor),
    Column("open_ports", "Open Ports", 120, False, lambda e: e.open_ports,
           lambda e: ", ".join(str(p) for p in e.open_ports)),
    Column("device_type", "Device Type (Guess)", 220, False, lambda e: e.device_type_guess),
    Column("mtu", "MTU", 60, True, lambda e: e.mtu,
           lambda e: "No reply" if e.mtu_no_reply else format_mtu(e.mtu)),
    Column("succeed_count", "Succeed Count", 95, True, lambda e: e.succeed_count),
    Column("failed_count", "Failed Count", 85, True, lambda e: e.failed_count),
    Column("consecutive_failed", "Consecutive Failed", 120, True,
           lambda e: e.consecutive_failed),
    Column("max_consecutive_failed", "Max. Consecutive Failed", 150, True,
           lambda e: e.max_consecutive_failed),
    Column("max_consecutive_failed_time", "Max. Consecutive Failed Time", 180, True,
           lambda e: e.max_consecutive_failed_seconds,
           lambda e: format_duration(e.max_consecutive_failed_seconds)),
    Column("percent_failed", "% Failed", 70, True, lambda e: e.percent_failed,
           lambda e: f"{e.percent_failed:.1f}%" if e.total_sent else ""),
    Column("total_sent", "Total Sent Pings", 110, True, lambda e: e.total_sent),
    Column("last_status", "Last Ping Status", 170, False,
           lambda e: e.last_status.value if e.last_status else ""),
    Column("last_rtt", "Last Ping Time", 100, True, lambda e: e.last_rtt_ms,
           lambda e: format_ms(e.last_rtt_ms)),
    Column("last_ttl", "Last Ping TTL", 95, True, lambda e: e.last_ttl),
    Column("average_rtt", "Average Ping Time", 120, True, lambda e: e.average_rtt_ms,
           lambda e: format_ms(e.average_rtt_ms)),
    Column("min_rtt", "Minimum Ping Time", 120, True, lambda e: e.min_rtt_ms,
           lambda e: format_ms(e.min_rtt_ms)),
    Column("max_rtt", "Maximum Ping Time", 120, True, lambda e: e.max_rtt_ms,
           lambda e: format_ms(e.max_rtt_ms)),
    Column("last_succeed_on", "Last Succeed On", 150, True,
           lambda e: e.last_succeed_on, lambda e: format_timestamp(e.last_succeed_on)),
    Column("last_failed_on", "Last Failed On", 150, True,
           lambda e: e.last_failed_on, lambda e: format_timestamp(e.last_failed_on)),
    Column("description", "Description", 160, False, lambda e: e.description),
    Column("group", "Group", 120, False, lambda e: e.group),
    Column("order", "Order", 60, True, lambda e: e.order),
    Column("disabled", "Disabled", 70, False, lambda e: not e.enabled,
           lambda e: "Yes" if not e.enabled else ""),
)

COLUMN_BY_KEY = {column.key: column for column in COLUMNS}
