"""One row of the main grid: a target plus its running statistics."""

from __future__ import annotations

import time
from dataclasses import dataclass, field

from ..ping.engine import PingTarget
from ..ping.result import PingResult, PingStatus


@dataclass
class HostEntry:
    """A pinged host and everything the grid reports about it.

    Counters update incrementally — the average is a running mean, so memory
    does not grow with the number of pings even over a multi-day run.
    """

    key: int
    host: str
    port: int | None = None
    description: str = ""
    group: str = ""
    order: int = 0
    enabled: bool = True

    ip_address: str = ""
    reply_ip: str = ""
    mac_address: str = ""
    #: The device's own network name (reverse DNS / mDNS), not what the user typed.
    hostname: str = ""
    #: The address's name in DNS (PTR), from the system's DNS servers.
    dns_name: str = ""
    #: Manufacturer, looked up from the MAC's IEEE OUI prefix.
    vendor: str = ""
    #: Ports found open by ping.port_scan.scan_many: a plain int for TCP, or
    #: an "<port>/udp" string for UDP.
    open_ports: list[int | str] = field(default_factory=list)
    #: Best-effort label from ping.port_scan.guess_device_type.
    device_type_guess: str = ""
    #: True once a port scan has actually run for this host — distinct from
    #: open_ports being empty, which just as validly means "scanned, found
    #: nothing open" as "never scanned yet".
    ports_scanned: bool = False
    #: Every IP the host's name resolves to (empty for a host that's already
    #: a literal IP — there's nothing to discover — or whose name fails to
    #: resolve). May be more than one for a load-balanced/CDN name; ip_address
    #: above is only the one actually being pinged.
    all_resolved_ips: list[str] = field(default_factory=list)
    #: True once the all-IPs lookup has actually run — see ports_scanned.
    all_ips_resolved: bool = False
    #: Path MTU in bytes from the last Check MTU, None if not known.
    mtu: int | None = None
    #: True when Check MTU ran but the host didn't answer at all.
    mtu_no_reply: bool = False

    succeed_count: int = 0
    failed_count: int = 0
    consecutive_failed: int = 0
    max_consecutive_failed: int = 0
    max_consecutive_failed_seconds: float = 0.0

    last_status: PingStatus | None = None
    last_rtt_ms: float | None = None
    last_ttl: int | None = None
    min_rtt_ms: float | None = None
    max_rtt_ms: float | None = None
    _rtt_total_ms: float = 0.0

    last_succeed_on: float | None = None
    last_failed_on: float | None = None
    #: When the current run of failures began, for the longest-outage figure.
    _failure_streak_started: float | None = None

    @property
    def display_name(self) -> str:
        return f"{self.host}:{self.port}" if self.port is not None else self.host

    @property
    def total_sent(self) -> int:
        return self.succeed_count + self.failed_count

    @property
    def percent_failed(self) -> float:
        total = self.total_sent
        return (self.failed_count / total * 100.0) if total else 0.0

    @property
    def average_rtt_ms(self) -> float | None:
        if not self.succeed_count:
            return None
        return self._rtt_total_ms / self.succeed_count

    @property
    def is_tcp(self) -> bool:
        return self.port is not None

    def to_target(self) -> PingTarget:
        return PingTarget(
            key=self.key,
            host=self.host,
            port=self.port,
            enabled=self.enabled,
            resolved_ip=self.ip_address,
        )

    # -- statistics --------------------------------------------------------

    def apply(self, result: PingResult) -> None:
        """Fold one ping result into the running statistics."""
        self.last_status = result.status
        self.last_rtt_ms = result.rtt_ms
        self.last_ttl = result.ttl
        if result.reply_ip:
            self.reply_ip = result.reply_ip
        if result.destination_ip:
            self.ip_address = result.destination_ip

        if result.succeeded:
            self._apply_success(result)
        else:
            self._apply_failure(result)

    def _apply_success(self, result: PingResult) -> None:
        self.succeed_count += 1
        self.consecutive_failed = 0
        self._failure_streak_started = None
        self.last_succeed_on = result.timestamp
        rtt = result.rtt_ms
        if rtt is None:
            return
        self._rtt_total_ms += rtt
        if self.min_rtt_ms is None or rtt < self.min_rtt_ms:
            self.min_rtt_ms = rtt
        if self.max_rtt_ms is None or rtt > self.max_rtt_ms:
            self.max_rtt_ms = rtt

    def _apply_failure(self, result: PingResult) -> None:
        self.failed_count += 1
        self.consecutive_failed += 1
        self.last_failed_on = result.timestamp
        if self._failure_streak_started is None:
            self._failure_streak_started = result.timestamp
        self.max_consecutive_failed = max(
            self.max_consecutive_failed, self.consecutive_failed
        )
        streak = result.timestamp - self._failure_streak_started
        self.max_consecutive_failed_seconds = max(
            self.max_consecutive_failed_seconds, streak
        )

    def reset_statistics(self) -> None:
        """Clear counters but keep identity — the Edit > Clear Statistics action."""
        self.succeed_count = 0
        self.failed_count = 0
        self.consecutive_failed = 0
        self.max_consecutive_failed = 0
        self.max_consecutive_failed_seconds = 0.0
        self.last_status = None
        self.last_rtt_ms = None
        self.last_ttl = None
        self.min_rtt_ms = None
        self.max_rtt_ms = None
        self._rtt_total_ms = 0.0
        self.last_succeed_on = None
        self.last_failed_on = None
        self._failure_streak_started = None
        self.reply_ip = ""
