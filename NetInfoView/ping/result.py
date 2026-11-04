"""Shared result types for the ICMP and TCP ping paths."""

from __future__ import annotations

import time
from dataclasses import dataclass
from enum import Enum


class PingStatus(str, Enum):
    """Outcome of a single ping, worded as PingInfoView words it."""

    SUCCEEDED = "Succeeded"
    TIMEOUT = "Request Timeout"
    NET_UNREACHABLE = "Destination Net Unreachable"
    HOST_UNREACHABLE = "Destination Host Unreachable"
    PROTOCOL_UNREACHABLE = "Destination Protocol Unreachable"
    PORT_UNREACHABLE = "Destination Port Unreachable"
    FRAGMENTATION_NEEDED = "Packet Needs To Be Fragmented"
    ADMIN_PROHIBITED = "Administratively Prohibited"
    TTL_EXPIRED = "TTL Expired In Transit"
    SOURCE_QUENCH = "Source Quench"
    BAD_DESTINATION = "Bad Destination"
    NO_RESOURCES = "No Resources"
    GENERAL_FAILURE = "General Failure"
    CONNECTION_REFUSED = "Connection Refused"

    @property
    def succeeded(self) -> bool:
        return self is PingStatus.SUCCEEDED


#: ICMP (type, code) -> status. Codes absent from a type's map fall back to the
#: type's catch-all entry under code ``None``.
_ICMP_STATUS: dict[int, dict[int | None, PingStatus]] = {
    3: {
        0: PingStatus.NET_UNREACHABLE,
        1: PingStatus.HOST_UNREACHABLE,
        2: PingStatus.PROTOCOL_UNREACHABLE,
        3: PingStatus.PORT_UNREACHABLE,
        4: PingStatus.FRAGMENTATION_NEEDED,
        9: PingStatus.ADMIN_PROHIBITED,
        10: PingStatus.ADMIN_PROHIBITED,
        13: PingStatus.ADMIN_PROHIBITED,
        None: PingStatus.HOST_UNREACHABLE,
    },
    4: {None: PingStatus.SOURCE_QUENCH},
    11: {None: PingStatus.TTL_EXPIRED},
    12: {None: PingStatus.BAD_DESTINATION},
}


def status_for_icmp(icmp_type: int, icmp_code: int) -> PingStatus:
    """Map an ICMP error type/code onto a displayable status."""
    by_code = _ICMP_STATUS.get(icmp_type)
    if by_code is None:
        return PingStatus.GENERAL_FAILURE
    return by_code.get(icmp_code, by_code[None])


@dataclass(slots=True)
class PingResult:
    """One ping attempt against one host."""

    status: PingStatus
    rtt_ms: float | None = None
    #: Address that answered. Empty on a timeout.
    reply_ip: str = ""
    ttl: int | None = None
    #: Address the ping was sent to, i.e. the forward lookup of the host name.
    destination_ip: str = ""
    #: Wall-clock time of the attempt, for the "Last Succeed/Failed On" columns.
    timestamp: float = 0.0

    def __post_init__(self) -> None:
        if not self.timestamp:
            self.timestamp = time.time()

    @property
    def succeeded(self) -> bool:
        return self.status.succeeded
