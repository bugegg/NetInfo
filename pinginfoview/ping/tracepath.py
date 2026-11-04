"""Trace Path MTU: the path MTU to each hop on the way to a host, like Linux's
``tracepath``, so a drop (a PPPoE link at 1492, a VPN tunnel at 1400, ...)
can be pinned on the router where it happens.

Like ping/mtu.py this drives ``/sbin/ping -D`` (Don't Fragment), adding
``-m <ttl>`` so each probe dies at one hop and that router answers "Time to
live exceeded". A hop that answers a probe of the current path MTU proves
every link up to it carries that size. When a link can't, the router in
front of it usually says so ("frag needed and DF set (MTU 1492)") and the
MTU it names is taken as is; when it stays silent instead, the size is found
by a binary search at that hop, the same way Check MTU does it.

On Windows each probe is an IcmpSendEcho with the TTL and Don't Fragment
set (ping/icmp_windows.py). It doesn't pass on the MTU a "fragmentation
needed" names, so a drop is always found by the search there.
"""

from __future__ import annotations

import re
import subprocess
import threading
from collections.abc import Callable
from dataclasses import dataclass

from ..osinfo import IS_WINDOWS
from .mtu import (
    ETHERNET_PAYLOAD, HEADERS, MAX_MTU, PING, WAIT_ARGS, WAIT_MS, LinkMtu, route_mtu,
)

MAX_HOPS = 30

#: What came back for one probe.
EXCEEDED = "exceeded"  # a router on the way: Time to live exceeded
REACHED = "reached"  # the host itself answered the echo
FRAG = "frag"  # a router: too big for the next link, DF set
UNREACHABLE = "unreachable"  # any other ICMP error, e.g. host unreachable
TIMEOUT = "timeout"  # nothing, or the Mac's own interface refused the size

#: Kinds that prove a probe of that size got as far as its TTL allowed.
ANSWERED = (EXCEEDED, REACHED, UNREACHABLE)

_FROM = re.compile(r"^\d+ bytes from ([0-9A-Fa-f.:]+): (.*)$", re.MULTILINE)
_MTU = re.compile(r"MTU (\d+)")


@dataclass(frozen=True)
class Reply:
    kind: str
    source: str = ""
    mtu: int | None = None  # the next link's MTU, for FRAG
    text: str = ""  # ping's own wording, for UNREACHABLE


@dataclass
class Hop:
    ttl: int
    address: str = ""  # "" when nothing at this hop answered
    #: The largest packet that reaches this hop unfragmented, or None if
    #: the hop never answered.
    mtu: int | None = None
    reached: bool = False  # this is the host being traced
    unreachable: bool = False  # a router said the host can't be reached
    note: str = ""


Probe = Callable[[str, int, int], Reply]


def parse(output: str) -> Reply:
    """The Reply in ``/sbin/ping -c 1`` output (stdout and stderr merged)."""
    match = _FROM.search(output)
    if match is None:
        return Reply(TIMEOUT)
    source, rest = match.groups()
    if "icmp_seq=" in rest:
        return Reply(REACHED, source)
    if "Time to live exceeded" in rest:
        return Reply(EXCEEDED, source)
    if "frag needed" in rest.lower():
        mtu = _MTU.search(rest)
        return Reply(FRAG, source, int(mtu.group(1)) if mtu else None)
    return Reply(UNREACHABLE, source, text=rest.strip())


def probe(ip: str, ttl: int, payload: int) -> Reply:
    """One ping of `payload` bytes with Don't Fragment set that may travel
    `ttl` hops. Nothing back is retried once, so a stray loss isn't taken
    for "too big"."""
    reply = Reply(TIMEOUT)
    for _ in range(2):
        reply = _ping_once(ip, ttl, payload)
        if reply.kind != TIMEOUT:
            break
    return reply


def _echo_once_windows(ip: str, ttl: int, payload: int) -> Reply:
    """One IcmpSendEcho, as the Reply ``/sbin/ping`` would have given."""
    from .icmp_windows import echo

    result = echo(ip, WAIT_MS, payload, ttl=ttl, dont_fragment=True)
    return reply_for_status(result.status, result.reply_ip)


def reply_for_status(status, source: str) -> Reply:
    """A ping/result.PingStatus (and who sent it) as a Reply."""
    from .result import PingStatus

    if status is PingStatus.SUCCEEDED:
        return Reply(REACHED, source)
    if status is PingStatus.TTL_EXPIRED:
        return Reply(EXCEEDED, source)
    if status is PingStatus.FRAGMENTATION_NEEDED:
        return Reply(FRAG, source)
    if status in (PingStatus.TIMEOUT, PingStatus.NO_RESOURCES,
                  PingStatus.GENERAL_FAILURE) or not source:
        return Reply(TIMEOUT)
    return Reply(UNREACHABLE, source, text=status.value)


def _ping_once(ip: str, ttl: int, payload: int) -> Reply:
    """One ``/sbin/ping``, stopped as soon as anything answers. ping itself
    exits early only on the echo reply: after "Time to live exceeded" or
    "frag needed" it would sit out its interval and wait time (~2 s a hop)."""
    if IS_WINDOWS:
        return _echo_once_windows(ip, ttl, payload)
    try:
        process = subprocess.Popen(
            [PING, "-D", "-n", "-c", "1", *WAIT_ARGS, "-m", str(ttl),
             "-s", str(payload), ip],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
        )
    except OSError:
        return Reply(TIMEOUT)
    # ping ends by itself after WAIT_MS; this only guards against a hang.
    watchdog = threading.Timer(WAIT_MS / 1000 + 2, process.kill)
    watchdog.start()
    output = ""
    try:
        for line in process.stdout:
            output += line
            if _FROM.search(line):
                break
    finally:
        watchdog.cancel()
        if process.poll() is None:
            process.kill()
        process.wait()
        process.stdout.close()
    return parse(output)


def trace_hop(ip: str, ttl: int, mtu: int, probe: Probe = probe, known: bool = True) -> Hop:
    """Hop `ttl` on the way to `ip`, given that `mtu` reached the hop before
    it. The Hop's mtu is the new path MTU (None if the hop stayed silent).
    `known` is False while `mtu` is only the MAX_MTU ceiling, not something
    measured, so finding less isn't reported as a drop."""
    reply = probe(ip, ttl, mtu - HEADERS)
    reported_by = ""
    # A router in front of a smaller link names its MTU: take it and retry.
    while reply.kind == FRAG and reply.mtu is not None and HEADERS < reply.mtu < mtu:
        mtu, reported_by = reply.mtu, reply.source
        reply = probe(ip, ttl, mtu - HEADERS)

    searched = False
    if reply.kind not in ANSWERED:
        small = probe(ip, ttl, 0)
        if small.kind not in ANSWERED:
            return Hop(ttl, note="No reply")
        # Answers small probes only: big ones are dropped without a word
        # somewhere before this hop, so search for the size that gets through.
        good, bad, reply = 0, mtu - HEADERS, small
        # Most links are standard Ethernet: settle that in two probes before
        # searching the whole range up to the ceiling.
        for size in (ETHERNET_PAYLOAD, ETHERNET_PAYLOAD + 1):
            if not good < size < bad:
                continue
            attempt = probe(ip, ttl, size)
            if attempt.kind not in ANSWERED:
                bad = size
                break
            good, reply = size, attempt
        while bad - good > 1:
            middle = (good + bad) // 2
            attempt = probe(ip, ttl, middle)
            if attempt.kind in ANSWERED:
                good, reply = middle, attempt
            else:
                bad = middle
        mtu, searched = good + HEADERS, True

    hop = Hop(ttl, reply.source, mtu, reached=reply.kind == REACHED,
              unreachable=reply.kind == UNREACHABLE)
    if reported_by:
        hop.note = f"MTU drops to {mtu} (reported by {reported_by})"
    elif searched and known:
        hop.note = f"MTU drops to {mtu} (no router reported it)"
    if reply.kind == UNREACHABLE:
        hop.note = "; ".join(filter(None, (hop.note, reply.text)))
    return hop


def trace(
    ip: str,
    on_hop: Callable[[Hop], None],
    probe: Probe = probe,
    max_hops: int = MAX_HOPS,
    stopped: Callable[[], bool] = lambda: False,
    link_mtu: LinkMtu = route_mtu,
) -> None:
    """Report each hop to `ip` in turn until it answers itself, a router
    says it can't be reached, `max_hops` runs out or `stopped()` is true."""
    # Start from the Mac's own interface MTU when it's known (and probe-able).
    interface_mtu = link_mtu(ip)
    known = interface_mtu is not None and interface_mtu <= MAX_MTU
    mtu = interface_mtu if known else MAX_MTU
    for ttl in range(1, max_hops + 1):
        if stopped():
            return
        hop = trace_hop(ip, ttl, mtu, probe, known)
        if hop.mtu is not None:
            mtu, known = hop.mtu, True
        on_hop(hop)
        if hop.reached or hop.unreachable:
            return
