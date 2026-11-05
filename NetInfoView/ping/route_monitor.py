"""Route Monitor: ping every hop on the way to a host, round after round, so
each router's latency and loss can be followed over time (as PingPlotter
does).

Each round sends one probe per TTL, all at once, so a round never takes
longer than one timeout however long the route is. Every probe of every
round belongs to one ICMP flow (fixed identifier and checksum, see
ping/netpath.py), so a load-balancing router keeps it on one link and the
hops stay the same hops from round to round. The sequence number carries the
TTL and the round, so a late answer to an earlier round is never taken for
an answer to this one.

The first rounds probe up to MAX_HOPS; once the host answers, only up to its
hop. If the route gets longer (a router answers at the host's hop), the next
round looks all the way out again. A hop that answers from a new address for
CHANGE_ROUNDS rounds in a row is a route change.
"""

from __future__ import annotations

import select
import socket
import time
from collections.abc import Callable
from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, wait
from dataclasses import dataclass, field

from ..osinfo import IS_WINDOWS
from .netpath import ICMP_ECHO_REPLY, ICMP_UNREACHABLE, PAYLOAD, Answer, build_probe, flow_ident, parse

MAX_HOPS = 30
WAIT_MS = 1500
#: Once the host has answered, a round waits this long, or twice the host's
#: time if longer, for routers slower to answer than the host, then ends:
#: a hop that never answers needn't hold every round up for WAIT_MS.
SETTLE_MS = 500
#: Rounds in a row a hop must answer from a new address to count as a change.
CHANGE_ROUNDS = 3
#: Rounds an address is remembered at its hop. A router balancing packets
#: over two links answers from both by turns; going back to one it has
#: answered from lately isn't a route change.
KNOWN_ROUNDS = 100
#: Rounds at the start in which a hop's other addresses are learned rather
#: than reported: a load-balanced hop shows its second one only by chance.
WARMUP_ROUNDS = 10
#: Net Path's flows are 0-7; this one is apart so both can run at once.
FLOW = 12
#: Sequence numbers: 0xB000 | round (6 bits) << 6 | TTL (6 bits).
_SEQUENCE_BASE = 0xB000

#: round_probe(ip, ttls, round number) -> {ttl: Answer} for the TTLs that answered.
RoundProbe = Callable[[str, list[int], int], dict[int, Answer]]


def sequence_for(round_no: int, ttl: int) -> int:
    return _SEQUENCE_BASE | (round_no % 64) << 6 | (ttl & 0x3F)


def settle(deadline: float, now: float, answer: Answer) -> float:
    """When the round should end, given an answer just in at `now`."""
    if not (answer.reached or answer.unreachable):
        return deadline
    return min(deadline, now + max(SETTLE_MS, 2 * answer.rtt_ms) / 1000)


def round_socket(ip: str, ttls: list[int], round_no: int, wait_ms: int = WAIT_MS) -> dict[int, Answer]:
    """One probe per TTL over one unprivileged ICMP datagram socket."""
    answers: dict[int, Answer] = {}
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_ICMP)
    except OSError:
        return answers
    with sock:
        ident = flow_ident(FLOW)
        sent: dict[int, tuple[int, float]] = {}  # sequence -> (ttl, time sent)
        for ttl in ttls:
            sequence = sequence_for(round_no, ttl)
            try:
                sock.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, ttl)
                sock.sendto(build_probe(ident, sequence, FLOW), (ip, 0))
            except OSError:
                continue
            sent[sequence] = (ttl, time.perf_counter())
        deadline = time.perf_counter() + wait_ms / 1000
        while len(answers) < len(sent):
            left = deadline - time.perf_counter()
            if left <= 0 or not select.select([sock], [], [], left)[0]:
                break
            try:
                data, (source, _) = sock.recvfrom(2048)
            except OSError:
                break
            parsed = parse(data)
            if parsed is None:
                continue
            kind, _, got_ident, sequence = parsed
            if got_ident != ident or sequence not in sent:
                continue
            ttl, started = sent[sequence]
            if ttl in answers:
                continue
            now = time.perf_counter()
            answer = answers[ttl] = Answer(
                source, (now - started) * 1000,
                reached=kind == ICMP_ECHO_REPLY,
                unreachable=kind == ICMP_UNREACHABLE,
            )
            deadline = settle(deadline, now, answer)
    return answers


def round_windows(ip: str, ttls: list[int], round_no: int, wait_ms: int = WAIT_MS) -> dict[int, Answer]:
    """One IcmpSendEcho per TTL, side by side."""
    from .icmp_windows import echo
    from .result import PingStatus

    def one(ttl: int) -> tuple[int, Answer | None]:
        result = echo(ip, wait_ms, PAYLOAD, ttl=ttl, dont_fragment=False)
        if not result.reply_ip or result.status in (
                PingStatus.TIMEOUT, PingStatus.NO_RESOURCES, PingStatus.GENERAL_FAILURE):
            return ttl, None
        rtt = result.rtt_ms if result.rtt_ms is not None else float(wait_ms)
        return ttl, Answer(
            result.reply_ip, rtt,
            reached=result.status is PingStatus.SUCCEEDED,
            unreachable=result.status not in (PingStatus.SUCCEEDED, PingStatus.TTL_EXPIRED),
        )

    pool = ThreadPoolExecutor(max_workers=len(ttls) or 1)
    pending = {pool.submit(one, ttl) for ttl in ttls}
    answers: dict[int, Answer] = {}
    deadline = time.perf_counter() + wait_ms / 1000 + 0.2
    try:
        while pending:
            left = deadline - time.perf_counter()
            if left <= 0:
                break
            done, pending = wait(pending, timeout=left, return_when=FIRST_COMPLETED)
            now = time.perf_counter()
            for future in done:
                ttl, answer = future.result()
                if answer is not None:
                    answers[ttl] = answer
                    deadline = settle(deadline, now, answer)
    finally:
        # Echoes still out finish on their own within wait_ms; their
        # answers are left out like any that came too late.
        pool.shutdown(wait=False, cancel_futures=True)
    return answers


def default_round_probe() -> RoundProbe:
    return round_windows if IS_WINDOWS else round_socket


@dataclass(slots=True, frozen=True)
class HopSample:
    timestamp: float
    ttl: int
    #: Who answered; "" if nobody did.
    address: str
    #: None for a lost probe.
    rtt_ms: float | None


@dataclass(frozen=True)
class RouteChange:
    timestamp: float
    ttl: int
    old: str
    new: str


@dataclass
class RoundResult:
    timestamp: float
    #: One per TTL probed and kept, 1 up to the host's hop (or the furthest
    #: answer while the host hasn't answered).
    samples: list[HopSample] = field(default_factory=list)
    changes: list[RouteChange] = field(default_factory=list)
    #: The host's hop, or None while it isn't known.
    hop_count: int | None = None


class RouteTracker:
    """Which TTLs to probe next and what a round's answers mean: the host's
    hop, each hop's address, route changes. No I/O, so it can be tested."""

    def __init__(self, max_hops: int = MAX_HOPS) -> None:
        self.max_hops = max_hops
        self.hop_count: int | None = None
        self.round = 0
        #: ttl -> the address that hop answers from.
        self.addresses: dict[int, str] = {}
        #: ttl -> (a new address, rounds in a row it has answered from).
        self._pending: dict[int, tuple[str, int]] = {}
        #: The furthest hop that has answered.
        self._furthest = 0
        #: ttl -> {address: the last round it answered that hop}.
        self._known: dict[int, dict[str, int]] = {}

    def ttls(self) -> list[int]:
        return list(range(1, (self.hop_count or self.max_hops) + 1))

    def record(self, timestamp: float, answers: dict[int, Answer]) -> RoundResult:
        probed = self.hop_count or self.max_hops
        self.round += 1
        reached = min((t for t, a in answers.items() if t <= probed and (a.reached or a.unreachable)),
                      default=None)
        if reached is not None:
            limit = reached
            self.hop_count = reached
        elif self.hop_count is not None:
            limit = self.hop_count
            if limit in answers:
                # A router now answers where the host did: the route is
                # longer. Look all the way out again next round.
                self.hop_count = None
        else:
            # The host hasn't answered: keep every hop that ever has, so a
            # silent round counts as loss on them rather than leaving a gap,
            # and hop 1 at least, so a network that's down shows as down.
            limit = max(max((t for t in answers if t <= probed), default=0), self._furthest, 1)
        self._furthest = max(self._furthest, max((t for t in answers if t <= limit), default=0))

        result = RoundResult(timestamp, hop_count=self.hop_count)
        for ttl in range(1, limit + 1):
            answer = answers.get(ttl)
            if answer is None:
                result.samples.append(HopSample(timestamp, ttl, "", None))
                continue
            result.samples.append(HopSample(timestamp, ttl, answer.address, answer.rtt_ms))
            change = self._track(timestamp, ttl, answer.address)
            if change is not None:
                result.changes.append(change)
        return result

    def _track(self, timestamp: float, ttl: int, address: str) -> RouteChange | None:
        current = self.addresses.get(ttl)
        # Addresses this hop has been shown as, and the round each last was.
        known = self._known.setdefault(ttl, {})
        if current is None or address == current:
            self.addresses[ttl] = address
            known[address] = self.round
            self._pending.pop(ttl, None)
            return None
        last = known.get(address)
        if self.round <= WARMUP_ROUNDS or (last is not None and self.round - last <= KNOWN_ROUNDS):
            # One of the hop's usual addresses: show it, but it's no change.
            self._pending.pop(ttl, None)
            self.addresses[ttl] = address
            known[address] = self.round
            return None
        seen, count = self._pending.get(ttl, (address, 0))
        count = count + 1 if seen == address else 1
        if count < CHANGE_ROUNDS:
            self._pending[ttl] = (address, count)
            return None
        self._pending.pop(ttl, None)
        self.addresses[ttl] = address
        known[address] = self.round
        return RouteChange(timestamp, ttl, current, address)


def resolve(target: str) -> str:
    """The IPv4 address of a host name or address; raises OSError."""
    target = target.strip()
    infos = socket.getaddrinfo(target, None, socket.AF_INET, socket.SOCK_DGRAM)
    if not infos:
        raise OSError(f"{target} has no IPv4 address")
    return infos[0][4][0]
