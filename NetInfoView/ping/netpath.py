"""Net Path: every route the packets to a host can take, hop by hop.

A plain traceroute follows one route. Routers that balance load over
several links (ECMP) pick the link from a hash of each packet's header
fields, so packets to the same host can take different routes. Net Path
sends ``FLOWS`` probe *flows* each TTL; within a flow every probe has the
same ICMP identifier and checksum (the payload absorbs the changing
sequence number, as Paris traceroute does), so a load-balancing router
sends one flow down one link every time and the hops a flow visits form one
real route. The routes of all flows together are the path graph.

On macOS the probes go out over an unprivileged ICMP datagram socket (see
ping/icmp.py). Windows' IcmpSendEcho picks the identifier itself, so there
the flows can't be pinned: each probe may hash differently, and the graph
may show a link between two hops of different routes.
"""

from __future__ import annotations

import os
import select
import socket
import struct
import time
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field

from ..osinfo import IS_WINDOWS

FLOWS = 8
MAX_HOPS = 30
WAIT_MS = 1500
#: Silent TTLs in a row after which a sweep gives up on reaching the host.
SILENT_LIMIT = 6
PAYLOAD = 24

ICMP_ECHO_REQUEST = 8
ICMP_ECHO_REPLY = 0
ICMP_UNREACHABLE = 3
_HEADER = struct.Struct("!BBHHH")  # type, code, checksum, identifier, sequence
#: Sequence numbers are 0xA000 + TTL, apart from the ping engine's low ones.
_SEQUENCE_BASE = 0xA000


@dataclass(frozen=True)
class Answer:
    """What came back to one probe."""

    address: str
    rtt_ms: float
    reached: bool = False  # the host itself answered
    unreachable: bool = False  # a router said the host can't be reached


#: probe(ip, ttl, flows) -> {flow: Answer} for the flows that got an answer.
Probe = Callable[[str, int, list[int]], dict[int, Answer]]


@dataclass
class Sweep:
    """One trace of every flow to the host."""

    started: float
    flows: int
    #: routes[flow][ttl - 1] is that hop's Answer, or None if it was silent.
    routes: list[list[Answer | None]] = field(default_factory=list)

    def reached_flows(self) -> int:
        return sum(any(a is not None and a.reached for a in route) for route in self.routes)

    @property
    def finished(self) -> bool:
        return bool(self.routes)


def ones_sum(data: bytes) -> int:
    """RFC 1071 one's-complement sum of 16-bit words."""
    if len(data) % 2:
        data += b"\x00"
    total = sum(struct.unpack(f"!{len(data) // 2}H", data))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return total


def flow_ident(flow: int) -> int:
    """The ICMP identifier of a flow: this process's, plus the flow."""
    return ((os.getpid() & 0x0FFF) << 4 | flow) & 0xFFFF


def build_probe(ident: int, sequence: int, flow: int, payload: int = PAYLOAD) -> bytes:
    """An echo request whose checksum depends only on `flow`: the first two
    payload bytes are chosen to cancel whatever the sequence adds."""
    filler = bytes((ord("a") + (i % 23)) for i in range(max(0, payload - 2)))
    target = (0x1000 + flow * 0x0111) & 0xFFFF  # the one's sum every probe of the flow has
    partial = ones_sum(_HEADER.pack(ICMP_ECHO_REQUEST, 0, 0, ident, sequence) + filler)
    adjust = (target - partial) % 0xFFFF
    body = struct.pack("!H", adjust) + filler
    checksum = ~ones_sum(_HEADER.pack(ICMP_ECHO_REQUEST, 0, 0, ident, sequence) + body) & 0xFFFF
    return _HEADER.pack(ICMP_ECHO_REQUEST, 0, checksum, ident, sequence) + body


def _ip_header_length(data: bytes) -> int:
    if not data or data[0] >> 4 != 4:
        return 0
    length = (data[0] & 0x0F) * 4
    return length if 20 <= length <= len(data) else 0


def parse(data: bytes) -> tuple[int, int, int, int] | None:
    """(icmp type, icmp code, identifier, sequence) of what a received packet
    answers: its own for an echo reply, the quoted probe's for an error."""
    offset = _ip_header_length(data)
    if len(data) < offset + _HEADER.size:
        return None
    kind, code, _, ident, sequence = _HEADER.unpack_from(data, offset)
    if kind == ICMP_ECHO_REPLY:
        return kind, code, ident, sequence
    quoted = data[offset + 8:]
    inner = _ip_header_length(quoted)
    if not inner or len(quoted) < inner + _HEADER.size:
        return None
    _, _, _, ident, sequence = _HEADER.unpack_from(quoted, inner)
    return kind, code, ident, sequence


def probe_socket(ip: str, ttl: int, flows: list[int], wait_ms: int = WAIT_MS) -> dict[int, Answer]:
    """One probe per flow at `ttl`, all at once, over an ICMP datagram socket."""
    answers: dict[int, Answer] = {}
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_ICMP)
    except OSError:
        return answers
    with sock:
        try:
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, ttl)
        except OSError:
            return answers
        sequence = _SEQUENCE_BASE + ttl
        sent: dict[int, tuple[int, float]] = {}  # ident -> (flow, time sent)
        for flow in flows:
            ident = flow_ident(flow)
            try:
                sock.sendto(build_probe(ident, sequence, flow), (ip, 0))
            except OSError:
                continue
            sent[ident] = (flow, time.perf_counter())
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
            kind, code, ident, seq = parsed
            if seq != sequence or ident not in sent:
                continue
            flow, started = sent[ident]
            if flow in answers:
                continue
            answers[flow] = Answer(
                source, (time.perf_counter() - started) * 1000,
                reached=kind == ICMP_ECHO_REPLY,
                unreachable=kind == ICMP_UNREACHABLE,
            )
    return answers


def probe_windows(ip: str, ttl: int, flows: list[int], wait_ms: int = WAIT_MS) -> dict[int, Answer]:
    """One IcmpSendEcho per flow at `ttl`, side by side."""
    from .icmp_windows import echo
    from .result import PingStatus

    def one(flow: int) -> tuple[int, Answer | None]:
        result = echo(ip, wait_ms, PAYLOAD + flow, ttl=ttl, dont_fragment=False)
        if not result.reply_ip or result.status in (
                PingStatus.TIMEOUT, PingStatus.NO_RESOURCES, PingStatus.GENERAL_FAILURE):
            return flow, None
        rtt = result.rtt_ms if result.rtt_ms is not None else float(wait_ms)
        return flow, Answer(
            result.reply_ip, rtt,
            reached=result.status is PingStatus.SUCCEEDED,
            unreachable=result.status not in (PingStatus.SUCCEEDED, PingStatus.TTL_EXPIRED),
        )

    with ThreadPoolExecutor(max_workers=len(flows) or 1) as pool:
        return {flow: answer for flow, answer in pool.map(one, flows) if answer is not None}


def default_probe() -> Probe:
    return probe_windows if IS_WINDOWS else probe_socket


def sweep(
    ip: str,
    probe: Probe | None = None,
    flows: int = FLOWS,
    max_hops: int = MAX_HOPS,
    stopped: Callable[[], bool] = lambda: False,
    on_ttl: Callable[[int], None] = lambda ttl: None,
) -> Sweep:
    """Trace every flow to `ip`, one TTL at a time. A flow stops once the
    host (or a router saying it's unreachable) answers; the sweep stops when
    every flow has, `max_hops` runs out, or SILENT_LIMIT TTLs in a row bring
    no answer at all."""
    probe = probe or default_probe()
    result = Sweep(time.time(), flows, [[] for _ in range(flows)])
    active = list(range(flows))
    silent = 0
    for ttl in range(1, max_hops + 1):
        if stopped() or not active:
            break
        on_ttl(ttl)
        answers = probe(ip, ttl, active)
        # Routers rate-limit their ICMP errors: ask once more before
        # calling a flow's hop silent.
        missing = [f for f in active if f not in answers]
        if missing and not stopped():
            answers.update(probe(ip, ttl, missing))
        for flow in active:
            result.routes[flow].append(answers.get(flow))
        active = [f for f in active if not (f in answers and (answers[f].reached or answers[f].unreachable))]
        silent = 0 if answers else silent + 1
        if silent >= SILENT_LIMIT:
            break
    for route in result.routes:  # silent hops past the last answer say nothing
        while route and route[-1] is None:
            route.pop()
    return result


# -- the graph -------------------------------------------------------------

SOURCE = "source"
DESTINATION = "destination"


@dataclass
class Node:
    key: str
    address: str = ""  # "" for a hop that never answered
    ttl: int = 0
    rtts: list[float] = field(default_factory=list)
    flows: set[int] = field(default_factory=set)
    unreachable: bool = False
    #: Flows last seen here that never reached the host: where they were lost.
    dropped: set[int] = field(default_factory=set)

    @property
    def silent(self) -> bool:
        return self.key not in (SOURCE, DESTINATION) and not self.address

    def latency(self) -> tuple[float, float, float] | None:
        """(min, avg, max) in ms, None if it never answered."""
        if not self.rtts:
            return None
        return min(self.rtts), sum(self.rtts) / len(self.rtts), max(self.rtts)

    def loss(self) -> float:
        """The share of the flows through this hop that were lost after it."""
        return len(self.dropped) / len(self.flows) if self.flows else 0.0


@dataclass
class Edge:
    parent: str
    child: str
    flows: set[int] = field(default_factory=set)
    #: True for the guessed link from a route's last answer to a host it
    #: never reached.
    unknown: bool = False


@dataclass
class PathGraph:
    nodes: dict[str, Node]
    edges: dict[tuple[str, str], Edge]
    flows: int
    reached: int  # flows that reached the host

    def edge_latency(self, edge: Edge) -> float | None:
        """How much later the child answers than the parent, in ms."""
        child = self.nodes[edge.child].latency()
        if child is None or edge.unknown:
            return None
        if edge.parent == SOURCE:
            return child[1]
        parent = self.nodes[edge.parent].latency()
        return None if parent is None else max(0.0, child[1] - parent[1])


def build_graph(sweeps: list[Sweep], destination: str) -> PathGraph:
    """The routes of every flow of `sweeps` as one graph, from SOURCE to
    DESTINATION. A router is one node however many routes pass it; a silent
    hop is a node of its own for each hop before it, so separate routes
    don't merge through hops that told nothing."""
    nodes = {SOURCE: Node(SOURCE, ttl=0), DESTINATION: Node(DESTINATION, destination)}
    edges: dict[tuple[str, str], Edge] = {}
    flows = max((s.flows for s in sweeps), default=0)
    reached = 0

    def link(parent: str, child: str, flow: int, unknown: bool = False) -> None:
        edge = edges.setdefault((parent, child), Edge(parent, child, unknown=unknown))
        edge.flows.add(flow)
        edge.unknown = edge.unknown and unknown

    for number, s in enumerate(sweeps):
        for flow, route in enumerate(s.routes):
            tag = number * flows + flow
            previous = SOURCE
            arrived = False
            for ttl, answer in enumerate(route, start=1):
                if answer is None:
                    key = f"*{ttl}<{previous}"
                    node = nodes.setdefault(key, Node(key, ttl=ttl))
                elif answer.reached or answer.address == destination:
                    key = DESTINATION
                    node = nodes[key]
                    node.rtts.append(answer.rtt_ms)
                    node.ttl = max(node.ttl, ttl)
                    arrived = True
                else:
                    key = answer.address
                    node = nodes.setdefault(key, Node(key, answer.address, ttl=ttl))
                    node.ttl = min(node.ttl, ttl)
                    node.rtts.append(answer.rtt_ms)
                    node.unreachable |= answer.unreachable
                node.flows.add(tag)
                if key != previous:
                    link(previous, key, tag)
                previous = key
                if arrived:
                    break
            if arrived:
                reached += 1
            else:
                nodes[previous].dropped.add(tag)
                nodes[previous].flows.add(tag)
                link(previous, DESTINATION, tag, unknown=True)
    total = sum(s.flows for s in sweeps)
    graph = PathGraph(nodes, edges, total, reached)
    last = max((n.ttl for n in nodes.values() if n.key != DESTINATION), default=0)
    nodes[DESTINATION].ttl = max(nodes[DESTINATION].ttl, last + 1)
    return graph


def health(s: Sweep) -> str:
    """"ok" if every flow reached the host, "partial" if some did,
    "down" if none did."""
    reached = s.reached_flows()
    if reached == s.flows:
        return "ok"
    return "partial" if reached else "down"


# -- how healthy a hop or link looks -----------------------------------------

OK, WARN, CRIT = "ok", "warn", "crit"
#: Latency above a hop's or link's usual that turns it amber, then red.
WARN_MS = 50.0
CRIT_MS = 150.0
#: Share of the flows through a hop lost after it that turns it amber, then red.
WARN_LOSS = 0.25
CRIT_LOSS = 0.5
_ORDER = {OK: 0, WARN: 1, CRIT: 2}


def worst(*levels: str) -> str:
    return max(levels, key=_ORDER.__getitem__, default=OK)


def usual(values: list[float]) -> float | None:
    """The median of `values`: what a hop or link normally measures."""
    if not values:
        return None
    ordered = sorted(values)
    middle = len(ordered) // 2
    return ordered[middle] if len(ordered) % 2 else (ordered[middle - 1] + ordered[middle]) / 2


def latency_level(now: float | None, normal: float | None,
                  what: str = "Latency") -> tuple[str, str]:
    """How far `now` is above `normal`, as a level and a reason ("" if fine)."""
    if now is None or normal is None:
        return OK, ""
    excess = now - normal
    level = CRIT if excess >= CRIT_MS else WARN if excess >= WARN_MS else OK
    if level == OK:
        return OK, ""
    return level, f"{what} {now:.0f} ms, +{excess:.0f} ms over its usual {normal:.0f} ms"


def loss_level(node: Node) -> tuple[str, str]:
    """How many of the flows through `node` were lost after it."""
    share = node.loss()
    level = CRIT if share >= CRIT_LOSS else WARN if share >= WARN_LOSS else OK
    if level == OK:
        return OK, ""
    return level, f"{len(node.dropped)} of {len(node.flows)} flows lost after this hop"
