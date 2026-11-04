"""The scheduler: pings every enabled target once per interval, forever.

Runs on its own asyncio loop with no Qt dependency. Results are handed back
through a callback in batches so the GUI thread repaints a few times a second
instead of once per reply.
"""

from __future__ import annotations

import asyncio
import socket
import time
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field

from ..osinfo import IS_WINDOWS
from .icmp import IcmpPinger
from .result import PingResult, PingStatus
from .tcp import tcp_ping

#: How often batched results are flushed to the callback.
FLUSH_INTERVAL_SECONDS = 0.25


@dataclass(slots=True)
class PingTarget:
    """What the engine needs to know about one host. Statistics live elsewhere."""

    key: int
    host: str
    #: Set for TCP pings written as ``host:port``; None means ICMP.
    port: int | None = None
    enabled: bool = True
    #: Cached forward lookup, reused unless resolve_every_ping is on.
    resolved_ip: str = ""

    @property
    def is_tcp(self) -> bool:
        return self.port is not None


@dataclass
class EngineOptions:
    """The subset of Settings the engine acts on, copied in so it stays plain."""

    interval_seconds: float = 3.0
    timeout_ms: int = 3000
    ping_size: int = 32
    ttl: int = 64
    dont_fragment: bool = False
    max_concurrent: int = 500
    resolve_every_ping: bool = False
    stop_after_pings: int = 0

    @classmethod
    def from_settings(cls, settings) -> "EngineOptions":
        return cls(
            interval_seconds=settings.ping_interval_seconds,
            timeout_ms=settings.ping_timeout_ms,
            ping_size=settings.ping_size,
            ttl=settings.ttl,
            dont_fragment=settings.dont_fragment,
            max_concurrent=settings.max_concurrent_pings,
            resolve_every_ping=settings.resolve_every_ping,
            stop_after_pings=settings.stop_after_pings,
        )


#: (target key, result) pairs.
ResultBatch = list[tuple[int, PingResult]]


class PingEngine:
    """Owns the ping loop. Create it inside the thread that will run it."""

    def __init__(
        self,
        on_results: Callable[[ResultBatch], None],
        on_round_complete: Callable[[int], None] | None = None,
    ) -> None:
        self._on_results = on_results
        self._on_round_complete = on_round_complete
        self._options = EngineOptions()
        self._targets: list[PingTarget] = []
        if IS_WINDOWS:
            from .icmp_windows import IcmpWindowsPinger

            self._pinger = IcmpWindowsPinger()
        else:
            self._pinger = IcmpPinger()
        self._semaphore = asyncio.Semaphore(self._options.max_concurrent)
        self._pending_batch: ResultBatch = []
        self._in_flight: set[int] = set()
        self._dns_cache: dict[str, str] = {}
        self._rounds_done = 0
        self._stop_event: asyncio.Event | None = None
        self._tasks: set[asyncio.Task] = set()

    # -- configuration -----------------------------------------------------

    def set_targets(self, targets: Iterable[PingTarget]) -> None:
        self._targets = list(targets)

    def set_options(self, options: EngineOptions) -> None:
        previous = self._options
        self._options = options
        if options.max_concurrent != previous.max_concurrent:
            self._semaphore = asyncio.Semaphore(options.max_concurrent)
        self._pinger.configure(ttl=options.ttl, dont_fragment=options.dont_fragment)

    @property
    def dont_fragment_supported(self) -> bool:
        return self._pinger.dont_fragment_supported

    # -- the loop ----------------------------------------------------------

    async def run(self) -> None:
        """Ping every target on the interval until :meth:`stop` or the ping limit."""
        self._stop_event = asyncio.Event()
        self._rounds_done = 0
        self._pinger.open()
        self._pinger.configure(ttl=self._options.ttl, dont_fragment=self._options.dont_fragment)
        flusher = asyncio.create_task(self._flush_loop())
        try:
            while not self._stop_event.is_set():
                round_started = time.perf_counter()
                self._start_round()
                self._rounds_done += 1
                if self._on_round_complete is not None:
                    self._on_round_complete(self._rounds_done)
                limit = self._options.stop_after_pings
                if limit and self._rounds_done >= limit:
                    await self._drain()
                    break
                elapsed = time.perf_counter() - round_started
                delay = max(0.0, self._options.interval_seconds - elapsed)
                try:
                    await asyncio.wait_for(self._stop_event.wait(), delay)
                except asyncio.TimeoutError:
                    pass
        finally:
            flusher.cancel()
            await self._drain()
            self._flush()
            self._pinger.close()

    def stop(self) -> None:
        if self._stop_event is not None:
            self._stop_event.set()

    def _start_round(self) -> None:
        for target in self._targets:
            if not target.enabled:
                continue
            # A target whose previous ping has not come back yet is skipped
            # rather than queued, so a slow host cannot build a backlog.
            if target.key in self._in_flight:
                continue
            self._in_flight.add(target.key)
            task = asyncio.create_task(self._ping_target(target))
            self._tasks.add(task)
            task.add_done_callback(self._tasks.discard)

    async def _drain(self) -> None:
        if self._tasks:
            await asyncio.gather(*list(self._tasks), return_exceptions=True)

    async def _ping_target(self, target: PingTarget) -> None:
        try:
            async with self._semaphore:
                result = await self._ping_once(target)
            self._pending_batch.append((target.key, result))
        except asyncio.CancelledError:
            raise
        except Exception:
            self._pending_batch.append((target.key, PingResult(PingStatus.GENERAL_FAILURE)))
        finally:
            self._in_flight.discard(target.key)

    async def _ping_once(self, target: PingTarget) -> PingResult:
        ip = await self._resolve(target)
        if not ip:
            return PingResult(PingStatus.BAD_DESTINATION)
        if target.is_tcp:
            result = await tcp_ping(ip, target.port or 0, self._options.timeout_ms)
        else:
            result = await self._pinger.ping(
                ip, self._options.timeout_ms, self._options.ping_size
            )
        result.destination_ip = ip
        return result

    async def _resolve(self, target: PingTarget) -> str:
        """Forward-resolve the host, reusing the cache unless told not to."""
        if not self._options.resolve_every_ping:
            cached = target.resolved_ip or self._dns_cache.get(target.host)
            if cached:
                target.resolved_ip = cached
                return cached
        try:
            infos = await asyncio.get_running_loop().getaddrinfo(
                target.host, None, family=socket.AF_INET, type=socket.SOCK_STREAM
            )
        except (OSError, UnicodeError):
            return ""
        if not infos:
            return ""
        ip = infos[0][4][0]
        self._dns_cache[target.host] = ip
        target.resolved_ip = ip
        return ip

    # -- batching ----------------------------------------------------------

    async def _flush_loop(self) -> None:
        while True:
            await asyncio.sleep(FLUSH_INTERVAL_SECONDS)
            self._flush()

    def _flush(self) -> None:
        if not self._pending_batch:
            return
        batch, self._pending_batch = self._pending_batch, []
        self._on_results(batch)
