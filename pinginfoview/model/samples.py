"""Per-host latency samples for the graph window.

Kept apart from the lower pane's HistoryModel on purpose: that one obeys the
"Record Failed Pings Only"/"Status Changes Only" filter and is shared by every
host, whereas a graph needs every ping of one host regardless of that filter.
"""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass

from ..ping.result import PingResult

#: An hour of history at the default one-second interval.
DEFAULT_SAMPLES_PER_HOST = 3600


@dataclass(slots=True, frozen=True)
class Sample:
    timestamp: float
    #: None for a ping that failed (timeout, unreachable, ...).
    rtt_ms: float | None


@dataclass(slots=True, frozen=True)
class SampleStats:
    sent: int
    lost: int
    min_ms: float | None
    avg_ms: float | None
    max_ms: float | None
    last_ms: float | None

    @property
    def loss_percent(self) -> float:
        return (self.lost / self.sent * 100.0) if self.sent else 0.0


class SampleStore:
    """A capped ring buffer of samples per host key."""

    def __init__(self, per_host: int = DEFAULT_SAMPLES_PER_HOST) -> None:
        self.per_host = per_host
        self._samples: dict[int, deque[Sample]] = {}

    def add(self, key: int, result: PingResult) -> None:
        buffer = self._samples.get(key)
        if buffer is None:
            buffer = self._samples[key] = deque(maxlen=self.per_host)
        buffer.append(
            Sample(result.timestamp, result.rtt_ms if result.succeeded else None)
        )

    def samples(self, key: int, since: float | None = None) -> list[Sample]:
        buffer = self._samples.get(key)
        if not buffer:
            return []
        if since is None:
            return list(buffer)
        return [s for s in buffer if s.timestamp >= since]

    def oldest(self, key: int) -> float | None:
        """Timestamp of the earliest sample still kept for this host."""
        buffer = self._samples.get(key)
        return buffer[0].timestamp if buffer else None

    def discard(self, key: int) -> None:
        self._samples.pop(key, None)

    def retain(self, keys: set[int]) -> None:
        """Drop the samples of every host no longer in the list."""
        for key in [k for k in self._samples if k not in keys]:
            del self._samples[key]

    def clear(self) -> None:
        self._samples.clear()


def summarize(samples: list[Sample]) -> SampleStats:
    rtts = [s.rtt_ms for s in samples if s.rtt_ms is not None]
    last = samples[-1].rtt_ms if samples else None
    return SampleStats(
        sent=len(samples),
        lost=len(samples) - len(rtts),
        min_ms=min(rtts) if rtts else None,
        avg_ms=sum(rtts) / len(rtts) if rtts else None,
        max_ms=max(rtts) if rtts else None,
        last_ms=last,
    )


def nice_ceiling(value: float) -> float:
    """Round a latency up to a tidy axis maximum: 10, 12, 15, 20, 25, 30, ..."""
    if value <= 10:
        return 10.0
    step = 10.0
    while True:
        for factor in (1, 1.2, 1.5, 2, 2.5, 3, 4, 5, 6, 8):
            if value <= step * factor:
                return step * factor
        step *= 10
