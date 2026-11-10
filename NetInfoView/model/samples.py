"""Per-host latency samples for the graph window.

Kept apart from the lower pane's HistoryModel on purpose: that one obeys the
"Record Failed Pings Only"/"Status Changes Only" filter and is shared by every
host, whereas a graph needs every ping of one host regardless of that filter.
"""

from __future__ import annotations

import math
from array import array
from bisect import bisect_left, bisect_right
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


class _Series:
    """One host's samples as two flat arrays of doubles (a failed ping's
    RTT is NaN): 16 bytes a sample, where a deque of Sample objects took
    about 100. Pings arrive in time order, so ranges are found by bisect.

    The oldest samples beyond the cap are skipped by moving ``start`` and
    cut off in one go once half a cap of them has piled up."""

    __slots__ = ("times", "rtts", "start")

    def __init__(self) -> None:
        self.times = array("d")
        self.rtts = array("d")
        self.start = 0

    def __len__(self) -> int:
        return len(self.times) - self.start

    def append(self, timestamp: float, rtt_ms: float | None, cap: int) -> None:
        self.times.append(timestamp)
        self.rtts.append(math.nan if rtt_ms is None else rtt_ms)
        if len(self) > cap:
            self.start += 1
            if self.start >= max(1, cap // 2):
                del self.times[: self.start]
                del self.rtts[: self.start]
                self.start = 0

    def slice(self, since: float | None, until: float | None) -> list[Sample]:
        times = self.times
        i = self.start if since is None else bisect_left(times, since, self.start)
        j = len(times) if until is None else bisect_right(times, until, i)
        return [Sample(t, None if r != r else r)
                for t, r in zip(times[i:j], self.rtts[i:j])]


class SampleStore:
    """A capped buffer of samples per host key."""

    def __init__(self, per_host: int = DEFAULT_SAMPLES_PER_HOST) -> None:
        self.per_host = per_host
        self._samples: dict[int, _Series] = {}

    def add(self, key: int, result: PingResult) -> None:
        series = self._samples.get(key)
        if series is None:
            series = self._samples[key] = _Series()
        series.append(
            result.timestamp, result.rtt_ms if result.succeeded else None, self.per_host
        )

    def samples(
        self, key: int, since: float | None = None, until: float | None = None
    ) -> list[Sample]:
        """This host's samples from `since` to `until` (both inclusive)."""
        series = self._samples.get(key)
        if not series:
            return []
        return series.slice(since, until)

    def oldest(self, key: int) -> float | None:
        """Timestamp of the earliest sample still kept for this host."""
        series = self._samples.get(key)
        return series.times[series.start] if series else None

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
