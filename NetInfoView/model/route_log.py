"""Route Monitor's history: every hop's samples in memory for the window,
and the same samples logged to a SQLite file per session so they outlast the
window (and can be exported as CSV)."""

from __future__ import annotations

import csv
import math
import re
import sqlite3
import time
from array import array
from bisect import bisect_left
from dataclasses import dataclass
from pathlib import Path

from ..fileio.vendor_db import _app_data_dir
from ..ping.route_monitor import HopSample, RoundResult, RouteChange
from ..settings import APPLICATION
from .samples import Sample

#: How much of each hop's history is kept in memory (the log file keeps all).
KEEP_SECONDS = 24 * 3600
#: Log files older than this are deleted when a Route Monitor opens.
KEEP_DAYS = 30
#: A middle hop's loss is the router limiting its replies, not loss on the
#: path, when a hop after it loses less than this share of it.
CARRIED_SHARE = 0.5


@dataclass(frozen=True)
class HopStats:
    sent: int
    lost: int
    min_ms: float | None
    avg_ms: float | None
    max_ms: float | None
    #: Mean change in latency between consecutive replies.
    jitter_ms: float | None
    #: The latest probe: None if it was lost.
    last_ms: float | None

    @property
    def loss_percent(self) -> float:
        return self.lost / self.sent * 100.0 if self.sent else 0.0

    @property
    def silent(self) -> bool:
        """Probed, but never answered."""
        return self.sent > 0 and self.lost == self.sent


def hop_stats(samples: list[Sample]) -> HopStats:
    rtts = [s.rtt_ms for s in samples if s.rtt_ms is not None]
    jitter = (sum(abs(b - a) for a, b in zip(rtts, rtts[1:])) / (len(rtts) - 1)
              if len(rtts) > 1 else None)
    return HopStats(
        sent=len(samples),
        lost=len(samples) - len(rtts),
        min_ms=min(rtts) if rtts else None,
        avg_ms=sum(rtts) / len(rtts) if rtts else None,
        max_ms=max(rtts) if rtts else None,
        jitter_ms=jitter,
        last_ms=samples[-1].rtt_ms if samples else None,
    )


def rate_limited(stats: dict[int, HopStats]) -> set[int]:
    """The hops whose loss doesn't carry on to the hops after them: routers
    that answer only so many expired probes, not a link losing packets."""
    out = set()
    for ttl, hop in stats.items():
        if hop.lost == 0 or hop.silent:
            continue
        later = [s.loss_percent for t, s in stats.items() if t > ttl and s.sent and not s.silent]
        if later and min(later) < hop.loss_percent * CARRIED_SHARE:
            out.add(ttl)
    return out


class HopSeries:
    """One hop's samples in compact arrays, with running totals so the stats
    of any recent stretch take no longer for a day of samples than a minute.
    A day at one sample a second is about 2.4 MB."""

    def __init__(self) -> None:
        self.times = array("d")
        #: NaN for a lost probe.
        self.rtts = array("f")
        # Running totals *before* each sample (one entry longer than the
        # samples): replies, their latency, and the change in latency from
        # the reply before.
        self._replies = array("I", [0])
        self._rtt_sum = array("d", [0.0])
        self._jitter_sum = array("d", [0.0])
        self._jitter_count = array("I", [0])
        self._last_reply: float | None = None
        #: Index of the oldest sample still kept.
        self._start = 0

    def __len__(self) -> int:
        return len(self.times) - self._start

    def append(self, timestamp: float, rtt_ms: float | None) -> None:
        self.times.append(timestamp)
        self.rtts.append(math.nan if rtt_ms is None else rtt_ms)
        replies, total = self._replies[-1], self._rtt_sum[-1]
        jitter, jitter_count = self._jitter_sum[-1], self._jitter_count[-1]
        if rtt_ms is not None:
            replies += 1
            total += rtt_ms
            if self._last_reply is not None:
                jitter += abs(rtt_ms - self._last_reply)
                jitter_count += 1
            self._last_reply = rtt_ms
        self._replies.append(replies)
        self._rtt_sum.append(total)
        self._jitter_sum.append(jitter)
        self._jitter_count.append(jitter_count)

    def forget_before(self, timestamp: float) -> None:
        self._start = max(self._start, bisect_left(self.times, timestamp, self._start))
        # Shift the arrays down once half of them is forgotten.
        if self._start > 1024 and self._start * 2 > len(self.times):
            cut = self._start
            for values in (self.times, self.rtts, self._replies, self._rtt_sum,
                           self._jitter_sum, self._jitter_count):
                del values[:cut]
            self._start = 0

    def first(self) -> float | None:
        return self.times[self._start] if len(self) else None

    def _index(self, since: float | None) -> int:
        if since is None:
            return self._start
        return bisect_left(self.times, since, self._start)

    def samples(self, since: float | None = None) -> list[Sample]:
        i = self._index(since)
        return [Sample(t, None if r != r else r)
                for t, r in zip(self.times[i:], self.rtts[i:])]

    def stats(self, since: float | None = None) -> HopStats:
        i, j = self._index(since), len(self.times)
        sent = j - i
        replies = self._replies[j] - self._replies[i]
        rtts = [r for r in self.rtts[i:j] if r == r] if replies else []
        # Changes in latency between replies inside the stretch: the first
        # reply's own change was against a reply before the stretch.
        start = i
        if replies:
            start = next(k for k in range(i, j) if self.rtts[k] == self.rtts[k]) + 1
        jitter = self._jitter_sum[j] - self._jitter_sum[start]
        jitter_count = self._jitter_count[j] - self._jitter_count[start]
        last = self.rtts[j - 1] if sent else math.nan
        return HopStats(
            sent=sent,
            lost=sent - replies,
            min_ms=min(rtts) if rtts else None,
            avg_ms=(self._rtt_sum[j] - self._rtt_sum[i]) / replies if replies else None,
            max_ms=max(rtts) if rtts else None,
            jitter_ms=jitter / jitter_count if jitter_count else None,
            last_ms=None if last != last else last,
        )


class RouteLog:
    """Every hop's samples for the last `keep_seconds`, newest last."""

    def __init__(self, keep_seconds: float = KEEP_SECONDS) -> None:
        self.keep_seconds = keep_seconds
        self._hops: dict[int, HopSeries] = {}
        #: ttl -> the address that hop answers from now.
        self.addresses: dict[int, str] = {}
        self.changes: list[RouteChange] = []
        self.hop_count: int | None = None
        #: When the session started, and its latest round.
        self.started: float | None = None
        self.last: float | None = None

    @property
    def first(self) -> float | None:
        """The oldest sample still kept."""
        return min((t for t in (h.first() for h in self._hops.values()) if t is not None),
                   default=None)

    def add(self, result: RoundResult) -> None:
        for sample in result.samples:
            series = self._hops.get(sample.ttl)
            if series is None:
                series = self._hops[sample.ttl] = HopSeries()
            series.append(sample.timestamp, sample.rtt_ms)
            if sample.address and sample.ttl not in self.addresses:
                self.addresses[sample.ttl] = sample.address
        for change in result.changes:
            self.addresses[change.ttl] = change.new
            self.changes.append(change)
        if result.hop_count is not None:
            self.hop_count = result.hop_count
            # The host answers from its own address, whatever came first.
            for sample in result.samples:
                if sample.ttl == result.hop_count and sample.address:
                    self.addresses[sample.ttl] = sample.address
        if self.started is None:
            self.started = result.timestamp
        self.last = result.timestamp
        cutoff = result.timestamp - self.keep_seconds
        for series in self._hops.values():
            series.forget_before(cutoff)
        self.changes = [c for c in self.changes if c.timestamp >= cutoff]

    def ttls(self) -> list[int]:
        """The hops to show: up to the host's, or the furthest that answered."""
        if self.hop_count is not None:
            return list(range(1, self.hop_count + 1))
        return list(range(1, max(max(self.addresses, default=0), max(self._hops, default=0)) + 1))

    def samples(self, ttl: int, since: float | None = None) -> list[Sample]:
        series = self._hops.get(ttl)
        return series.samples(since) if series is not None else []

    def hop(self, ttl: int, since: float | None = None) -> HopStats:
        series = self._hops.get(ttl)
        return series.stats(since) if series is not None else hop_stats([])

    def stats(self, since: float | None = None) -> dict[int, HopStats]:
        return {ttl: self.hop(ttl, since) for ttl in self.ttls()}

    def clear(self) -> None:
        self.__init__(self.keep_seconds)


# -- the log file -----------------------------------------------------------

_SCHEMA = """
CREATE TABLE IF NOT EXISTS session (target TEXT, ip TEXT, started REAL, interval REAL);
CREATE TABLE IF NOT EXISTS samples (t REAL, ttl INTEGER, address TEXT, rtt_ms REAL);
CREATE TABLE IF NOT EXISTS changes (t REAL, ttl INTEGER, old TEXT, new TEXT);
"""


def routes_dir() -> Path:
    """``~/Library/Application Support/NetInfoView/routes`` on macOS,
    ``%APPDATA%\\NetInfoView\\routes`` on Windows."""
    return _app_data_dir() / APPLICATION / "routes"


def log_path(target: str, started: float, folder: Path | None = None) -> Path:
    safe = re.sub(r"[^A-Za-z0-9._-]+", "_", target.strip()) or "host"
    stamp = time.strftime("%Y%m%d-%H%M%S", time.localtime(started))
    return (folder or routes_dir()) / f"{safe}-{stamp}.sqlite"


class RouteLogFile:
    """One session's log. Use it from one thread only (SQLite's rule)."""

    def __init__(self, path: Path, target: str = "", ip: str = "", interval: float = 0.0) -> None:
        self.path = path
        path.parent.mkdir(parents=True, exist_ok=True)
        self._db = sqlite3.connect(str(path))
        self._db.executescript(_SCHEMA)
        if target and not self._db.execute("SELECT 1 FROM session").fetchone():
            self._db.execute("INSERT INTO session VALUES (?, ?, ?, ?)",
                             (target, ip, time.time(), interval))
        self._db.commit()

    def write(self, result: RoundResult) -> None:
        self._db.executemany(
            "INSERT INTO samples VALUES (?, ?, ?, ?)",
            [(s.timestamp, s.ttl, s.address, s.rtt_ms) for s in result.samples],
        )
        self._db.executemany(
            "INSERT INTO changes VALUES (?, ?, ?, ?)",
            [(c.timestamp, c.ttl, c.old, c.new) for c in result.changes],
        )
        self._db.commit()

    def samples(self) -> list[HopSample]:
        rows = self._db.execute("SELECT t, ttl, address, rtt_ms FROM samples ORDER BY t, ttl")
        return [HopSample(*row) for row in rows]

    def changes(self) -> list[RouteChange]:
        rows = self._db.execute("SELECT t, ttl, old, new FROM changes ORDER BY t")
        return [RouteChange(*row) for row in rows]

    def close(self) -> None:
        self._db.close()


def export_csv(log: Path, out: Path, names: dict[str, str] | None = None) -> int:
    """Every sample in `log` as a CSV row; returns how many."""
    names = names or {}
    source = RouteLogFile(log)
    try:
        samples = source.samples()
    finally:
        source.close()
    with open(out, "w", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle)
        writer.writerow(["time", "hop", "address", "name", "rtt_ms"])
        for s in samples:
            writer.writerow([
                time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(s.timestamp)),
                s.ttl, s.address, names.get(s.address, ""),
                "" if s.rtt_ms is None else f"{s.rtt_ms:.2f}",
            ])
    return len(samples)


def prune_logs(folder: Path | None = None, days: int = KEEP_DAYS, now: float | None = None) -> int:
    """Delete log files not written to for `days`; returns how many."""
    folder = folder or routes_dir()
    if not folder.is_dir():
        return 0
    cutoff = (now if now is not None else time.time()) - days * 86400
    removed = 0
    for path in folder.glob("*.sqlite"):
        try:
            if path.stat().st_mtime < cutoff:
                path.unlink()
                removed += 1
        except OSError:
            continue
    return removed
