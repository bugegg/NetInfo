"""Internet speed test, measured the way nPerf does: idle latency and
jitter first, then download and upload over several parallel HTTP streams
for a fixed time, sampling the bytes moved every 100 ms. The first seconds
(TCP slow start) are dropped and the rest averaged; the peak is kept too.
While the transfers run, a separate connection keeps timing small requests,
so the latency under load (bufferbloat) is reported as well.

The default server is Cloudflare's speed test (speed.cloudflare.com):
anycast, so the nearest data centre answers, and free to use without a key.
Any server that serves ``<base>/__down?bytes=N`` and accepts a POST to
``<base>/__up`` works too (e.g. one in the company's own network).

Qt-free; the window runs ``run_test`` on a worker thread.
"""

from __future__ import annotations

import bisect
import copy
import http.client
import json
import math
import random
import re
import socket
import statistics
import struct
import sys
import threading
import time
import urllib.parse
import urllib.request
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field

from ..https import ssl_context, urlopen
from . import send_queue

DEFAULT_SERVER = "https://speed.cloudflare.com"
USER_AGENT = "NetInfoView-SpeedTest"

#: Bytes asked for in a stream's first download request, and sent in its
#: first upload; each stream keeps making requests until the phase's time is
#: up. Every later request is sized to last about REQUEST_TARGET_S at the
#: speed the previous one ran, between MIN_CHUNK and MAX_CHUNK. (A fixed
#: 5 MB had each stream of a fast line stop for a new request every 0.2 s,
#: and the graph sawtoothed; Ookla's servers send 25 MB in under a second
#: to one stream on a 250 Mbps line.) Bytes are counted as they move, so a
#: first request that can't finish within the phase on a slow line still
#: measures it.
DOWN_CHUNK = 100_000_000
UP_CHUNK = 100_000_000
MIN_CHUNK = 250_000
MAX_CHUNK = 200_000_000
#: Cloudflare's /__down answers 403 from 100,000,000 bytes up.
CLOUDFLARE_MAX_DOWN = 99_999_999
REQUEST_TARGET_S = 2.5
#: Statuses that mean "not that much at once": Cloudflare answers 403 to a
#: download over CLOUDFLARE_MAX_DOWN and 429 once an address has pulled a
#: lot in a short while; a web server in front of LibreSpeed may answer 413
#: to a big upload. The stream halves its size and never grows past that again.
TOO_BIG = (403, 413, 429)
READ_SIZE = 64 * 1024
#: The average speed is taken the way Ookla describes its own: the transfer
#: (after the ramp) is cut into SLICES equal stretches of time, and the
#: fastest TRIM_FAST and slowest TRIM_SLOW of them are left out, so one
#: stall or burst doesn't swing the result.
SLICES = 20
TRIM_FAST = 0.10
TRIM_SLOW = 0.20
SAMPLE_INTERVAL_S = 0.1
PEAK_WINDOW_S = 1.0
TIMEOUT_S = 10.0


@dataclass(frozen=True)
class ServerSpec:
    """A server to test against. ``kind`` is "cloudflare" (``/__down?bytes=N``
    and ``/__up``, which any custom URL is taken to speak too), "librespeed"
    (the LibreSpeed backend's garbage.php / empty.php) or "ookla" (an
    Ookla server daemon's ``/download?size=N``, ``/upload`` and ``/hello``)."""
    name: str
    url: str
    kind: str = "cloudflare"
    dl: str = "garbage.php"
    ul: str = "empty.php"
    ping: str = "empty.php"
    ip: str = "getIP.php"
    sponsor: str = ""
    #: The sponsor's website (LibreSpeed lists it), for its logo.
    sponsor_url: str = ""


CLOUDFLARE = ServerSpec("Cloudflare (nearest)", DEFAULT_SERVER)

#: LibreSpeed's list of public servers around the world.
LIBRESPEED_LIST_URL = "https://librespeed.org/backend-servers/servers.php"
#: Used when the list can't be fetched (taken from it in November 2026).
FALLBACK_SERVERS = (
    ServerSpec("Tokyo, Japan (A573)", "https://librespeed.a573.net/", "librespeed",
               "backend/garbage.php", "backend/empty.php", "backend/empty.php",
               "backend/getIP.php", "A573"),
    ServerSpec("Frankfurt, Germany (Clouvider)", "https://fra.speedtest.clouvider.net/backend",
               "librespeed", sponsor="Clouvider"),
    ServerSpec("London, England (Clouvider)", "https://lon.speedtest.clouvider.net/backend",
               "librespeed", sponsor="Clouvider"),
    ServerSpec("Amsterdam, Netherlands (Clouvider)", "https://ams.speedtest.clouvider.net/backend",
               "librespeed", sponsor="Clouvider"),
    ServerSpec("New York, United States (2) (Clouvider)",
               "https://nyc.speedtest.clouvider.net/backend", "librespeed", sponsor="Clouvider"),
    ServerSpec("Los Angeles, United States (1) (Clouvider)",
               "https://la.speedtest.clouvider.net/backend", "librespeed", sponsor="Clouvider"),
)


#: Ookla's list of Speedtest servers in Thailand, run by Thai ISPs.
OOKLA_LIST_URL = "https://www.speedtest.net/api/js/servers?engine=js&search=Thailand&limit=100"
OOKLA_COUNTRY = "TH"
FALLBACK_OOKLA = (
    ServerSpec("Bangkok, Thailand (True Online)", "https://spd-bkk1.trueinternet.co.th:8080",
               "ookla", sponsor="True Online"),
    ServerSpec("Bangkok, Thailand (3BB)",
               "https://speedtest-sp1.3bb.co.th.prod.hosts.ooklaserver.net:8080",
               "ookla", sponsor="3BB"),
    ServerSpec("Bangkok, Thailand (AIS Fibre)",
               "https://tlssp1.myaisfibre.com.prod.hosts.ooklaserver.net:8080",
               "ookla", sponsor="AIS Fibre"),
    ServerSpec("Bangkok, Thailand (NT Corporate)", "https://brkspeedtest.cat.net.th:8080",
               "ookla", sponsor="NT Corporate"),
)


@dataclass
class SpeedTestOptions:
    server: str | ServerSpec = DEFAULT_SERVER
    duration_s: float = 10.0
    #: Seconds of each transfer left out of the average (TCP slow start).
    ramp_s: float = 2.0
    streams: int = 6
    #: Pings in the final ping phase.
    latency_count: int = 20
    #: Seconds between them, so a burst doesn't time one queue.
    ping_gap_s: float = 0.1
    #: Seconds of quiet between download and upload, so the queues the
    #: download filled have drained before upload starts timing.
    pause_s: float = 1.5
    download: bool = True
    upload: bool = True
    #: Automatic: try each of these for PROBE_S first and test the fastest
    #: (`server` is then only the fallback should none of them answer).
    candidates: tuple[ServerSpec, ...] = ()


@dataclass
class TransferResult:
    mbps: float = 0.0
    peak_mbps: float = 0.0
    bytes: int = 0
    #: (seconds since the phase started, Mbps over the last interval).
    samples: list[tuple[float, float]] = field(default_factory=list)
    loaded_latency_ms: float | None = None


@dataclass
class SpeedResult:
    latency_ms: float | None = None
    jitter_ms: float | None = None
    download: TransferResult | None = None
    upload: TransferResult | None = None
    #: About the test: host, and from Cloudflare colo, loc, ip, http, tls.
    meta: dict[str, str] = field(default_factory=dict)
    error: str = ""
    #: How many pings the latency and jitter come from.
    ping_count: int = 0


# ----------------------------------------------------------------- helpers


def mbps(byte_count: float, seconds: float) -> float:
    return byte_count * 8 / seconds / 1e6 if seconds > 0 else 0.0


def jitter(rtts: list[float]) -> float:
    """Mean difference between consecutive round trips (as nPerf and
    RFC 3550 smoothing-free jitter do)."""
    if len(rtts) < 2:
        return 0.0
    return statistics.fmean(abs(b - a) for a, b in zip(rtts, rtts[1:]))


def rolling_mbps(points: list[tuple[float, int]], window_s: float = PEAK_WINDOW_S) -> float:
    """Speed over the last `window_s` of cumulative (seconds, bytes) points
    (or since the start, before that much has passed). Bytes arrive in
    bursts, one per round trip, so a single 100 ms interval swings between
    nothing and several times the line rate on a distant server."""
    if len(points) < 2:
        return 0.0
    t1, b1 = points[-1]
    t0, b0 = points[0]
    for t, b in reversed(points[:-1]):
        if t1 - t >= window_s:
            t0, b0 = t, b
            break
    return mbps(b1 - b0, t1 - t0)


def _bytes_at(points: list[tuple[float, int]], t: float) -> float:
    """Cumulative bytes at time `t`, interpolated between the points."""
    i = bisect.bisect_left(points, t, key=lambda p: p[0])
    if i == 0:
        return points[0][1]
    if i >= len(points):
        return points[-1][1]
    (t0, b0), (t1, b1) = points[i - 1], points[i]
    return b0 + (b1 - b0) * (t - t0) / (t1 - t0) if t1 > t0 else b1


def trimmed_mbps(points: list[tuple[float, int]], slices: int = SLICES) -> float:
    """Average speed over cumulative (seconds, bytes) points with the
    fastest TRIM_FAST and slowest TRIM_SLOW of `slices` equal stretches of
    time left out. Too few points to slice: the plain average."""
    (t0, b0), (t1, b1) = points[0], points[-1]
    if t1 <= t0:
        return 0.0
    # No finer than the samples themselves, or slices would just echo them.
    slices = min(slices, len(points) - 1)
    if slices < 5:
        return mbps(b1 - b0, t1 - t0)
    step = (t1 - t0) / slices
    edges = [_bytes_at(points, t0 + k * step) for k in range(slices + 1)]
    speeds = sorted(mbps(b - a, step) for a, b in zip(edges, edges[1:]))
    slow = int(slices * TRIM_SLOW)
    fast = int(slices * TRIM_FAST)
    return statistics.fmean(speeds[slow:slices - fast])


def summarize(points: list[tuple[float, int]], ramp_s: float) -> TransferResult:
    """Turn cumulative (seconds, bytes) points into a result: per-interval
    speeds (each over the second up to it, as the graph shows them), their
    peak, and the average after the ramp-up."""
    result = TransferResult(bytes=points[-1][1] if points else 0)
    for i in range(1, len(points)):
        result.samples.append((points[i][0], rolling_mbps(points[:i + 1])))
    # Peak over a rolling second: a single 100 ms sample swings with bursts.
    # After the ramp, like the average: the first moments are the
    # connections opening and buffers filling, not the line.
    steady = [p for p in points if p[0] >= ramp_s]
    peak_points = steady if len(steady) >= 2 else points
    j = 0
    for t1, b1 in peak_points:
        while j + 1 < len(peak_points) and t1 - peak_points[j + 1][0] >= PEAK_WINDOW_S:
            j += 1
        t0, b0 = peak_points[j]
        if t1 - t0 >= PEAK_WINDOW_S:
            result.peak_mbps = max(result.peak_mbps, mbps(b1 - b0, t1 - t0))
    if len(steady) >= 2:
        result.mbps = trimmed_mbps(steady)
    elif len(points) >= 2:  # too short to drop the ramp: use it all
        result.mbps = mbps(points[-1][1] - points[0][1], points[-1][0] - points[0][0])
    result.peak_mbps = max(result.peak_mbps, result.mbps)
    return result


class _Server:
    def __init__(self, spec: str | ServerSpec) -> None:
        if isinstance(spec, str):
            spec = ServerSpec(spec, spec)
        self.spec = spec
        url = urllib.parse.urlsplit(spec.url.strip())
        if url.scheme not in ("http", "https") or not url.hostname:
            raise ValueError(f"not an http(s) URL: {spec.url}")
        self.https = url.scheme == "https"
        self.host = url.hostname
        self.port = url.port
        self.path = url.path.rstrip("/")
        self.librespeed = spec.kind == "librespeed"
        self.ookla = spec.kind == "ookla"
        #: The most one download may ask for, known up front where the
        #: server is (the rest is found by TOO_BIG halving).
        self.max_down = (CLOUDFLARE_MAX_DOWN if self.host == "speed.cloudflare.com"
                         else MAX_CHUNK)

    def connect(self) -> http.client.HTTPConnection:
        if self.https:
            return http.client.HTTPSConnection(self.host, self.port, timeout=TIMEOUT_S,
                                               context=ssl_context())
        return http.client.HTTPConnection(self.host, self.port, timeout=TIMEOUT_S)

    def _at(self, path: str) -> str:
        return f"{self.path}/{path.lstrip('/')}"

    def down(self, n: int) -> str:
        if self.ookla:
            return self._at(f"download?size={n}")
        if self.librespeed:  # garbage.php sends ckSize chunks of 1 MiB
            return self._at(f"{self.spec.dl}?ckSize={max(1, math.ceil(n / 1_048_576))}")
        return self._at(f"__down?bytes={n}")

    def ping(self) -> str:
        if self.ookla:
            return self._at(f"hello?nocache={random.random()}")
        if self.librespeed:
            return self._at(f"{self.spec.ping}?r={random.random()}")
        return self.down(0)

    def up(self) -> str:
        if self.ookla:
            return self._at("upload")
        return self._at(self.spec.ul if self.librespeed else "__up")


def http_error(status: int) -> str:
    if status == 429:
        return "HTTP 429: the server is rate-limiting this address; try again in a few minutes"
    return f"HTTP {status}"


def _headers() -> dict[str, str]:
    return {"User-Agent": USER_AGENT, "Accept-Encoding": "identity"}


_DUR = re.compile(r"\bdur=([\d.]+)")


def server_time_ms(header: str | None) -> float:
    """The server's own processing time from a Server-Timing header (the sum
    of its ``dur=`` entries), which a round trip must not count."""
    return sum(float(d) for d in _DUR.findall(header or ""))


def _ping(conn: http.client.HTTPConnection, server: _Server) -> float:
    """Time one empty request on a kept-alive connection, in ms, less the
    time the server spent on it."""
    start = time.perf_counter()
    conn.request("GET", server.ping(), headers=_headers())
    resp = conn.getresponse()
    resp.read()
    elapsed = (time.perf_counter() - start) * 1000
    return max(elapsed - server_time_ms(resp.getheader("server-timing")), 0.0)


def parse_trace(text: str) -> dict[str, str]:
    """``key=value`` lines of Cloudflare's /cdn-cgi/trace."""
    pairs = (line.split("=", 1) for line in text.splitlines() if "=" in line)
    return {k: v for k, v in pairs if k in ("colo", "loc", "ip", "http", "tls")}


def parse_librespeed_ip(text: str) -> dict[str, str]:
    """getIP.php answers JSON whose processedString reads
    "1.2.3.4 - ISP name, TH (1234 km)", or just the address."""
    try:
        data = json.loads(text)
        line = data.get("processedString", "") if isinstance(data, dict) else ""
    except ValueError:
        line = text
    ip, _, isp = line.strip().partition(" - ")
    out = {"ip": ip.strip()} if ip.strip() else {}
    if isp:
        out["isp"] = re.sub(r"\s*\(.*\)$", "", isp).strip()
    return out


def _read_meta(conn: http.client.HTTPConnection, server: _Server, meta: dict[str, str]) -> None:
    """Which server or data centre answered, the TLS version, and the public
    IP it saw."""
    meta["host"] = server.host
    if server.ookla:
        meta["colo"] = server.spec.name
        conn.request("GET", server.ping(), headers=_headers())
        conn.getresponse().read()
    elif server.librespeed:
        meta["colo"] = server.spec.name
        conn.request("GET", server._at(f"{server.spec.ip}?isp=true"), headers=_headers())
        resp = conn.getresponse()
        body = resp.read()
        if resp.status == 200:
            meta.update(parse_librespeed_ip(body.decode("utf-8", "replace")))
    else:
        conn.request("GET", "/cdn-cgi/trace", headers=_headers())
        resp = conn.getresponse()
        body = resp.read()
        if resp.status == 200:
            meta.update(parse_trace(body.decode("utf-8", "replace")))
    sock = getattr(conn, "sock", None)
    if "tls" not in meta and hasattr(sock, "version") and sock.version():
        meta["tls"] = sock.version()


def measure_latency(server: _Server, count: int,
                    meta: dict[str, str] | None = None,
                    stop: threading.Event | None = None,
                    on_rtt: Callable[[float], None] | None = None,
                    gap_s: float = 0.0) -> list[float]:
    """`count` round trips on one kept-alive connection (its connect and
    TLS handshake not counted), each passed to `on_rtt` as it comes."""
    conn = server.connect()
    try:
        if meta is not None:
            _read_meta(conn, server, meta)  # also connect + TLS, not counted
        else:
            _ping(conn, server)
        rtts = []
        for i in range(count):
            if stop is not None and stop.is_set():
                break
            if i and gap_s and stop is not None and stop.wait(gap_s):
                break
            rtts.append(_ping(conn, server))
            if on_rtt is not None:
                on_rtt(rtts[-1])
        return rtts
    finally:
        conn.close()


# ------------------------------------------------------------ server list


def parse_librespeed_list(data: object) -> list[ServerSpec]:
    servers = []
    for item in data if isinstance(data, list) else []:
        try:
            servers.append(ServerSpec(
                name=str(item["name"]), url=str(item["server"]), kind="librespeed",
                dl=str(item.get("dlURL") or "garbage.php"),
                ul=str(item.get("ulURL") or "empty.php"),
                ping=str(item.get("pingURL") or "empty.php"),
                ip=str(item.get("getIpURL") or "getIP.php"),
                sponsor=str(item.get("sponsorName") or ""),
                sponsor_url=str(item.get("sponsorURL") or ""),
            ))
        except (KeyError, TypeError):
            continue
    return [s for s in servers if s.url.startswith(("http://", "https://"))]


def parse_ookla_list(data: object, country: str = OOKLA_COUNTRY) -> list[ServerSpec]:
    """Ookla's server list: each entry's host ("name:8080"), city, sponsor."""
    servers, seen = [], set()
    for item in data if isinstance(data, list) else []:
        try:
            if str(item.get("cc", "")).upper() != country:
                continue
            host = str(item["host"]).strip()
            city = str(item["name"]).strip()
            country_name = str(item.get("country") or "Thailand").strip()
            sponsor = str(item.get("sponsor") or "").strip()
            https = item.get("https_functional") in (1, True, "1")
        except (KeyError, TypeError, AttributeError):
            continue
        if not host or host in seen:
            continue
        seen.add(host)
        servers.append(ServerSpec(f"{city}, {country_name} ({sponsor})",
                                  f"{'https' if https else 'http'}://{host}", "ookla",
                                  sponsor=sponsor))
    return servers


def _fetch_json(url: str, timeout: float) -> object:
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    with urlopen(request, timeout) as resp:
        return json.load(resp)


def fetch_servers(timeout: float = 8.0) -> list[ServerSpec]:
    """Ookla's servers in Thailand and LibreSpeed's public servers around the
    world; for either list that can't be fetched, the built-in few."""
    with ThreadPoolExecutor(max_workers=2) as pool:
        ookla = pool.submit(_fetch_json, OOKLA_LIST_URL, timeout)
        libre = pool.submit(_fetch_json, LIBRESPEED_LIST_URL, timeout)
        try:
            thai = parse_ookla_list(ookla.result())
        except (OSError, ValueError):
            thai = []
        try:
            world = parse_librespeed_list(libre.result())
        except (OSError, ValueError):
            world = []
    return (thai or list(FALLBACK_OOKLA)) + (world or list(FALLBACK_SERVERS))


#: How many of the nearest Ookla servers Automatic tries, and for how long
#: each. Connect time alone picks badly: on a 3BB line the nearest three
#: answered within 0.5 ms of each other, yet one downloaded at ~150 Mbps
#: and another at ~430, depending on how each network peers with the ISP.
AUTO_CANDIDATES = 4
PROBE_S = 1.0
PROBE_STREAMS = 4


def nearest_ookla(ranked: list[tuple[ServerSpec, float | None]],
                  count: int = 1) -> list[tuple[ServerSpec, float]]:
    """The `count` Ookla servers (in Thailand) that answered quickest, with
    their connect times, nearest first. What Automatic chooses among: a
    server inside the local ISPs, as speedtest.net picks, measures the line
    rather than the route out to Cloudflare (which on a 3BB line gave about
    220 Mbps up where a Bangkok Ookla server gave about 390)."""
    reachable = [(s, ms) for s, ms in ranked if s.kind == "ookla" and ms is not None]
    return sorted(reachable, key=lambda item: item[1])[:count]


def pick_fastest(specs: tuple[ServerSpec, ...] | list[ServerSpec], seconds: float = PROBE_S,
                 stop: threading.Event | None = None) -> ServerSpec | None:
    """Download from each server for `seconds`, one after another, and
    return the fastest (None if none of them sent anything)."""
    best, best_mbps = None, 0.0
    probe = SpeedTestOptions(duration_s=seconds, ramp_s=seconds * 0.3, streams=PROBE_STREAMS)
    for spec in specs:
        if stop is not None and stop.is_set():
            break
        try:
            speed = run_transfer(_Server(spec), False, probe, stop=stop).mbps
        except (OSError, ValueError, http.client.HTTPException):
            continue
        if speed > best_mbps:
            best, best_mbps = spec, speed
    return best


def connect_time_ms(spec: ServerSpec, timeout: float = 2.0, tries: int = 2) -> float | None:
    """How near a server is: the quickest TCP connect to it, in ms (None if
    it can't be reached). A server that fails once isn't asked again, so an
    unreachable one costs one timeout, not `tries` of them."""
    url = urllib.parse.urlsplit(spec.url)
    if not url.hostname:
        return None
    port = url.port or (443 if url.scheme == "https" else 80)
    best = None
    for _ in range(tries):
        start = time.perf_counter()
        try:
            socket.create_connection((url.hostname, port), timeout=timeout).close()
        except OSError:
            break
        ms = (time.perf_counter() - start) * 1000
        best = ms if best is None else min(best, ms)
    return best


#: Servers timed at once: enough that a list of ~120 takes about as long as
#: its farthest server, not a dozen of them back to back.
RANK_WORKERS = 64
#: How often the servers timed so far are handed over while ranking.
RANK_PROGRESS_S = 0.25


def _ranked(servers: list[ServerSpec], times: dict[str, float | None]) -> list[tuple[ServerSpec, float | None]]:
    ranked = [(spec, times.get(spec.url)) for spec in servers]
    ranked.sort(key=lambda st: (st[1] is None, st[1] or 0, st[0].name))
    return ranked


def rank_servers(
    servers: list[ServerSpec],
    on_progress: Callable[[list[tuple[ServerSpec, float | None]]], None] | None = None,
) -> list[tuple[ServerSpec, float | None]]:
    """Every server with its connect time, nearest first, unreachable last.
    ``on_progress``, if given, gets the servers reached so far (ranked) as
    they come in, so a list can be shown before the slowest is timed."""
    if not servers:
        return []
    times: dict[str, float | None] = {}
    last = time.monotonic()
    with ThreadPoolExecutor(max_workers=min(RANK_WORKERS, len(servers))) as pool:
        futures = {pool.submit(connect_time_ms, spec): spec for spec in servers}
        for future in as_completed(futures):
            try:
                times[futures[future].url] = future.result()
            except Exception:
                times[futures[future].url] = None
            if on_progress is not None and time.monotonic() - last >= RANK_PROGRESS_S:
                last = time.monotonic()
                reached = [spec for spec in servers if times.get(spec.url) is not None]
                on_progress(_ranked(reached, times))
    return _ranked(servers, times)


# --------------------------------------------------------------- transfers


class _Counter:
    """Bytes moved so far. Downloads add what they read. Uploads count what
    the server has acknowledged: what was written to each connection less
    what its send buffer still holds (send_queue), since a fresh buffer
    takes megabytes at once and the first second would read far too fast."""

    def __init__(self) -> None:
        self._bytes = 0
        self.lock = threading.Lock()
        self.errors: list[str] = []
        #: Per upload stream: [socket, bytes written on it, bytes known to
        #: have arrived (all of them once a response came back)].
        self._uploads: dict[int, list] = {}

    def add(self, n: int) -> None:
        with self.lock:
            self._bytes += n

    @staticmethod
    def _arrived(entry: list) -> int:
        sock, written, settled = entry
        waiting = send_queue.queued(sock, written)
        if waiting is None:
            return written  # can't tell: count it as sent, as before
        return max(settled, written - min(max(waiting, 0), written))

    @property
    def value(self) -> int:
        with self.lock:
            return self._bytes + sum(self._arrived(e) for e in self._uploads.values())

    def upload_on(self, key: int, sock) -> None:
        """Stream `key` is sending on `sock` (a new connection or the same)."""
        with self.lock:
            entry = self._uploads.get(key)
            if entry is not None and entry[0] is sock:
                return
            if entry is not None:
                self._bytes += self._arrived(entry)
            self._uploads[key] = [sock, 0, 0]

    def wrote(self, key: int, n: int) -> None:
        with self.lock:
            self._uploads[key][1] += n

    def settle(self, key: int) -> None:
        """The server answered: everything written so far has arrived."""
        with self.lock:
            entry = self._uploads.get(key)
            if entry is not None:
                entry[2] = entry[1]

    def upload_closing(self, key: int) -> None:
        """Called before the stream's socket closes, while it can still be asked."""
        with self.lock:
            entry = self._uploads.pop(key, None)
            if entry is not None:
                self._bytes += self._arrived(entry)


def next_chunk(size: int, elapsed_s: float, cap: int) -> int:
    """The size for a stream's next request: about REQUEST_TARGET_S at the
    speed the last one (`size` bytes in `elapsed_s`) ran, within MIN_CHUNK
    and `cap`."""
    if elapsed_s <= 0:
        return size
    return max(MIN_CHUNK, min(cap, int(size / elapsed_s * REQUEST_TARGET_S)))


def _download_stream(server: _Server, counter: _Counter, done: threading.Event) -> None:
    conn = None
    cap = min(MAX_CHUNK, server.max_down)
    size = min(DOWN_CHUNK, cap)
    while not done.is_set():
        try:
            if conn is None:
                conn = server.connect()
            started = time.perf_counter()
            conn.request("GET", server.down(size), headers=_headers())
            resp = conn.getresponse()
            if resp.status in TOO_BIG and size > MIN_CHUNK:
                resp.read()
                size = cap = max(MIN_CHUNK, size // 2)  # ask for less from now on
                continue
            if resp.status != 200:
                resp.read()
                raise OSError(http_error(resp.status))
            while not done.is_set():
                data = resp.read(READ_SIZE)
                if not data:
                    break
                counter.add(len(data))
            if done.is_set():
                # Mid-body: reset rather than let the rest of a big
                # response keep arriving into the next phase.
                _abort(conn)
                conn = None
                break
            size = next_chunk(size, time.perf_counter() - started, cap)
        except (OSError, http.client.HTTPException) as exc:
            counter.errors.append(str(exc) or type(exc).__name__)
            if conn is not None:
                conn.close()
            conn = None
            if done.wait(0.5):
                break
    if conn is not None:
        conn.close()


def _abort(conn: http.client.HTTPConnection) -> None:
    """Close at once, discarding unsent data (a reset, not a graceful close)."""
    sock = getattr(conn, "sock", None)
    if sock is not None:
        try:
            # struct linger: two ints on macOS/Linux, two u_shorts on Windows.
            linger = struct.pack("HH" if sys.platform == "win32" else "ii", 1, 0)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, linger)
        except OSError:
            pass
    conn.close()


def _upload_stream(server: _Server, counter: _Counter, done: threading.Event) -> None:
    chunk = b"0" * READ_SIZE
    key = threading.get_ident()
    conn = None
    size, cap = UP_CHUNK, MAX_CHUNK
    while not done.is_set():
        try:
            if conn is None:
                conn = server.connect()
            started = time.perf_counter()
            conn.putrequest("POST", server.up(), skip_accept_encoding=True)
            for k, v in _headers().items():
                conn.putheader(k, v)
            conn.putheader("Content-Type", "application/octet-stream")
            conn.putheader("Content-Length", str(size))
            conn.endheaders()
            counter.upload_on(key, conn.sock)
            sent = 0
            while sent < size and not done.is_set():
                n = min(READ_SIZE, size - sent)
                conn.send(chunk[:n])
                sent += n
                counter.wrote(key, n)
            if done.is_set():
                # Mid-body: drop what the kernel still holds to send, or it
                # goes on uploading after the phase and slows the ping after.
                counter.upload_closing(key)
                _abort(conn)
                conn = None
                break
            resp = conn.getresponse()
            resp.read()
            counter.settle(key)
            if resp.status in TOO_BIG and size > MIN_CHUNK:
                size = cap = max(MIN_CHUNK, size // 2)
                continue
            if resp.status not in (200, 204):
                raise OSError(http_error(resp.status))
            size = next_chunk(size, time.perf_counter() - started, cap)
        except (OSError, http.client.HTTPException) as exc:
            counter.errors.append(str(exc) or type(exc).__name__)
            counter.upload_closing(key)
            if conn is not None:
                conn.close()
            conn = None
            # A server that cuts off a body too big for it shows up here
            # rather than as a 413: try a smaller one (it may grow again).
            size = max(MIN_CHUNK, size // 2)
            if done.wait(0.5):
                break
    counter.upload_closing(key)
    if conn is not None:
        conn.close()


def _loaded_pinger(server: _Server, done: threading.Event, out: list[float]) -> None:
    try:
        conn = server.connect()
        _ping(conn, server)
        while not done.wait(0.2):
            out.append(_ping(conn, server))
        conn.close()
    except (OSError, http.client.HTTPException):
        pass


def run_transfer(server: _Server, upload: bool, options: SpeedTestOptions,
                 on_sample: Callable[[float, float], None] | None = None,
                 stop: threading.Event | None = None) -> TransferResult:
    counter = _Counter()
    done = threading.Event()
    loaded: list[float] = []
    worker = _upload_stream if upload else _download_stream
    threads = [threading.Thread(target=worker, args=(server, counter, done), daemon=True)
               for _ in range(options.streams)]
    threads.append(threading.Thread(target=_loaded_pinger, args=(server, done, loaded),
                                    daemon=True))
    start = time.perf_counter()
    for t in threads:
        t.start()
    points = [(0.0, 0)]
    try:
        while True:
            time.sleep(SAMPLE_INTERVAL_S)
            now = time.perf_counter() - start
            points.append((now, counter.value))
            if on_sample is not None:
                on_sample(now, rolling_mbps(points))
            if now >= options.duration_s or (stop is not None and stop.is_set()):
                break
    finally:
        done.set()
        for t in threads:
            t.join(timeout=2)
    result = summarize(points, options.ramp_s)
    if loaded:
        result.loaded_latency_ms = statistics.median(loaded)
    if result.bytes == 0:
        if counter.errors:
            raise OSError(counter.errors[0])
        if not (stop is not None and stop.is_set()):
            raise OSError("no data came back from the server")
    return result


def _pause(options: SpeedTestOptions, stop: threading.Event | None,
           on_phase: Callable[[str], None] | None) -> bool:
    """The quiet between phases; False if stopped meanwhile."""
    if options.pause_s <= 0:
        return True
    if on_phase:
        on_phase("pause")
    if stop is not None:
        return not stop.wait(options.pause_s)
    time.sleep(options.pause_s)
    return True


def run_test(options: SpeedTestOptions,
             on_phase: Callable[[str], None] | None = None,
             on_sample: Callable[[str, float, float], None] | None = None,
             stop: threading.Event | None = None,
             on_progress: Callable[[SpeedResult], None] | None = None) -> SpeedResult:
    """As nPerf runs it: connect, download, a pause, upload, a pause, then
    ping (latency and jitter, on the line the transfers have left quiet).
    ``on_phase`` gets "choose" (Automatic trying its candidates), "connect",
    "download", "pause", "upload", "ping";
    ``on_sample`` gets (phase, seconds, value): Mbps for the transfers, the
    round trip in ms for each ping; ``on_progress`` gets the result so far
    after each phase."""
    result = SpeedResult()
    stopped = lambda: stop is not None and stop.is_set()  # noqa: E731
    try:
        spec = options.server
        if options.candidates:
            if on_phase:
                on_phase("choose")
            spec = pick_fastest(options.candidates, stop=stop) or spec
        result.meta["server_url"] = spec.url if isinstance(spec, ServerSpec) else spec
        server = _Server(spec)
        if on_phase:
            on_phase("connect")
        measure_latency(server, 0, result.meta, stop)  # reachable? and who answers
        if on_progress:
            on_progress(copy.deepcopy(result))
        ran = False
        for phase, enabled in (("download", options.download), ("upload", options.upload)):
            if not enabled or stopped():
                continue
            if ran and not _pause(options, stop, on_phase):
                break
            if on_phase:
                on_phase(phase)
            cb = (lambda t, v, p=phase: on_sample(p, t, v)) if on_sample else None
            setattr(result, phase, run_transfer(server, phase == "upload", options, cb, stop))
            ran = True
            if on_progress:
                on_progress(copy.deepcopy(result))
        if options.latency_count > 0 and not stopped() and (not ran or _pause(options, stop, on_phase)):
            if on_phase:
                on_phase("ping")
            start = time.perf_counter()
            on_rtt = ((lambda ms: on_sample("ping", time.perf_counter() - start, ms))
                      if on_sample else None)
            rtts = measure_latency(server, options.latency_count, None, stop, on_rtt,
                                   options.ping_gap_s)
            if rtts:
                result.latency_ms = statistics.median(rtts)
                result.jitter_ms = jitter(rtts)
                result.ping_count = len(rtts)
            if on_progress:
                on_progress(copy.deepcopy(result))
    except (OSError, ValueError, http.client.HTTPException) as exc:
        result.error = str(exc) or type(exc).__name__
    return result


if __name__ == "__main__":  # python -m NetInfoView.ping.speedtest [server]
    import sys

    opts = SpeedTestOptions(server=sys.argv[1]) if len(sys.argv) > 1 else SpeedTestOptions()
    r = run_test(opts, on_phase=lambda p: print(f"-- {p}", flush=True))
    print(f"server   {r.meta}")
    if r.latency_ms is not None:
        print(f"latency  {r.latency_ms:.1f} ms  jitter {r.jitter_ms:.1f} ms")
    for name in ("download", "upload"):
        t = getattr(r, name)
        if t:
            loaded = f"{t.loaded_latency_ms:.0f} ms" if t.loaded_latency_ms else "-"
            print(f"{name:8} {t.mbps:.1f} Mbps  peak {t.peak_mbps:.1f}  "
                  f"{t.bytes / 1e6:.0f} MB  loaded ping {loaded}")
    if r.error:
        print("error", r.error)
