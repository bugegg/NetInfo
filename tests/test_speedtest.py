import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from NetInfoView.ping import speedtest
from NetInfoView.ping.speedtest import (
    ServerSpec, SpeedTestOptions, _Server, jitter, parse_librespeed_ip, parse_librespeed_list,
    parse_trace, server_time_ms, summarize,
)


def test_summarize_drops_the_ramp_and_keeps_the_peak():
    # 1 MB per 0.5 s for the first second (16 Mbps), then 2 MB per 0.5 s (32 Mbps).
    points = [(0.0, 0), (0.5, 1_000_000), (1.0, 2_000_000), (1.5, 4_000_000), (2.0, 6_000_000)]
    r = summarize(points, ramp_s=1.0)
    assert r.mbps == pytest.approx(32.0)
    assert r.peak_mbps == pytest.approx(32.0)
    assert r.bytes == 6_000_000
    # Each sample is the speed over the second up to it.
    assert [round(s) for _, s in r.samples] == [16, 16, 24, 32]


def test_peak_is_over_a_rolling_second_not_one_burst():
    # Steady 8 Mbps (100 kB per 0.1 s) with one 0.1 s burst of 1 MB.
    points, total = [(0.0, 0)], 0
    for i in range(1, 31):
        total += 1_000_000 if i == 20 else 100_000
        points.append((i / 10, total))
    r = summarize(points, ramp_s=0.0)
    # The graph's samples are rolling seconds too, so they top out at the peak.
    assert max(s for _, s in r.samples) == pytest.approx(15.2)
    assert r.peak_mbps == pytest.approx(15.2)  # 1.9 MB over the second around it


def test_rolling_mbps_smooths_bursts_one_round_trip_apart():
    # 2.5 MB lands every 0.2 s, nothing in between: 100 Mbps on average.
    points, total = [(0.0, 0)], 0
    for i in range(1, 31):
        total += 2_500_000 if i % 2 == 0 else 0
        points.append((i / 10, total))
    assert speedtest.rolling_mbps(points) == pytest.approx(100.0)
    assert speedtest.rolling_mbps(points[:3]) == pytest.approx(100.0)  # 0.2 s so far
    assert speedtest.rolling_mbps(points[:1]) == 0.0


def test_average_leaves_out_the_fastest_and_slowest_slices():
    # 40 Mbps (0.5 MB per 0.1 s) for 2 s, but stalled for 0.2 s of it and
    # with one 0.1 s burst: the plain average would swing with both.
    points, total = [(0.0, 0)], 0
    for i in range(1, 21):
        total += {5: 0, 6: 0, 15: 2_000_000}.get(i, 500_000)
        points.append((i / 10, total))
    plain = speedtest.mbps(total, 2.0)
    assert plain != pytest.approx(40.0)
    assert speedtest.trimmed_mbps(points) == pytest.approx(40.0)
    assert summarize(points, ramp_s=0.0).mbps == pytest.approx(40.0)


def test_trimmed_average_falls_back_to_plain_with_few_points():
    points = [(0.0, 0), (0.5, 1_000_000), (1.0, 3_000_000)]
    assert speedtest.trimmed_mbps(points) == pytest.approx(24.0)


def test_next_chunk_aims_for_a_few_seconds_per_request():
    target = speedtest.REQUEST_TARGET_S
    # 25 MB in 0.5 s (400 Mbps): the next one is 50 MB per second of target.
    assert speedtest.next_chunk(25_000_000, 0.5, speedtest.MAX_CHUNK) == int(50_000_000 * target)
    assert speedtest.next_chunk(25_000_000, 0.01, 60_000_000) == 60_000_000  # capped
    assert speedtest.next_chunk(25_000_000, 1000.0, speedtest.MAX_CHUNK) == speedtest.MIN_CHUNK
    assert speedtest.next_chunk(25_000_000, 0.0, speedtest.MAX_CHUNK) == 25_000_000


def test_summarize_uses_everything_when_too_short_for_the_ramp():
    r = summarize([(0.0, 0), (0.5, 1_000_000)], ramp_s=2.0)
    assert r.mbps == pytest.approx(16.0)


def test_summarize_empty():
    assert summarize([(0.0, 0)], 2.0).mbps == 0.0


def test_jitter_is_mean_consecutive_difference():
    assert jitter([10, 12, 11, 15]) == pytest.approx((2 + 1 + 4) / 3)
    assert jitter([10]) == 0.0


def test_server_time_sums_the_durations():
    header = 'cfSpeedEdge;dur=3, cfSpeedWorker;dur=21.5, cfL4;desc="?proto=TCP&rtt=9114"'
    assert server_time_ms(header) == pytest.approx(24.5)
    assert server_time_ms(None) == 0.0


def test_parse_trace():
    assert parse_trace("fl=1\nip=1.2.3.4\ncolo=BKK\nloc=TH\n") == {
        "ip": "1.2.3.4", "colo": "BKK", "loc": "TH"}


class _Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    uploaded = 0
    #: Downloads bigger than this get a 403, as Cloudflare does from 100 MB.
    max_down: int | None = None
    #: Sizes of the downloads asked for.
    requested: list[int] = []

    def log_message(self, *args):
        pass

    def do_GET(self):
        if "getIP.php" in self.path:
            body = b'{"processedString":"203.0.113.9 - Example ISP, TH (12 km)","rawIspInfo":""}'
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        if self.path.startswith("/hello"):
            body = b"hello 2.11"
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        if self.path.startswith("/download?size="):
            n = int(self.path.split("size=")[1])
        elif "garbage.php" in self.path:
            n = int(self.path.split("ckSize=")[1]) * 1_048_576
        else:
            n = int(self.path.split("bytes=")[1]) if "bytes=" in self.path else 0
        type(self).requested.append(n)
        if self.max_down is not None and n > self.max_down:
            self.send_response(403)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        known = ("__down" in self.path or "garbage.php" in self.path or "empty.php" in self.path
                 or self.path.startswith("/download"))
        self.send_response(200 if known else 404)
        self.send_header("Content-Length", str(n))
        self.end_headers()
        chunk = b"x" * 65536
        try:
            while n > 0:
                self.wfile.write(chunk[:n])
                n -= min(n, 65536)
        except OSError:
            pass

    def do_POST(self):  # /__up, empty.php and Ookla's /upload alike
        left = int(self.headers["Content-Length"])
        while left > 0:
            data = self.rfile.read(min(left, 65536))
            if not data:
                return
            left -= len(data)
            type(self).uploaded += len(data)
        self.send_response(200)
        self.send_header("Content-Length", "0")
        self.end_headers()


@pytest.fixture
def server():
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    httpd.daemon_threads = True
    httpd.handle_error = lambda *args: None  # clients drop connections mid-transfer
    t = threading.Thread(target=httpd.serve_forever, daemon=True)
    t.start()
    yield f"http://127.0.0.1:{httpd.server_address[1]}"
    httpd.shutdown()
    httpd.server_close()


def test_full_run_against_a_local_server(server, monkeypatch):
    monkeypatch.setattr(speedtest, "DOWN_CHUNK", 2_000_000)
    monkeypatch.setattr(speedtest, "UP_CHUNK", 1_000_000)
    phases, samples = [], []
    opts = SpeedTestOptions(server=server, duration_s=0.6, ramp_s=0.2, streams=2,
                            latency_count=3, pause_s=0.2)
    r = speedtest.run_test(opts, on_phase=phases.append,
                           on_sample=lambda p, t, v: samples.append(p))
    assert r.error == ""
    assert phases == ["connect", "download", "pause", "upload", "pause", "ping"]
    assert r.latency_ms is not None and r.jitter_ms is not None
    assert r.download.mbps > 0 and r.download.bytes > 0
    assert r.upload.mbps > 0 and _Handler.uploaded > 0
    assert {"download", "upload", "ping"} <= set(samples)
    assert r.ping_count == 3
    assert r.meta["host"] == "127.0.0.1"


def test_stop_ends_the_run_early(server):
    stop = threading.Event()
    stop.set()
    r = speedtest.run_test(SpeedTestOptions(server=server, latency_count=3), stop=stop)
    assert r.download is None and r.upload is None


def test_unreachable_server_reports_an_error():
    r = speedtest.run_test(SpeedTestOptions(server="http://127.0.0.1:9", latency_count=1))
    assert r.error


def test_bad_url():
    assert speedtest.run_test(SpeedTestOptions(server="ftp://x")).error


def test_librespeed_paths():
    spec = ServerSpec("Tokyo", "https://librespeed.example/", "librespeed",
                      "backend/garbage.php", "backend/empty.php", "backend/empty.php")
    server = _Server(spec)
    assert server.down(5_000_000) == "/backend/garbage.php?ckSize=5"
    assert server.down(250_000) == "/backend/garbage.php?ckSize=1"
    assert server.up() == "/backend/empty.php"
    assert server.ping().startswith("/backend/empty.php?r=")
    cf = _Server("https://speed.cloudflare.com")
    assert cf.down(10) == "/__down?bytes=10" and cf.up() == "/__up" and cf.ping() == "/__down?bytes=0"


def test_parse_librespeed_list_skips_bad_entries():
    data = [
        {"name": "Tokyo, Japan (A573)", "server": "https://librespeed.a573.net/",
         "dlURL": "backend/garbage.php", "ulURL": "backend/empty.php",
         "pingURL": "backend/empty.php", "getIpURL": "backend/getIP.php", "sponsorName": "A573"},
        {"name": "no server"},
        {"name": "ftp", "server": "ftp://x"},
    ]
    servers = parse_librespeed_list(data)
    assert [s.name for s in servers] == ["Tokyo, Japan (A573)"]
    assert servers[0].kind == "librespeed" and servers[0].dl == "backend/garbage.php"
    assert parse_librespeed_list({"not": "a list"}) == []


def test_parse_librespeed_ip():
    assert parse_librespeed_ip('{"processedString":"1.2.3.4 - True Internet, TH (5 km)"}') == {
        "ip": "1.2.3.4", "isp": "True Internet, TH"}
    assert parse_librespeed_ip("1.2.3.4") == {"ip": "1.2.3.4"}


def test_fetch_servers_falls_back_when_offline(monkeypatch):
    def fail(*a, **k):
        raise OSError("offline")
    monkeypatch.setattr(speedtest, "urlopen", fail)
    assert speedtest.fetch_servers() == (list(speedtest.FALLBACK_OOKLA)
                                         + list(speedtest.FALLBACK_SERVERS))


def test_parse_ookla_list_keeps_thai_servers_once():
    data = [
        {"host": "spd-bkk1.trueinternet.co.th:8080", "name": "Bangkok", "country": "Thailand",
         "cc": "TH", "sponsor": "True Online", "https_functional": 1},
        {"host": "spd-bkk1.trueinternet.co.th:8080", "name": "Bangkok", "country": "Thailand",
         "cc": "TH", "sponsor": "True Online", "https_functional": 1},
        {"host": "plain.example:8080", "name": "Hat Yai", "country": "Thailand", "cc": "TH",
         "sponsor": "NT", "https_functional": None},
        {"host": "sg.example:8080", "name": "Singapore", "country": "Singapore", "cc": "SG"},
        {"name": "no host", "cc": "TH"},
    ]
    servers = speedtest.parse_ookla_list(data)
    assert [(s.name, s.url, s.kind) for s in servers] == [
        ("Bangkok, Thailand (True Online)", "https://spd-bkk1.trueinternet.co.th:8080", "ookla"),
        ("Hat Yai, Thailand (NT)", "http://plain.example:8080", "ookla"),
    ]


def test_ookla_paths():
    server = _Server(ServerSpec("Bangkok", "https://spd.example:8080", "ookla"))
    assert server.down(5_000_000) == "/download?size=5000000"
    assert server.up() == "/upload"
    assert server.ping().startswith("/hello?nocache=")


def test_full_run_against_a_local_ookla_server(server, monkeypatch):  # noqa: F811
    monkeypatch.setattr(speedtest, "DOWN_CHUNK", 2_000_000)
    monkeypatch.setattr(speedtest, "UP_CHUNK", 1_000_000)
    spec = ServerSpec("Bangkok, Thailand (Local)", server, "ookla", sponsor="Local")
    r = speedtest.run_test(SpeedTestOptions(server=spec, duration_s=0.6, ramp_s=0.2,
                                            streams=2, latency_count=3, pause_s=0))
    assert r.error == ""
    assert r.latency_ms is not None
    assert r.download.bytes > 0 and r.upload.bytes > 0
    assert r.meta["colo"] == "Bangkok, Thailand (Local)"


def test_rank_servers_puts_nearest_first_and_unreachable_last(monkeypatch):
    a, b, c = (ServerSpec(n, f"https://{n}.example") for n in "abc")
    times = {"a": 80.0, "b": None, "c": 20.0}
    monkeypatch.setattr(speedtest, "connect_time_ms", lambda spec: times[spec.name])
    assert speedtest.rank_servers([a, b, c]) == [(c, 20.0), (a, 80.0), (b, None)]


def test_full_run_against_a_local_librespeed_server(server, monkeypatch):
    monkeypatch.setattr(speedtest, "DOWN_CHUNK", 2_000_000)
    monkeypatch.setattr(speedtest, "UP_CHUNK", 1_000_000)
    spec = ServerSpec("Local, Test", server, "librespeed")
    r = speedtest.run_test(SpeedTestOptions(server=spec, duration_s=0.6, ramp_s=0.2,
                                            streams=2, latency_count=3))
    assert r.error == ""
    assert r.download.bytes > 0 and r.upload.bytes > 0
    assert r.meta["colo"] == "Local, Test" and r.meta["ip"] == "203.0.113.9"
    assert r.meta["isp"] == "Example ISP, TH"


def test_no_data_is_an_error_not_zero_mbps(monkeypatch):
    class Silent(speedtest._Server):
        pass
    monkeypatch.setattr(speedtest, "_download_stream", lambda server, counter, done: done.wait(1))
    monkeypatch.setattr(speedtest, "_loaded_pinger", lambda server, done, out: None)
    with pytest.raises(OSError, match="no data"):
        speedtest.run_transfer(Silent("http://127.0.0.1:9"), False,
                               SpeedTestOptions(duration_s=0.3, streams=1))


def test_stop_during_the_pause_skips_upload(server, monkeypatch):  # noqa: F811
    monkeypatch.setattr(speedtest, "DOWN_CHUNK", 2_000_000)
    stop = threading.Event()

    def on_phase(phase):
        if phase == "pause":
            stop.set()
    r = speedtest.run_test(SpeedTestOptions(server=server, duration_s=0.3, ramp_s=0.1,
                                            streams=1, latency_count=1, pause_s=5),
                           on_phase=on_phase, stop=stop)
    assert r.download is not None and r.upload is None


def test_ping_comes_last_after_the_transfers(server, monkeypatch):  # noqa: F811
    monkeypatch.setattr(speedtest, "DOWN_CHUNK", 2_000_000)
    monkeypatch.setattr(speedtest, "UP_CHUNK", 1_000_000)
    order = []
    r = speedtest.run_test(
        SpeedTestOptions(server=server, duration_s=0.3, ramp_s=0.1, streams=1,
                         latency_count=4, pause_s=0.05, ping_gap_s=0),
        on_sample=lambda phase, t, v: order.append(phase))
    assert r.error == "" and r.ping_count == 4
    assert order[-4:] == ["ping"] * 4
    assert order.index("ping") > max(i for i, p in enumerate(order) if p == "upload")


def test_stop_before_the_ping_leaves_no_latency(server, monkeypatch):  # noqa: F811
    monkeypatch.setattr(speedtest, "DOWN_CHUNK", 2_000_000)
    stop = threading.Event()
    pauses = []

    def on_phase(phase):
        if phase == "pause":
            pauses.append(phase)
            if len(pauses) == 2:  # the pause before the ping
                stop.set()
    r = speedtest.run_test(SpeedTestOptions(server=server, duration_s=0.2, ramp_s=0.05,
                                            streams=1, pause_s=1),
                           on_phase=on_phase, stop=stop)
    assert r.upload is not None and r.latency_ms is None


def test_rank_servers_hands_over_the_reached_servers_as_they_come(monkeypatch):
    import time as _time

    from NetInfoView.ping.speedtest import ServerSpec

    near, far, dead = (ServerSpec(n, f"https://{n}.example") for n in ("near", "far", "dead"))

    def fake_time(spec, *a, **k):
        if spec is far:
            _time.sleep(0.3)
            return 80.0
        return None if spec is dead else 5.0

    monkeypatch.setattr(speedtest, "connect_time_ms", fake_time)
    monkeypatch.setattr(speedtest, "RANK_PROGRESS_S", 0)
    partials = []
    ranked = speedtest.rank_servers([far, dead, near], on_progress=partials.append)
    assert [s.name for s, _ in ranked] == ["near", "far", "dead"]
    # The near server shows up before the far one has been timed, and an
    # unreachable one never appears in a partial list.
    assert any([s.name for s, _ in p] == ["near"] for p in partials)
    assert all("dead" not in [s.name for s, _ in p] for p in partials)


def test_an_unreachable_server_is_tried_only_once(monkeypatch):
    from NetInfoView.ping.speedtest import ServerSpec

    attempts = []

    def refuse(address, timeout):
        attempts.append(address)
        raise OSError("refused")

    monkeypatch.setattr(speedtest.socket, "create_connection", refuse)
    assert speedtest.connect_time_ms(ServerSpec("x", "https://x.example")) is None
    assert len(attempts) == 1


def test_download_halves_and_stays_under_a_size_the_server_refuses(server, monkeypatch):
    monkeypatch.setattr(speedtest, "DOWN_CHUNK", 2_000_000)
    monkeypatch.setattr(_Handler, "max_down", 1_500_000)
    monkeypatch.setattr(_Handler, "requested", [])
    opts = SpeedTestOptions(server=server, duration_s=0.5, ramp_s=0.1, streams=1)
    r = speedtest.run_transfer(_Server(server), upload=False, options=opts)
    assert r.bytes > 0
    asked = [n for n in _Handler.requested if n]  # not the 0-byte pings alongside
    assert asked[0] == 2_000_000 and asked[1] == 1_000_000
    # Grown again on loopback's speed, but never back past the refused size.
    assert all(n <= 1_000_000 for n in asked[1:])


def test_cloudflare_downloads_start_under_its_limit():
    cloudflare = _Server(speedtest.CLOUDFLARE)
    assert cloudflare.max_down == speedtest.CLOUDFLARE_MAX_DOWN < 100_000_000
    assert _Server("https://speed.example.com").max_down == speedtest.MAX_CHUNK
    assert speedtest.DOWN_CHUNK == speedtest.UP_CHUNK == 100_000_000


def test_automatic_tests_the_fastest_candidate(server, monkeypatch):
    slow = ServerSpec("Slow", server + "/slow", "ookla")
    fast = ServerSpec("Fast", server + "/fast", "ookla")
    dead = ServerSpec("Dead", "http://127.0.0.1:9", "ookla")
    speeds = {"Slow": 100.0, "Fast": 400.0}

    def probe(srv, upload, options, on_sample=None, stop=None):
        if srv.spec.name not in speeds:
            raise OSError("refused")
        return speedtest.TransferResult(mbps=speeds[srv.spec.name])

    monkeypatch.setattr(speedtest, "run_transfer", probe)
    assert speedtest.pick_fastest((slow, dead, fast)) == fast
    assert speedtest.pick_fastest((dead,)) is None
    phases = []
    opts = SpeedTestOptions(server=slow, candidates=(slow, dead, fast), download=False,
                            upload=False, latency_count=0)
    r = speedtest.run_test(opts, on_phase=phases.append)
    assert phases[:2] == ["choose", "connect"]
    assert r.meta["server_url"] == fast.url
