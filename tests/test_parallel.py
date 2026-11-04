"""Tests for ping/parallel.py and the probes that use it."""

import time

from pinginfoview.ping import hostname, mtu
from pinginfoview.ping.parallel import first_answer


def test_first_answer_keeps_list_order_but_runs_at_once():
    def slow(answer, seconds):
        def call():
            time.sleep(seconds)
            return answer
        return call

    started = time.monotonic()
    assert first_answer([slow("", 0.3), slow("second", 0.3), slow("third", 0.0)]) == "second"
    assert time.monotonic() - started < 0.5
    assert first_answer([slow("x", 0), slow("y", 0)], usable=lambda a: a == "y") == "y"
    assert first_answer([]) == ""


def test_first_answer_skips_a_source_that_raises():
    def boom():
        raise OSError("no route")

    assert first_answer([boom, lambda: "ok"]) == "ok"


def test_off_link_hosts_skip_multicast_probes(monkeypatch):
    asked = []

    def multicast(ip):
        asked.append("multicast")
        return "from-multicast"

    def unicast(ip):
        asked.append("unicast")
        return ""

    monkeypatch.setattr(hostname, "DEVICE_PROBES", (multicast, unicast))
    monkeypatch.setattr(hostname, "LINK_ONLY_PROBES", (multicast,))
    monkeypatch.setattr(hostname, "_on_link", lambda ip: False)
    assert hostname._ask_device("10.30.2.32") == ""
    assert asked == ["unicast"]
    monkeypatch.setattr(hostname, "_on_link", lambda ip: True)
    assert hostname._ask_device("192.168.1.20") == "from-multicast"


def test_route_mtu_is_remembered_per_address(monkeypatch):
    calls = []
    monkeypatch.setattr(mtu, "route_mtu", lambda ip: calls.append(ip) or 1500)
    monkeypatch.setattr(mtu, "_route_cache", {})
    assert mtu.cached_route_mtu("10.0.0.1") == 1500
    assert mtu.cached_route_mtu("10.0.0.1") == 1500
    assert mtu.cached_route_mtu("10.0.0.2") == 1500
    assert calls == ["10.0.0.1", "10.0.0.2"]
