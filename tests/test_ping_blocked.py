"""A host that drops ping but accepts TCP connections shows as "Ping blocked"."""

import asyncio
import socket

from NetInfoView.model.host import HostEntry
from NetInfoView.ping import engine as engine_module
from NetInfoView.ping.engine import PingEngine, PingTarget
from NetInfoView.ping.result import PingResult, PingStatus
from NetInfoView.ui.dashboard import status_badge


class _SilentPinger:
    """Every ping times out, as for a host whose firewall drops ICMP."""

    dont_fragment_supported = False

    def open(self):
        pass

    def close(self):
        pass

    def configure(self, ttl=None, dont_fragment=None):
        pass

    async def ping(self, ip, timeout_ms, payload_size=32):
        return PingResult(PingStatus.TIMEOUT)


def _engine(monkeypatch, ports, intercepted=frozenset()):
    monkeypatch.setattr(engine_module, "TCP_FALLBACK_PORTS", ports)

    async def find_intercepted():
        return intercepted

    engine = PingEngine(on_results=lambda batch: None)
    engine._pinger = _SilentPinger()
    monkeypatch.setattr(engine, "_find_intercepted", find_intercepted)
    return engine


def test_failed_ping_finds_an_open_port(monkeypatch):
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen()
    open_port = listener.getsockname()[1]
    closed = socket.socket()
    closed.bind(("127.0.0.1", 0))
    closed_port = closed.getsockname()[1]
    closed.close()
    try:
        engine = _engine(monkeypatch, (closed_port, open_port))
        target = PingTarget(key=1, host="127.0.0.1", resolved_ip="127.0.0.1")
        result = asyncio.run(engine._ping_once(target))
    finally:
        listener.close()
    assert result.status is PingStatus.TIMEOUT and result.tcp_port == open_port


def test_ports_are_tried_again_only_after_a_while(monkeypatch):
    tried = []

    async def first_open_port(ip, ports, timeout_ms):
        tried.append(ip)
        return 443

    monkeypatch.setattr(engine_module, "first_open_port", first_open_port)
    engine = _engine(monkeypatch, (443,))
    target = PingTarget(key=1, host="192.0.2.1", resolved_ip="192.0.2.1")

    async def two_pings():
        return [await engine._ping_once(target) for _ in range(2)]

    assert [r.tcp_port for r in asyncio.run(two_pings())] == [443, 443]
    assert tried == ["192.0.2.1"]  # the second ping reused the first answer


def test_a_host_that_answers_ping_is_never_ping_blocked(monkeypatch):
    tried = []

    async def first_open_port(ip, ports, timeout_ms):
        tried.append(ip)
        return 3389

    replies = iter([PingResult(PingStatus.SUCCEEDED, 1.0, "192.0.2.1"),
                    PingResult(PingStatus.TIMEOUT)])

    async def ping(ip, timeout_ms, payload_size=32):
        return next(replies)

    monkeypatch.setattr(engine_module, "first_open_port", first_open_port)
    engine = _engine(monkeypatch, (3389,))
    engine._pinger.ping = ping
    target = PingTarget(key=1, host="192.0.2.1", resolved_ip="192.0.2.1")

    async def two_pings():
        return [await engine._ping_once(target) for _ in range(2)]

    online, lost = asyncio.run(two_pings())
    # Online, then a ping lost: a timeout, not "Ping blocked".
    assert online.succeeded and lost.status is PingStatus.TIMEOUT and lost.tcp_port is None
    assert tried == []


def test_a_host_seen_answering_ping_before_is_not_probed(monkeypatch):
    async def first_open_port(ip, ports, timeout_ms):
        raise AssertionError("not probed")

    monkeypatch.setattr(engine_module, "first_open_port", first_open_port)
    engine = _engine(monkeypatch, (3389,))
    entry = HostEntry(key=1, host="192.0.2.1", ip_address="192.0.2.1")
    entry.apply(PingResult(PingStatus.SUCCEEDED, 1.0, "192.0.2.1"))
    assert asyncio.run(engine._ping_once(entry.to_target())).tcp_port is None


def test_ports_answered_on_the_way_are_ignored(monkeypatch):
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen()
    port = listener.getsockname()[1]
    try:
        # A firewall answering this port for every address (as SIP helpers
        # do for 5060) makes it useless as a sign the host is up.
        engine = _engine(monkeypatch, (port,), intercepted=frozenset({port}))
        target = PingTarget(key=1, host="127.0.0.1", resolved_ip="127.0.0.1")
        assert asyncio.run(engine._ping_once(target)).tcp_port is None
    finally:
        listener.close()


def test_find_intercepted(monkeypatch):
    async def tcp_ping(ip, port, timeout_ms):
        assert ip == engine_module.CANARY_IP
        return PingResult(PingStatus.SUCCEEDED if port == 5060 else PingStatus.TIMEOUT)

    monkeypatch.setattr(engine_module, "TCP_FALLBACK_PORTS", (443, 5060))
    monkeypatch.setattr(engine_module, "tcp_ping", tcp_ping)
    assert asyncio.run(PingEngine._find_intercepted()) == {5060}


def test_host_entry_status():
    entry = HostEntry(key=1, host="192.0.2.1")
    entry.apply(PingResult(PingStatus.TIMEOUT, tcp_port=443))
    assert entry.ping_blocked and entry.is_up and entry.failed_count == 1
    assert status_badge(entry)[0] == "Ping blocked"
    entry.apply(PingResult(PingStatus.TIMEOUT))
    assert not entry.ping_blocked and not entry.is_up
    assert status_badge(entry)[0] == "Offline"
    entry.apply(PingResult(PingStatus.SUCCEEDED, 1.0, "192.0.2.1"))
    assert entry.is_up and not entry.ping_blocked
    assert status_badge(entry)[0] == "Online"
