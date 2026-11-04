"""Net Path's TCP probes: a SYN to the service's port with a short TTL."""

import socket
import struct
import sys

import pytest

from NetInfoView.ping import netpath_tcp
from NetInfoView.ping.netpath_tcp import TcpProber, TcpUnavailable, quoted_tcp


def _ip(payload, source, protocol, destination="192.168.1.2"):
    return struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(payload), 0, 0, 57, protocol, 0,
                       socket.inet_aton(source), socket.inet_aton(destination)) + payload


def _exceeded(router, source_port, destination_port=443, kind=11):
    syn = _ip(struct.pack("!HHI", source_port, destination_port, 0), "192.168.1.2", 6, "8.8.8.8")
    return _ip(struct.pack("!BBHI", kind, 0, 0, 0) + syn, router, 1)


def test_quoted_tcp_reads_the_ports_of_the_probe_an_error_is_about():
    assert quoted_tcp(_exceeded("10.0.0.1", 41000)) == (11, 0, 41000, 443)
    assert quoted_tcp(_exceeded("10.0.0.1", 41000, kind=3)) == (3, 0, 41000, 443)
    echo_reply = _ip(struct.pack("!BBHHH", 0, 0, 0, 1, 1), "8.8.8.8", 1)
    assert quoted_tcp(echo_reply) is None
    about_udp = _ip(struct.pack("!BBHI", 11, 0, 0, 0)
                    + _ip(struct.pack("!HH", 1, 2), "192.168.1.2", 17), "10.0.0.1", 1)
    assert quoted_tcp(about_udp) is None
    assert quoted_tcp(b"\x45\x00") is None


class FakeListener:
    """Hands out ICMP errors for the probes sent, as a router would."""

    def __init__(self, router):
        self.router, self.closed = router, False
        self.ports = []  # the source ports the probes went from

    def packets(self, wait):
        return [(_exceeded(self.router, port), self.router) for port in self.ports]

    def close(self):
        self.closed = True


def test_a_router_on_the_way_answers_for_every_flow(monkeypatch):
    prober = TcpProber(443, wait_ms=500)
    listener = FakeListener("10.0.0.1")
    prober._listener = listener
    # The SYNs themselves go nowhere: connect() is stubbed out, and each
    # socket opened tells the fake router which port it came from (a port
    # another program holds is skipped, so they needn't be consecutive).
    monkeypatch.setattr(socket.socket, "connect", lambda self, address: None)
    real_open = TcpProber._open

    def opened(ttl, port):
        sock = real_open(ttl, port)
        if sock is not None:
            listener.ports.append(port)
        return sock

    monkeypatch.setattr(TcpProber, "_open", staticmethod(opened))
    answers = prober("8.8.8.8", 3, [0, 1, 2])
    assert sorted(answers) == [0, 1, 2]
    assert {a.address for a in answers.values()} == {"10.0.0.1"}
    assert not any(a.reached for a in answers.values())
    prober.close()
    assert listener.closed


class Silent:
    def packets(self, wait):
        return []

    def close(self):
        pass


def test_the_host_answering_syn_ack_or_rst_is_reached():
    server = socket.socket()
    server.bind(("127.0.0.1", 0))
    server.listen(8)
    open_port = server.getsockname()[1]
    prober = TcpProber(open_port, wait_ms=3000, listener=Silent())
    answers = prober("127.0.0.1", 64, [0, 1])
    assert sorted(answers) == [0, 1] and all(a.reached for a in answers.values())

    closed = socket.socket()
    closed.bind(("127.0.0.1", 0))
    closed_port = closed.getsockname()[1]
    closed.close()  # nothing listens: the host answers RST
    # Windows retries a refused SYN for about two seconds before saying so.
    prober = TcpProber(closed_port, wait_ms=3000, listener=Silent())
    answers = prober("127.0.0.1", 64, [0])
    assert answers[0].reached and answers[0].address == "127.0.0.1"
    server.close()


def test_every_probe_gets_a_port_of_its_own():
    prober = TcpProber()
    ports = [prober.next_port() for _ in range(5)]
    assert len(set(ports)) == 5
    assert all(netpath_tcp.PORT_RANGE[0] <= p < netpath_tcp.PORT_RANGE[1] for p in ports)
    prober._next = netpath_tcp.PORT_RANGE[1] - 1
    assert prober.next_port() == netpath_tcp.PORT_RANGE[1] - 1
    assert prober.next_port() == netpath_tcp.PORT_RANGE[0]  # wraps around


@pytest.mark.skipif(sys.platform == "win32",
                    reason="on Windows it depends on admin rights or Npcap")
def test_tcp_probes_work_here():
    assert netpath_tcp.unavailable("127.0.0.1") == ""


from test_main_window import qapp  # noqa: E402,F401


def test_the_window_falls_back_to_icmp_when_tcp_cannot_be_used(qapp, monkeypatch):
    from PyQt6.QtWidgets import QApplication
    from NetInfoView.ui import netpath_window as nw

    def no_tcp(self, ip, ttl, flows):
        raise TcpUnavailable("TCP probes need NetInfoView run as administrator, or Npcap")

    monkeypatch.setattr(TcpProber, "__call__", no_tcp)
    # The ICMP trace it falls back to: nothing answers, so it ends quickly.
    from NetInfoView.ping import netpath
    monkeypatch.setattr(netpath, "default_probe", lambda: lambda ip, ttl, flows: {})
    started = []
    real_start = nw.NetPathWindow.start
    monkeypatch.setattr(nw.NetPathWindow, "start",
                        lambda self: started.append(self.probe_port()) or real_start(self))
    window = nw.NetPathWindow("dns.google", "8.8.8.8", live=False)
    assert window.probe_text() == "TCP SYN to port 443"
    assert "TCP SYN to port 443" in window.route_text.text()
    thread = window._thread
    assert thread.wait(5000)
    QApplication.processEvents()
    # Fell back: ICMP chosen, the reason shown, and a new trace started.
    assert window.mode.currentText() == "ICMP" and not window.port.isVisibleTo(window)
    assert "administrator" in window.status.text()
    assert started[:2] == [443, None]
    assert window._thread.wait(5000)
    QApplication.processEvents()
    window.close()


def test_changing_the_probe_starts_over(qapp, monkeypatch):
    from NetInfoView.ping.netpath import Answer, Sweep
    from NetInfoView.ui import netpath_window as nw

    started = []
    monkeypatch.setattr(nw.NetPathWindow, "start", lambda self: started.append(self.probe_port()))
    window = nw.NetPathWindow("dns.google", "8.8.8.8")
    window.add_sweep(Sweep(0, 1, [[Answer("8.8.8.8", 5, reached=True)]]))
    assert len(window.sweeps) == 1
    window.mode.setCurrentIndex(1)  # ICMP
    assert window.sweeps == [] and window.history.healths == [] and started == [443, None]
    assert "ICMP echo" in window.route_text.text()
    window.mode.setCurrentIndex(0)
    window.port.setValue(22)
    window.port.editingFinished.emit()
    assert started[-1] == 22 and "port 22" in window.route_text.text()
    window.close()
