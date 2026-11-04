"""Net Path: probe packets, sweeps, the path graph and its window."""

import socket
import struct

from NetInfoView.ping import netpath
from NetInfoView.ping.netpath import DESTINATION, SOURCE, Answer, Sweep


def _checksum(packet):
    return struct.unpack_from("!H", packet, 2)[0]


def test_a_flow_keeps_one_checksum_whatever_the_sequence():
    for flow in range(netpath.FLOWS):
        ident = netpath.flow_ident(flow)
        sums = {_checksum(netpath.build_probe(ident, 0xA000 + ttl, flow)) for ttl in range(1, 31)}
        assert len(sums) == 1
        # ...and every probe is a valid ICMP packet.
        assert netpath.ones_sum(netpath.build_probe(ident, 0xA005, flow)) == 0xFFFF
    firsts = {_checksum(netpath.build_probe(netpath.flow_ident(f), 0xA001, f)) for f in range(8)}
    assert len(firsts) == 8


def _ip(payload, source="10.0.0.1"):
    header = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(payload), 0, 0, 64, 1, 0,
                         socket.inet_aton(source), socket.inet_aton("192.168.1.2"))
    return header + payload


def test_parse_reads_the_quoted_probe_of_an_error():
    probe = netpath.build_probe(0x1234, 0xA003, 2)
    exceeded = _ip(struct.pack("!BBHI", 11, 0, 0, 0) + _ip(probe)[:28])
    assert netpath.parse(exceeded) == (11, 0, 0x1234, 0xA003)
    reply = _ip(struct.pack("!BBHHH", 0, 0, 0, 0x1234, 0xA009))
    assert netpath.parse(reply) == (0, 0, 0x1234, 0xA009)
    assert netpath.parse(b"\x45" + b"\x00" * 5) is None


# Two routes that split after hop 1 and join again at hop 3; hop 2 of the
# odd flows never answers on the first try.
def fake_probe(asked):
    def probe(ip, ttl, flows):
        asked.append((ttl, tuple(flows)))
        answers = {}
        for flow in flows:
            if ttl == 1:
                answers[flow] = Answer("10.0.0.1", 1.0)
            elif ttl == 2:
                if flow % 2 and len([a for a in asked if a[0] == 2]) == 1:
                    continue  # lost once, answered on the retry
                answers[flow] = Answer("10.0.1.1" if flow % 2 else "10.0.2.1", 5.0 + flow % 2)
            elif ttl == 3:
                answers[flow] = Answer("10.0.3.1", 9.0)
            else:
                answers[flow] = Answer(ip, 12.0, reached=True)
        return answers
    return probe


def test_sweep_follows_every_flow_until_it_arrives():
    asked = []
    result = netpath.sweep("8.8.8.8", fake_probe(asked), flows=4)
    assert result.reached_flows() == 4 and netpath.health(result) == "ok"
    assert [a.address for a in result.routes[1]] == ["10.0.0.1", "10.0.1.1", "10.0.3.1", "8.8.8.8"]
    # The lost probes at hop 2 were asked again, only for those flows.
    assert (2, (1, 3)) in asked
    assert max(ttl for ttl, _ in asked) == 4


def test_graph_merges_shared_hops_and_keeps_the_branches():
    result = netpath.sweep("8.8.8.8", fake_probe([]), flows=4)
    graph = netpath.build_graph([result], "8.8.8.8")
    assert set(graph.nodes) == {SOURCE, DESTINATION, "10.0.0.1", "10.0.1.1", "10.0.2.1", "10.0.3.1"}
    assert len(graph.edges[("10.0.0.1", "10.0.1.1")].flows) == 2
    assert len(graph.edges[(SOURCE, "10.0.0.1")].flows) == 4
    assert graph.nodes[DESTINATION].ttl == 4 and graph.reached == 4
    assert graph.edge_latency(graph.edges[(SOURCE, "10.0.0.1")]) == 1.0
    assert graph.edge_latency(graph.edges[("10.0.3.1", DESTINATION)]) == 3.0


def test_silent_hops_and_an_unreached_host():
    s = Sweep(0, 2, [
        [Answer("10.0.0.1", 1), None, Answer("10.0.3.1", 9)],
        [Answer("10.0.0.1", 1), None, Answer("10.0.3.1", 9)],
    ])
    graph = netpath.build_graph([s], "8.8.8.8")
    silent = [n for n in graph.nodes.values() if n.silent]
    assert len(silent) == 1 and silent[0].ttl == 2
    assert graph.edges[("10.0.3.1", DESTINATION)].unknown
    assert graph.reached == 0 and netpath.health(s) == "down"


def test_sweep_gives_up_after_a_run_of_silence():
    result = netpath.sweep("8.8.8.8", lambda ip, ttl, flows: {}, flows=2)
    assert result.routes == [[], []]


def test_lost_flows_are_pinned_on_the_hop_where_they_stop():
    # Flows 0-2 reach the host; flow 3 is last seen at 10.0.1.1.
    s = Sweep(0, 4, [
        [Answer("10.0.0.1", 1), Answer("10.0.2.1", 5), Answer("8.8.8.8", 9, reached=True)],
        [Answer("10.0.0.1", 1), Answer("10.0.1.1", 5), Answer("8.8.8.8", 9, reached=True)],
        [Answer("10.0.0.1", 1), Answer("10.0.1.1", 5), Answer("8.8.8.8", 9, reached=True)],
        [Answer("10.0.0.1", 1), Answer("10.0.1.1", 5)],
    ])
    graph = netpath.build_graph([s], "8.8.8.8")
    assert graph.nodes["10.0.0.1"].loss() == 0
    assert graph.nodes["10.0.1.1"].dropped == {3}
    assert netpath.loss_level(graph.nodes["10.0.1.1"]) == (
        netpath.WARN, "1 of 3 flows lost after this hop")


def test_latency_levels_and_usual():
    assert netpath.usual([]) is None
    assert netpath.usual([3, 1, 2]) == 2 and netpath.usual([1, 2, 3, 10]) == 2.5
    assert netpath.latency_level(None, 5) == (netpath.OK, "")
    assert netpath.latency_level(40, 5) == (netpath.OK, "")
    assert netpath.latency_level(60, 5)[0] == netpath.WARN
    level, reason = netpath.latency_level(170, 5)
    assert level == netpath.CRIT and reason == "Latency 170 ms, +165 ms over its usual 5 ms"
    assert netpath.worst(netpath.OK, netpath.CRIT, netpath.WARN) == netpath.CRIT


from test_main_window import _entries_with_statuses, qapp, window  # noqa: E402,F401


def test_window_shows_the_graph_history_and_details(qapp, monkeypatch):
    from PyQt6.QtWidgets import QApplication
    from NetInfoView.ping import hostname, whois
    from NetInfoView.ui import netpath_window

    # No real lookups: hop 10.0.2.1 has a name, the rest have none.
    monkeypatch.setattr(hostname, "resolve", lambda ip: "core.example" if ip == "10.0.2.1" else "")
    for name in ("netname", "reserved_name", "country"):
        monkeypatch.setattr(whois, name, lambda ip: "")
    window = netpath_window.NetPathWindow("dns.google", "8.8.8.8", probe=fake_probe([]),
                                          source=("OFFICE-PC", "192.168.1.2"), live=False)
    assert window._thread.wait(5000)
    QApplication.processEvents()
    assert window._thread is None and window.button.isEnabled()
    assert len(window.sweeps) == 1
    assert window.items["10.0.2.1"].title == "core.example"
    assert window.names["10.0.0.1"] == ""  # looked up, nothing found
    assert window.history.healths == ["ok"]
    assert set(window.items) == set(window.graph.nodes)
    assert window.details_title.text() == "Path overview"
    window.items["10.0.0.1"].setSelected(True)
    texts = [window.details_grid.itemAt(i).widget().text()
             for i in range(window.details_grid.count())
             if hasattr(window.details_grid.itemAt(i).widget(), "text")]
    assert "Splits to" in texts
    window._on_name("10.0.0.1", "gw.example")
    assert window.items["10.0.0.1"].title == "gw.example"
    window.add_sweep(Sweep(1, 4, [[Answer("10.0.0.1", 1)]] * 4))
    assert window.history.healths == ["ok", "down"] and window.shown == 1
    window.show_sweep(0)
    assert window.shown == 0 and not window._follow
    window.close()


def test_net_path_opens_from_the_main_window(window, monkeypatch):
    from NetInfoView.ui import netpath_window

    monkeypatch.setattr(netpath_window.NetPathWindow, "start", lambda self: None)
    assert window.net_path() is None  # nothing selected
    entries = _entries_with_statuses(window, "8.8.8.8")
    entries[0].ip_address = "8.8.8.8"  # as once it has been resolved
    window._table.selectRow(0)
    opened = window.net_path()
    assert isinstance(opened, netpath_window.NetPathWindow)
    assert opened._ip == "8.8.8.8"
    assert window._dashboard.nav_net_path.text() == "Net Path"
    opened.close()


def _route(hop2_ms, reach=True):
    hops = [Answer("10.0.0.1", 1), Answer("10.0.1.1", hop2_ms)]
    return hops + ([Answer("8.8.8.8", hop2_ms + 2, reached=True)] if reach else [])


def test_hops_and_links_are_colored_against_their_usual(qapp, monkeypatch):
    from NetInfoView.ui import netpath_window as nw

    monkeypatch.setattr(nw.NetPathWindow, "start", lambda self: None)
    window = nw.NetPathWindow("dns.google", "8.8.8.8")
    for _ in range(3):  # three normal traces: hop 2 answers in 5 ms
        window.add_sweep(Sweep(0, 2, [_route(5), _route(5)]))
    window.add_sweep(Sweep(1, 2, [_route(125), _route(125)]))  # hop 2 now +120 ms
    graph = window.graph
    level, reasons = window.node_condition(graph, "10.0.1.1")
    # Judged on the link into the hop (125 - 1 ms), not its round trip.
    assert level == "warn" and reasons == ["Link latency 124 ms, +120 ms over its usual 4 ms"]
    # The host beyond answers later too, but its own link is as usual.
    assert window.node_condition(graph, DESTINATION) == ("ok", [])
    assert window.edge_condition(graph, graph.edges[("10.0.0.1", "10.0.1.1")])[0] == "warn"
    assert window.node_condition(graph, "10.0.0.1") == ("ok", [])
    assert window.items["10.0.1.1"].ring.name() == nw.AMBER
    assert "Hop 2 (10.0.1.1): Link latency 124 ms" in window.details_grid.itemAtPosition(
        window.details_grid.rowCount() - 1, 1).widget().text()

    # The host stops answering: only the hop where the routes stop turns red.
    window.add_sweep(Sweep(2, 2, [_route(5, reach=False), _route(5, reach=False)]))
    graph = window.graph
    assert window.node_condition(graph, "10.0.1.1")[0] == "crit"
    assert window.node_condition(graph, "10.0.0.1")[0] == "ok"
    assert window.node_condition(graph, DESTINATION) == ("crit", ["2 of 2 flows didn't reach it"])
    assert window.items[DESTINATION].ring.name() == nw.RED

    # Stepping back in the history shows that trace's colors.
    window.show_sweep(0)
    assert window.items["10.0.1.1"].ring.name() == nw.GREEN
    window.close()
