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
    # 1 of 3 is past SolarWinds' 10% critical.
    assert netpath.loss_level(graph.nodes["10.0.1.1"]) == (
        netpath.CRIT, "1 of 3 flows lost after this hop")


def test_solarwinds_netpath_default_thresholds():
    # Latency 25 ms warning, 100 ms critical; packet loss 5% / 10%.
    assert netpath.latency_level(None) == (netpath.OK, "")
    assert netpath.latency_level(24.9) == (netpath.OK, "")
    assert netpath.latency_level(25) == (netpath.WARN, "Latency 25 ms (warning from 25 ms)")
    assert netpath.latency_level(99)[0] == netpath.WARN
    assert netpath.latency_level(100, "Link latency") == (
        netpath.CRIT, "Link latency 100 ms (critical from 100 ms)")
    assert [netpath.share_level(x) for x in (0, 0.049, 0.05, 0.099, 0.10, 1)] == [
        "ok", "ok", "warn", "warn", "crit", "crit"]
    assert netpath.worst(netpath.OK, netpath.CRIT, netpath.WARN) == netpath.CRIT
    assert netpath.usual([]) is None
    assert netpath.usual([3, 1, 2]) == 2 and netpath.usual([1, 2, 3, 10]) == 2.5


from test_main_window import _entries_with_statuses, qapp, window  # noqa: E402,F401


def test_window_shows_the_graph_history_and_details(qapp, monkeypatch):
    from PyQt6.QtWidgets import QApplication
    from NetInfoView.ping import hostname, whois
    from NetInfoView.ui import netpath_window

    # No real lookups: hop 10.0.2.1 has a name, the rest have none.
    monkeypatch.setattr(hostname, "resolve", lambda ip: "core.example" if ip == "10.0.2.1" else "")
    for name in ("netname", "reserved_name", "country", "as_org"):
        monkeypatch.setattr(whois, name, lambda ip: "")
    window = netpath_window.NetPathWindow("dns.google", "8.8.8.8", probe=fake_probe([]),
                                          source=("OFFICE-PC", "192.168.1.2"), live=False)
    assert window._thread.wait(5000)
    QApplication.processEvents()
    assert window._thread is None and window.button.isEnabled()
    assert len(window.sweeps) == 1
    assert window.items["10.0.2.1"].title == "core.example"
    assert window.names["10.0.0.1"] == ""  # looked up, nothing found
    assert window.history.healths == ["ok"] and window.health.text() == "●  Up"
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
    assert window.history.healths == ["ok", "crit"] and window.shown == 1
    assert window.health.text() == "●  Critical"
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


def test_hops_and_links_are_colored_by_the_netpath_thresholds(qapp, monkeypatch):
    from NetInfoView.ui import netpath_window as nw

    monkeypatch.setattr(nw.NetPathWindow, "start", lambda self: None)
    window = nw.NetPathWindow("dns.google", "8.8.8.8")
    window.add_sweep(Sweep(0, 2, [_route(5), _route(5)]))  # hop 2 answers in 5 ms
    assert window.node_condition(window.graph, "10.0.1.1") == ("ok", [])
    window.add_sweep(Sweep(1, 2, [_route(41), _route(41)]))  # its link now takes 40 ms
    graph = window.graph
    level, reasons = window.node_condition(graph, "10.0.1.1")
    # Judged on the link into the hop (41 - 1 ms), not its round trip.
    assert level == "warn" and reasons == ["Link latency 40 ms (warning from 25 ms)"]
    # The host beyond answers later too, but its own link is quick.
    assert window.node_condition(graph, DESTINATION) == ("ok", [])
    assert window.edge_condition(graph, graph.edges[("10.0.0.1", "10.0.1.1")])[0] == "warn"
    assert window.node_condition(graph, "10.0.0.1") == ("ok", [])
    assert window.items["10.0.1.1"].ring.name() == nw.AMBER
    # The history block and the status pill take the trace's worst hop.
    assert window.history.healths == ["ok", "warn"] and window.health.text() == "●  Warning"
    assert "Hop 2 (10.0.1.1): Link latency 40 ms" in window.details_grid.itemAtPosition(
        window.details_grid.rowCount() - 1, 1).widget().text()
    window.add_sweep(Sweep(1, 2, [_route(121), _route(121)]))  # 120 ms: critical
    assert window.items["10.0.1.1"].ring.name() == nw.RED

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


def test_routes_of_other_traces_are_drawn_thin_under_the_one_shown(qapp, monkeypatch):
    from NetInfoView.ui import netpath_window as nw

    monkeypatch.setattr(nw.NetPathWindow, "start", lambda self: None)
    window = nw.NetPathWindow("dns.google", "8.8.8.8")
    via_a = [Answer("10.0.0.1", 1), Answer("10.0.1.1", 5), Answer("8.8.8.8", 9, reached=True)]
    via_b = [Answer("10.0.0.1", 1), Answer("10.0.2.1", 5), Answer("8.8.8.8", 9, reached=True)]
    window.add_sweep(Sweep(0, 2, [via_a, via_a]))
    window.add_sweep(Sweep(1, 2, [via_b, via_b]))  # shown: the latest

    # By default only the trace on screen is drawn, as in SolarWinds.
    assert "10.0.1.1" not in window.items and "10.0.2.1" in window.items
    window.past_box.setChecked(True)
    # Both routes are on screen; only route B is the trace's own.
    assert {"10.0.1.1", "10.0.2.1"} <= set(window.items)
    old = window.edge_items[("10.0.0.1", "10.0.1.1")]
    now = window.edge_items[("10.0.0.1", "10.0.2.1")]
    assert old[1] is False and now[1] is True
    assert old[0].pen().widthF() < now[0].pen().widthF()
    assert window.items["10.0.1.1"].opacity() < 1 and window.items["10.0.2.1"].opacity() == 1
    # Hops keep their place from trace to trace.
    place = window.items["10.0.1.1"].pos()
    window.items["10.0.1.1"].setSelected(True)
    rows = [window.details_grid.itemAtPosition(r, 1).widget().text()
            for r in range(window.details_grid.rowCount())
            if window.details_grid.itemAtPosition(r, 1) is not None]
    assert "1 of 2 traces" in rows

    # Back to the first trace: the roles swap.
    window.show_sweep(0)
    assert window.edge_items[("10.0.0.1", "10.0.1.1")][1] is True
    assert window.edge_items[("10.0.0.1", "10.0.2.1")][1] is False
    assert window.items["10.0.2.1"].opacity() < 1 and window.items["10.0.1.1"].pos() == place
    window.close()


# A path that ends in a provider's mesh: hop 1 is ours, hops 2-3 are four
# GOOGLE routers (and one that didn't answer), then the host.
def _into_google():
    a = [Answer("10.0.0.1", 1), Answer("142.0.0.1", 5), Answer("142.0.1.1", 6),
         Answer("8.8.8.8", 9, reached=True)]
    b = [Answer("10.0.0.1", 1), Answer("142.0.0.2", 5), Answer("142.0.1.2", 6),
         Answer("8.8.8.8", 9, reached=True)]
    c = [Answer("10.0.0.1", 1), Answer("142.0.0.2", 5), None, Answer("8.8.8.8", 9, reached=True)]
    return Sweep(0, 3, [a, b, c])


GOOGLE = {f"142.0.{x}.{y}": "GOOGLE" for x in (0, 1) for y in (1, 2)}


def test_providers_are_named_by_their_as():
    from NetInfoView.ping import whois

    assert whois.org_from_as_name("GOOGLE - Google LLC, US") == "Google LLC"
    assert whois.org_from_as_name(
        "TTBP-AS-AP - Triple T Broadband Public Company Limited, TH") == (
        "Triple T Broadband Public Company Limited")
    assert whois.org_from_as_name("EXAMPLE-AS") == "EXAMPLE-AS"
    assert whois.org_from_as_name("") == ""
    assert whois.as_org("10.0.0.1") == ""  # private: nothing to ask


def test_a_providers_hops_become_one_box():
    graph = netpath.build_graph([_into_google()], "8.8.8.8")
    group_of = netpath.provider_groups(graph, GOOGLE)
    boxed = {key for key, group in group_of.items() if group == "group:GOOGLE:2"}
    silent = [key for key, node in graph.nodes.items() if node.silent]
    assert boxed == set(GOOGLE) | set(silent)  # the silent hop inside joins it
    assert "10.0.0.1" not in group_of  # private: never boxed
    # Too few routers of one provider stay as they are.
    assert netpath.provider_groups(graph, {"142.0.0.1": "TINY", "142.0.0.2": "TINY"}) == {}

    folded = netpath.collapse(graph, group_of)
    box = folded.nodes["group:GOOGLE:2"]
    assert box.label == "GOOGLE" and box.ttl == 2 and len(box.flows) == 3
    assert sorted(box.rtts) == [5, 5, 5]  # the hops where routes enter it
    assert set(folded.edges) == {(SOURCE, "10.0.0.1"), ("10.0.0.1", "group:GOOGLE:2"),
                                 ("group:GOOGLE:2", DESTINATION)}
    assert not folded.nodes["group:GOOGLE:2"].silent


def test_a_provider_far_apart_is_two_boxes():
    route = [Answer(f"142.0.0.{ttl}", ttl) for ttl in range(1, 4)]
    route += [Answer(f"10.9.0.{ttl}", ttl) for ttl in range(4, 8)]
    route += [Answer(f"142.0.0.{ttl}", ttl) for ttl in range(8, 11)]
    graph = netpath.build_graph([Sweep(0, 1, [route])], "8.8.8.8")
    orgs = {f"142.0.0.{ttl}": "SAMENET" for ttl in (1, 2, 3, 8, 9, 10)}
    assert set(netpath.provider_groups(graph, orgs).values()) == {
        "group:SAMENET:1", "group:SAMENET:8"}


def test_rarely_taken_links_are_left_out_but_no_hop_is_cut_off():
    # Over 20 probes, 19 go 10.0.0.1 -> .2 and one goes 10.0.0.1 -> .3 -> .4.
    common = [Answer("10.0.0.1", 1), Answer("10.0.0.2", 2), Answer("8.8.8.8", 3, reached=True)]
    rare = [Answer("10.0.0.1", 1), Answer("10.0.0.3", 2), Answer("8.8.8.8", 3, reached=True)]
    history = netpath.build_graph([Sweep(0, 20, [common] * 19 + [rare])], "8.8.8.8")
    keep = netpath.likely_edges(history, history)
    assert ("10.0.0.1", "10.0.0.2") in keep
    # 1 in 20 is under 10%, but it's 10.0.0.3's only way in or out: kept.
    assert ("10.0.0.1", "10.0.0.3") in keep and ("10.0.0.3", DESTINATION) in keep
    # A second, rarer way into the host is dropped.
    side = [Answer("10.0.0.1", 1), Answer("10.0.0.2", 2), Answer("10.0.0.3", 3),
            Answer("8.8.8.8", 4, reached=True)]
    history = netpath.build_graph([Sweep(0, 21, [common] * 19 + [rare, side])], "8.8.8.8")
    assert ("10.0.0.2", "10.0.0.3") not in netpath.likely_edges(history, history)


def test_the_window_boxes_providers_and_opens_a_box_on_double_click(qapp, monkeypatch):
    from NetInfoView.ui import netpath_window as nw

    monkeypatch.setattr(nw.NetPathWindow, "start", lambda self: None)
    window = nw.NetPathWindow("dns.google", "8.8.8.8")
    window.add_sweep(_into_google())
    assert "group:GOOGLE:2" not in window.items  # no org names known yet
    for address, org in GOOGLE.items():
        window._on_org(address, org)
    window.refresh_view()  # (the window does this itself once names settle)
    box = window.items["group:GOOGLE:2"]
    assert box.kind == "group" and box.title == "GOOGLE" and box.text == "4"
    assert not set(GOOGLE) & set(window.items)
    box.setSelected(True)
    assert window.details_title.text() == "GOOGLE"

    window._activate("group:GOOGLE:2")  # double-click: open the box
    assert "group:GOOGLE:2" not in window.items and set(GOOGLE) <= set(window.items)
    window._activate("142.0.1.1")  # double-click a hop in it: fold again
    assert "group:GOOGLE:2" in window.items

    window.group_box.setChecked(False)
    assert set(GOOGLE) <= set(window.items)
    window.close()


def test_double_clicking_a_box_on_screen_opens_it_without_crashing(qapp, monkeypatch):
    """A real double-click, through the view: opening the box redraws the
    scene and deletes the box clicked, which used to abort the program."""
    from PyQt6.QtCore import Qt
    from PyQt6.QtTest import QTest
    from PyQt6.QtWidgets import QApplication
    from NetInfoView.ui import netpath_window as nw

    monkeypatch.setattr(nw.NetPathWindow, "start", lambda self: None)
    window = nw.NetPathWindow("dns.google", "8.8.8.8")
    window.resize(1000, 600)
    window.show()
    window.add_sweep(_into_google())
    for address, org in GOOGLE.items():
        window._on_org(address, org)
    window.refresh_view()
    QApplication.processEvents()

    def double_click(key):
        item = window.items[key]
        spot = window.view.mapFromScene(item.scenePos())
        QTest.mouseDClick(window.view.viewport(), Qt.MouseButton.LeftButton, pos=spot)
        for _ in range(3):
            QApplication.processEvents()

    double_click("group:GOOGLE:2")
    assert "group:GOOGLE:2" not in window.items and set(GOOGLE) <= set(window.items)
    double_click("142.0.0.1")  # a hop of the open box: folds it again
    assert "group:GOOGLE:2" in window.items
    window.close()


# Home router, then a carrier numbering its routers privately around one
# public hop of its own (180.0.0.1), then Google.
def _through_a_carrier():
    hops = ["192.168.1.1", "10.1.0.1", "10.2.0.1", "180.0.0.1", "10.3.0.1", "142.0.0.1"]
    route = [Answer(address, ttl) for ttl, address in enumerate(hops, start=1)]
    return Sweep(0, 1, [route + [Answer("8.8.8.8", 9, reached=True)]])


def test_private_hops_count_with_the_provider_around_them():
    graph = netpath.build_graph([_through_a_carrier()], "8.8.8.8")
    orgs = {"180.0.0.1": "Carrier", "142.0.0.1": "Google LLC"}
    found = netpath.private_hop_orgs(graph, orgs, local="192.168.1.105")
    # Before the carrier's first public hop: the one after; after it: the one before.
    assert found == {"10.1.0.1": "Carrier", "10.2.0.1": "Carrier", "10.3.0.1": "Carrier"}
    # The home router (hop 1, this computer's network) is left alone.
    assert "192.168.1.1" not in found
    groups = netpath.provider_groups(graph, {**orgs, **found})
    assert {key for key, group in groups.items() if "Carrier" in group} == {
        "10.1.0.1", "10.2.0.1", "180.0.0.1", "10.3.0.1"}


def test_the_main_route_follows_the_most_taken_links():
    # Three probes go via 10.0.1.1, one via 10.0.2.1.
    via = {n: [Answer("10.0.0.1", 1), Answer(f"10.0.{n}.1", 2), Answer("8.8.8.8", 3, reached=True)]
           for n in (1, 2)}
    graph = netpath.build_graph([Sweep(0, 4, [via[1], via[1], via[1], via[2]])], "8.8.8.8")
    assert netpath.main_route(graph) == [SOURCE, "10.0.0.1", "10.0.1.1", DESTINATION]
    # Only the links given count: without 10.0.1.1's, the other way.
    usable = set(graph.edges) - {("10.0.0.1", "10.0.1.1")}
    assert netpath.main_route(graph, usable)[2] == "10.0.2.1"


def test_the_main_route_is_bold_and_the_others_faint(qapp, monkeypatch):
    from NetInfoView.ui import netpath_window as nw

    monkeypatch.setattr(nw.NetPathWindow, "start", lambda self: None)
    window = nw.NetPathWindow("dns.google", "8.8.8.8")
    via = {n: [Answer("10.0.0.1", 1), Answer(f"10.0.{n}.1", 2), Answer("8.8.8.8", 3, reached=True)]
           for n in (1, 2)}
    window.add_sweep(Sweep(0, 4, [via[1], via[1], via[1], via[2]]))
    main, other = window.edge_items[("10.0.0.1", "10.0.1.1")][0], window.edge_items[("10.0.0.1", "10.0.2.1")][0]
    assert main.pen().widthF() > other.pen().widthF() and other.opacity() < main.opacity()
    texts = [window.details_grid.itemAtPosition(r, 1).widget().text()
             for r in range(window.details_grid.rowCount())
             if window.details_grid.itemAtPosition(r, 1) is not None]
    assert any(t.startswith("3 of 4 probe flows took all of it") and "2: 10.0.1.1" in t
               for t in texts)
    window.close()
