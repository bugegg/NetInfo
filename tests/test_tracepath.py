"""Tests for Trace Path MTU (ping/tracepath.py and its window)."""

import pytest
from PyQt6.QtWidgets import QApplication

from NetInfoView.ping import tracepath
from NetInfoView.ping.tracepath import (
    EXCEEDED, FRAG, REACHED, TIMEOUT, UNREACHABLE, Hop, Reply,
)


@pytest.fixture(scope="session")
def qapp():
    yield QApplication.instance() or QApplication([])


def test_parse_ping_output():
    assert tracepath.parse(
        "PING 8.8.8.8 (8.8.8.8): 1472 data bytes\n"
        "556 bytes from 192.168.1.1: Time to live exceeded\n"
    ) == Reply(EXCEEDED, "192.168.1.1")
    assert tracepath.parse(
        "556 bytes from 192.168.1.1: frag needed and DF set (MTU 1492)\n"
    ) == Reply(FRAG, "192.168.1.1", 1492)
    assert tracepath.parse(
        "1480 bytes from 8.8.8.8: icmp_seq=0 ttl=117 time=20.1 ms\n"
    ) == Reply(REACHED, "8.8.8.8")
    assert tracepath.parse(
        "92 bytes from 10.0.0.1: Destination Host Unreachable\n"
    ) == Reply(UNREACHABLE, "10.0.0.1", text="Destination Host Unreachable")
    assert tracepath.parse("ping: sendto: Message too long\n").kind == TIMEOUT
    assert tracepath.parse("Request timeout for icmp_seq 0\n").kind == TIMEOUT


def _network(hops, target="10.9.9.9"):
    """A fake probe over a path of routers. `hops` is a list of
    (address, MTU of the link into it, whether it reports frag-needed,
    whether it answers at all); the last one is the target."""
    calls = []

    def probe(ip, ttl, payload):
        calls.append((ttl, payload))
        size = payload + tracepath.HEADERS
        for index, (address, link_mtu, reports, answers) in enumerate(hops[:ttl]):
            if size > link_mtu:
                if index and hops[index - 1][2]:
                    return Reply(FRAG, hops[index - 1][0], link_mtu)
                return Reply(TIMEOUT)
        address, _, _, answers = hops[min(ttl, len(hops)) - 1]
        if not answers:
            return Reply(TIMEOUT)
        return Reply(REACHED if ttl >= len(hops) else EXCEEDED, address)

    return probe, calls


def _trace(probe, **kwargs):
    hops = []
    kwargs.setdefault("link_mtu", lambda ip: None)
    tracepath.trace("10.9.9.9", hops.append, probe, **kwargs)
    return hops


def test_reported_drop_is_pinned_on_the_router_that_reports_it():
    probe, calls = _network([
        ("192.168.1.1", 1500, True, True),
        ("10.0.0.1", 1492, True, True),
        ("10.0.0.2", 1492, True, True),
        ("10.9.9.9", 1492, True, True),
    ])
    hops = _trace(probe)
    assert [(h.address, h.mtu) for h in hops] == [
        ("192.168.1.1", 1500), ("10.0.0.1", 1492), ("10.0.0.2", 1492), ("10.9.9.9", 1492),
    ]
    assert hops[1].note == "MTU drops to 1492 (reported by 192.168.1.1)"
    assert hops[-1].reached
    # Hop 1 settles 1500 below the ceiling in a few probes; after that no
    # search is needed: one probe per hop plus one retry after the report.
    assert len(calls) == 8
    assert hops[0].note == ""


def test_silent_drop_is_found_by_search():
    probe, _ = _network([
        ("192.168.1.1", 1500, False, True),
        ("10.0.0.1", 1400, False, True),
        ("10.9.9.9", 1400, False, True),
    ])
    hops = _trace(probe)
    assert [h.mtu for h in hops] == [1500, 1400, 1400]
    assert hops[1].note == "MTU drops to 1400 (no router reported it)"


def test_jumbo_path_is_traced_up_to_the_ceiling():
    probe, _ = _network([
        ("192.168.1.1", 9000, False, True),
        ("10.0.0.1", 4000, False, True),
        ("10.9.9.9", 4000, False, True),
    ])
    hops = _trace(probe)
    assert [h.mtu for h in hops] == [tracepath.MAX_MTU, 4000, 4000]
    assert hops[1].note == "MTU drops to 4000 (no router reported it)"


def test_trace_starts_from_the_interface_mtu():
    probe, calls = _network([
        ("192.168.1.1", 1500, False, True),
        ("10.9.9.9", 1500, False, True),
    ])
    hops = _trace(probe, link_mtu=lambda ip: 1500)
    assert [h.mtu for h in hops] == [1500, 1500]
    assert len(calls) == 2


def test_silent_hop_is_shown_and_skipped():
    probe, _ = _network([
        ("192.168.1.1", 1500, True, True),
        ("10.0.0.1", 1500, True, False),
        ("10.9.9.9", 1500, True, True),
    ])
    hops = _trace(probe)
    assert hops[1] == Hop(2, note="No reply")
    assert hops[2].reached and hops[2].mtu == 1500


def test_trace_stops_at_max_hops_or_when_asked():
    probe, _ = _network([("10.0.0.%d" % n, 1500, True, True) for n in range(1, 10)])
    assert len(_trace(probe, max_hops=3)) == 3
    assert _trace(probe, stopped=lambda: True) == []


def test_trace_stops_when_a_router_says_unreachable():
    def probe(ip, ttl, payload):
        return Reply(UNREACHABLE, "10.0.0.1", text="Destination Host Unreachable")

    hops = _trace(probe)
    assert len(hops) == 1 and hops[0].unreachable
    assert hops[0].note == "Destination Host Unreachable"


def test_real_trace_to_loopback():
    hops = []
    tracepath.trace("127.0.0.1", hops.append)
    assert [(h.address, h.mtu, h.reached) for h in hops] == [
        ("127.0.0.1", tracepath.MAX_MTU, True)
    ]


def test_window_tints_the_hop_where_mtu_drops(qapp, monkeypatch):
    from NetInfoView.ui import tracepath_window

    monkeypatch.setattr(tracepath_window.TracepathWindow, "start", lambda self: None)
    window = tracepath_window.TracepathWindow("router", "10.9.9.9")
    window.add_hop(Hop(1, "192.168.1.1", 1500))
    window.add_hop(Hop(2, "10.0.0.1", 1492, note="MTU drops to 1492"))
    window.add_hop(Hop(3))
    first, second, silent = (window.tree.topLevelItem(i) for i in range(3))
    assert second.text(3) == "1492" and second.text(5) == "MTU drops to 1492"
    assert second.background(0).color() == tracepath_window.DROP_TINT
    assert first.background(0).style().name == "NoBrush"
    assert silent.text(1) == "*" and silent.text(3) == ""
    window.close()


def test_menu_opens_a_trace_for_the_selected_host(qapp, tmp_path, monkeypatch):
    from NetInfoView.fileio.hostfile import parse_host_list
    from NetInfoView.settings import Settings
    from NetInfoView.ui import tracepath_window
    from NetInfoView.ui.main_window import MainWindow

    monkeypatch.setattr(
        "NetInfoView.fileio.vendor_db.default_db_path", lambda: tmp_path / "v.sqlite"
    )
    monkeypatch.setattr(tracepath_window.TracepathWindow, "start", lambda self: None)
    win = MainWindow(Settings())
    try:
        assert win.action_trace_mtu in win._table.actions()
        assert win.trace_path_mtu() is None  # nothing selected
        (entry,) = win._entries_from_parsed(parse_host_list("10.0.0.1 Gateway"))
        entry.ip_address = "10.0.0.1"
        win._model.set_entries([entry])
        win._table.selectRow(0)
        window = win.trace_path_mtu()
        assert window is not None and window._ip == "10.0.0.1"
        assert window.windowTitle() == "Trace Path MTU - 10.0.0.1"
        window.close()
    finally:
        win.close()


def test_whois_takes_the_most_specific_netname():
    from NetInfoView.ping import whois

    assert whois.parse(
        "% IANA WHOIS server\ninetnum:      142.0.0.0 - 142.255.255.255\n"
        "# whois.arin.net\nNetRange:       142.250.0.0 - 142.251.255.255\n"
        "NetName:        GOOGLE\n"
    ) == "GOOGLE"
    assert whois.parse(
        "netname:        APNIC-AP\nnetname:        AWN-CO-LTD-TH\n"
    ) == "AWN-CO-LTD-TH"
    assert whois.parse("% No match\n") == ""
    # Private and reserved addresses aren't looked up at all.
    assert whois.netname("10.33.255.252") == ""
    assert whois.netname("192.168.1.1") == ""
    assert whois.netname("not an ip") == ""


def test_reserved_addresses_are_named_by_their_block():
    from NetInfoView.ping import whois

    assert whois.reserved_name("10.33.255.252") == "Private (10.0.0.0/8)"
    assert whois.reserved_name("192.168.1.1") == "Private (192.168.0.0/16)"
    assert whois.reserved_name("100.64.1.1") == "Carrier-grade NAT (100.64.0.0/10)"
    assert whois.reserved_name("8.8.8.8") == ""
    assert whois.reserved_name("not an ip") == ""


def test_whois_details_of_an_apnic_network():
    from NetInfoView.ping import whois

    output = (
        "inetnum:      49.0.0.0 - 49.255.255.255\norganisation: APNIC\nsource:       IANA\n\n"
        "inetnum:        49.229.24.192 - 49.229.24.255\nnetname:        DOAHQInternetMainLink-TH\n"
        'descr:          reassign to "DOA Main Link"\ndescr:          contact "noc@example.th"\n'
        "country:        TH\nstatus:         ASSIGNED NON-PORTABLE\n"
        "last-modified:  2021-02-16T04:09:08Z\n\n"
        "irt:            IRT-AWN\nabuse-mailbox:  abuse@example.th\n\n"
        "role:           ABUSE AWN\ncountry:        ZZ\n"
    )
    assert whois.parse_details(output) == [
        ("Network", "DOAHQInternetMainLink-TH"),
        ("Range", "49.229.24.192 - 49.229.24.255"),
        ("Description", 'reassign to "DOA Main Link"\ncontact "noc@example.th"'),
        ("Country", "TH"),
        ("Status", "ASSIGNED NON-PORTABLE"),
        ("Abuse contact", "abuse@example.th"),
        ("Last modified", "2021-02-16T04:09:08Z"),
    ]


def test_whois_details_of_an_arin_network():
    from NetInfoView.ping import whois

    output = (
        "NetRange:       142.250.0.0 - 142.251.255.255\nCIDR:           142.250.0.0/15\n"
        "NetName:        GOOGLE\nNetType:        Direct Allocation\nUpdated:        2012-05-24\n\n"
        "OrgName:        Google LLC\nCountry:        US\n\n"
        "OrgAbuseEmail:  network-abuse@google.com\n"
    )
    details = dict(whois.parse_details(output))
    assert details["Network"] == "GOOGLE" and details["CIDR"] == "142.250.0.0/15"
    assert details["Organization"] == "Google LLC" and details["Country"] == "US"
    assert details["Abuse contact"] == "network-abuse@google.com"


def test_cymru_origin_as():
    from NetInfoView.ping import whois

    assert whois.parse_cymru(
        "AS      | IP               | BGP Prefix          | CC | Registry | Allocated  | AS Name\n"
        "15169   | 8.8.8.8          | 8.8.8.0/24          | US | arin     | 2023-12-28 | GOOGLE - Google LLC, US\n"
    )["AS Name"] == "GOOGLE - Google LLC, US"
    assert whois.parse_cymru("Error: no ASN found") == {}
    rows, raw = whois.details("10.30.0.34")
    assert rows[0] == ("Network", "Private (10.0.0.0/8)") and raw == ""


def test_double_clicking_a_hop_opens_its_details(qapp, monkeypatch):
    from NetInfoView.ui import hop_details_window, tracepath_window

    monkeypatch.setattr(tracepath_window.TracepathWindow, "start", lambda self: None)
    monkeypatch.setattr(hop_details_window.HopDetailsThread, "start", lambda self: None)
    window = tracepath_window.TracepathWindow("8.8.8.8", "8.8.8.8")
    window.add_hop(Hop(1, "49.229.24.193", 1280))
    window.add_hop(Hop(2))
    window._on_name(1, "DOAHQInternetMainLink-TH")
    first, silent = window.tree.topLevelItem(0), window.tree.topLevelItem(1)

    assert window.show_details(silent) is None
    details = window.show_details(first)
    assert details is not None and details.windowTitle() == "Hop 1 - 49.229.24.193"
    details.show_details("", [("Network", "DOAHQInternetMainLink-TH"), ("Country", "TH")], "raw")
    text = details.text()
    assert "Name: DOAHQInternetMainLink-TH" in text
    assert "Reverse DNS: (none)" in text and "Country: TH" in text
    assert "Looking up" not in text
    details.close()
    window.close()


def test_country_column(qapp, monkeypatch):
    from NetInfoView.ping import whois
    from NetInfoView.ui import tracepath_window

    assert tracepath_window.country_label("th") == "Thailand"
    assert tracepath_window.country_label("AP") == "AP"
    # Flags are bundled images, not emoji (Windows has no flag emoji).
    assert not tracepath_window.country_flag("th").isNull()
    assert tracepath_window.country_flag("AP").isNull()
    assert tracepath_window.country_flag("").isNull()
    assert whois.country("10.30.0.34") == ""
    monkeypatch.setattr(whois, "query", lambda ip, server="": (
        "15169 | 8.8.8.8 | 8.8.8.0/24 | US | arin | 2023-12-28 | GOOGLE - Google LLC, US"))
    assert whois.country("8.8.8.8") == "US"

    monkeypatch.setattr(tracepath_window.TracepathWindow, "start", lambda self: None)
    window = tracepath_window.TracepathWindow("8.8.8.8", "8.8.8.8")
    window.add_hop(Hop(1, "8.8.8.8", 1280, reached=True))
    window._on_country(1, "US")
    item = window.tree.topLevelItem(0)
    assert item.text(tracepath_window.COUNTRY_COLUMN) == "United States"
    assert not item.icon(tracepath_window.COUNTRY_COLUMN).isNull()
    window.close()
