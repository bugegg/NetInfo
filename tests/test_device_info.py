import pytest

import NetInfoView.ping.device_info as device_info
from NetInfoView.ping.device_info import DeviceInfoJob, DeviceInfoResult


@pytest.fixture(autouse=True)
def no_real_dns(monkeypatch):
    """No PTR queries to whatever DNS this machine uses; tests that care
    about DNS names stub dns_ptr.lookup themselves."""
    monkeypatch.setattr(device_info.dns_ptr, "system_nameservers", lambda: [])
    monkeypatch.setattr(device_info.dns_ptr, "lookup", lambda ip, servers=None: "")


class FakeVendorDB:
    def __init__(self, table=None):
        self.table = table or {}
        self.lookups = []

    def lookup(self, mac):
        self.lookups.append(mac)
        return self.table.get(mac, "")


def test_known_mac_is_used_without_touching_arp(monkeypatch):
    def fail(*a, **k):
        raise AssertionError("arp.lookup should not run when MAC is already known")
    monkeypatch.setattr(device_info.arp, "lookup", fail)
    monkeypatch.setattr(device_info.hostname_lookup, "resolve", lambda ip: "")

    results = device_info.resolve_batch(
        [DeviceInfoJob(key=1, ip="192.168.1.1", known_mac="00:11:22:DD:EE:FF")],
        FakeVendorDB(),
    )
    assert results == [DeviceInfoResult(key=1, mac="00:11:22:DD:EE:FF")]


def test_missing_mac_falls_back_to_arp_lookup(monkeypatch):
    monkeypatch.setattr(device_info.arp, "lookup", lambda ip: "11:22:33:44:55:66")
    monkeypatch.setattr(device_info.hostname_lookup, "resolve", lambda ip: "")

    results = device_info.resolve_batch(
        [DeviceInfoJob(key=1, ip="192.168.1.5")], FakeVendorDB()
    )
    assert results == [DeviceInfoResult(key=1, mac="11:22:33:44:55:66")]


def test_hostname_only_resolved_when_requested(monkeypatch):
    calls = []

    def fake_resolve(ip):
        calls.append(ip)
        return "device.local"

    monkeypatch.setattr(device_info.arp, "lookup", lambda ip: "")
    monkeypatch.setattr(device_info.hostname_lookup, "resolve", fake_resolve)

    results = device_info.resolve_batch(
        [
            DeviceInfoJob(key=1, ip="192.168.1.1", known_mac="AA:AA:AA:AA:AA:AA", needs_hostname=True),
            DeviceInfoJob(key=2, ip="192.168.1.2", known_mac="BB:BB:BB:BB:BB:BB", needs_hostname=False),
        ],
        FakeVendorDB(),
    )
    assert calls == ["192.168.1.1"]  # host 2 opted out, never queried
    by_key = {r.key: r for r in results}
    assert by_key[1].hostname == "device.local"
    assert by_key[2].hostname == ""


def test_vendor_looked_up_from_resolved_mac(monkeypatch):
    monkeypatch.setattr(device_info.arp, "lookup", lambda ip: "E8:13:6E:00:00:00")
    monkeypatch.setattr(device_info.hostname_lookup, "resolve", lambda ip: "")

    db = FakeVendorDB({"E8:13:6E:00:00:00": "Example Networks"})
    results = device_info.resolve_batch(
        [DeviceInfoJob(key=1, ip="192.168.1.1")], db
    )
    assert results == [
        DeviceInfoResult(key=1, mac="E8:13:6E:00:00:00", vendor="Example Networks")
    ]


def test_no_mac_means_no_vendor_lookup_attempted(monkeypatch):
    monkeypatch.setattr(device_info.arp, "lookup", lambda ip: "")
    monkeypatch.setattr(device_info.hostname_lookup, "resolve", lambda ip: "")

    db = FakeVendorDB()
    device_info.resolve_batch([DeviceInfoJob(key=1, ip="192.168.1.1")], db)
    assert db.lookups == []


def test_a_hanging_host_does_not_block_others(monkeypatch):
    """The whole point of the thread pool: one slow host can't serialise the rest."""
    import threading

    release_slow_host = threading.Event()
    order = []

    def fake_resolve(ip):
        if ip == "192.168.1.1":
            release_slow_host.wait(timeout=2)
            order.append("slow")
            return "slow.local"
        order.append(f"fast-{ip}")
        return f"{ip}.local"

    monkeypatch.setattr(device_info.arp, "lookup", lambda ip: "")
    monkeypatch.setattr(device_info.hostname_lookup, "resolve", fake_resolve)

    jobs = [DeviceInfoJob(key=1, ip="192.168.1.1", needs_hostname=True)] + [
        DeviceInfoJob(key=n, ip=f"192.168.1.{n}", needs_hostname=True)
        for n in range(2, 12)
    ]

    results_holder = {}

    def run():
        results_holder["results"] = device_info.resolve_batch(jobs, FakeVendorDB())

    thread = threading.Thread(target=run)
    thread.start()
    # Give the fast hosts time to finish while host 1 is still blocked.
    import time
    time.sleep(0.3)
    assert any(item.startswith("fast-") for item in order), "fast hosts should finish first"
    assert "slow" not in order
    release_slow_host.set()
    thread.join(timeout=3)

    by_key = {r.key: r for r in results_holder["results"]}
    assert by_key[1].hostname == "slow.local"
    assert by_key[5].hostname == "192.168.1.5.local"


def test_unresolvable_hosts_produce_empty_strings_not_exceptions(monkeypatch):
    def raise_error(ip):
        raise OSError("unreachable")
    monkeypatch.setattr(device_info.arp, "lookup", lambda ip: "")
    monkeypatch.setattr(device_info.hostname_lookup, "resolve", raise_error)

    results = device_info.resolve_batch(
        [DeviceInfoJob(key=1, ip="192.168.1.1", needs_hostname=True)], FakeVendorDB()
    )
    assert results == [DeviceInfoResult(key=1)]


def test_empty_snapshot_returns_empty_results():
    assert device_info.resolve_batch([], FakeVendorDB()) == []


def test_locally_administered_mac_reports_private_label_without_db_lookup(monkeypatch):
    """A randomized MAC (e.g. iOS/macOS "Private Wi-Fi address") was never
    assigned to any vendor, so it should never even reach the database."""
    from NetInfoView.fileio.vendor_db import PRIVATE_MAC_LABEL

    monkeypatch.setattr(device_info.hostname_lookup, "resolve", lambda ip: "")
    db = FakeVendorDB()

    # EA has the U/L bit set (locally administered).
    results = device_info.resolve_batch(
        [DeviceInfoJob(key=1, ip="192.168.1.105", known_mac="EA:F1:17:D1:35:87")], db
    )
    assert results == [
        DeviceInfoResult(key=1, mac="EA:F1:17:D1:35:87", vendor=PRIVATE_MAC_LABEL)
    ]
    assert db.lookups == [], "a locally-administered MAC must never hit the vendor DB"


def test_universally_administered_mac_still_uses_the_vendor_db(monkeypatch):
    """Sanity check: real vendor MACs are unaffected by the new check."""
    monkeypatch.setattr(device_info.hostname_lookup, "resolve", lambda ip: "")
    db = FakeVendorDB({"E8:13:6E:FB:77:BF": "HUAWEI TECHNOLOGIES CO.,LTD"})

    results = device_info.resolve_batch(
        [DeviceInfoJob(key=1, ip="192.168.1.1", known_mac="E8:13:6E:FB:77:BF")], db
    )
    assert results == [
        DeviceInfoResult(
            key=1, mac="E8:13:6E:FB:77:BF", vendor="HUAWEI TECHNOLOGIES CO.,LTD"
        )
    ]


# -- port scanning ------------------------------------------------------


def test_port_scan_only_runs_for_hosts_that_opted_in(monkeypatch):
    monkeypatch.setattr(device_info.arp, "lookup", lambda ip: "")
    monkeypatch.setattr(device_info.hostname_lookup, "resolve", lambda ip: "")
    scanned_ips = {}
    monkeypatch.setattr(
        device_info.port_scan,
        "scan_many",
        lambda ip_by_key, ports=None, udp_ports=None: scanned_ips.update(ip_by_key) or {k: [] for k in ip_by_key},
    )

    device_info.resolve_batch(
        [
            DeviceInfoJob(key=1, ip="192.168.1.1", needs_ports=True),
            DeviceInfoJob(key=2, ip="192.168.1.2", needs_ports=False),
        ],
        FakeVendorDB(),
    )
    assert scanned_ips == {1: "192.168.1.1"}


def test_port_scan_results_populate_open_ports_and_device_type_guess(monkeypatch):
    monkeypatch.setattr(device_info.arp, "lookup", lambda ip: "")
    monkeypatch.setattr(device_info.hostname_lookup, "resolve", lambda ip: "")
    monkeypatch.setattr(
        device_info.port_scan, "scan_many", lambda ip_by_key, ports=None, udp_ports=None: {1: [22, 80]}
    )
    monkeypatch.setattr(
        device_info.port_scan, "guess_device_type", lambda ports: "SSH-enabled thing"
    )

    results = device_info.resolve_batch(
        [DeviceInfoJob(key=1, ip="192.168.1.1", needs_ports=True)], FakeVendorDB()
    )
    assert results == [
        DeviceInfoResult(
            key=1, open_ports=[22, 80], device_type="SSH-enabled thing", ports_scanned=True
        )
    ]


def test_ports_scanned_flag_is_false_when_not_requested(monkeypatch):
    monkeypatch.setattr(device_info.arp, "lookup", lambda ip: "")
    monkeypatch.setattr(device_info.hostname_lookup, "resolve", lambda ip: "")

    def fail(*a, **k):
        raise AssertionError("scan_many should not run when nothing opted in")
    monkeypatch.setattr(device_info.port_scan, "scan_many", fail)

    results = device_info.resolve_batch(
        [DeviceInfoJob(key=1, ip="192.168.1.1")], FakeVendorDB()
    )
    assert results == [DeviceInfoResult(key=1)]
    assert results[0].ports_scanned is False


def test_port_scan_still_runs_when_the_vendor_is_already_known(monkeypatch):
    """Port scanning reports what ports a host has open, for any host that
    opted in — a real, OUI-assigned vendor doesn't exempt it."""
    monkeypatch.setattr(device_info.hostname_lookup, "resolve", lambda ip: "")
    monkeypatch.setattr(
        device_info.port_scan, "scan_many", lambda ip_by_key, ports=None, udp_ports=None: {1: [22, 80]}
    )

    db = FakeVendorDB({"E8:13:6E:FB:77:BF": "HUAWEI TECHNOLOGIES CO.,LTD"})
    results = device_info.resolve_batch(
        [
            DeviceInfoJob(
                key=1, ip="192.168.1.1", known_mac="E8:13:6E:FB:77:BF", needs_ports=True
            )
        ],
        db,
    )
    assert results == [
        DeviceInfoResult(
            key=1,
            mac="E8:13:6E:FB:77:BF",
            vendor="HUAWEI TECHNOLOGIES CO.,LTD",
            open_ports=[22, 80],
            device_type="SSH-enabled (Unix/Linux/macOS/Network Device)",
            ports_scanned=True,
        )
    ]


def test_port_scan_still_runs_for_a_private_administered_mac(monkeypatch):
    """A randomized MAC has no vendor to find by definition — this is
    exactly the host the port scan exists for, so it must not be skipped."""
    monkeypatch.setattr(device_info.hostname_lookup, "resolve", lambda ip: "")
    monkeypatch.setattr(
        device_info.port_scan, "scan_many", lambda ip_by_key, ports=None, udp_ports=None: {1: [80]}
    )

    results = device_info.resolve_batch(
        [
            DeviceInfoJob(
                key=1, ip="192.168.1.105", known_mac="EA:F1:17:D1:35:87", needs_ports=True
            )
        ],
        FakeVendorDB(),
    )
    assert results[0].ports_scanned is True
    assert results[0].open_ports == [80]


def test_port_scan_still_runs_when_the_vendor_is_unresolved(monkeypatch):
    """A universally-administered MAC with no match in the local vendor DB
    (not downloaded yet, or genuinely unknown) still gets scanned — "no
    vendor found" isn't the same as "no vendor to find"."""
    monkeypatch.setattr(device_info.arp, "lookup", lambda ip: "")
    monkeypatch.setattr(device_info.hostname_lookup, "resolve", lambda ip: "")
    scanned_ips = {}
    monkeypatch.setattr(
        device_info.port_scan,
        "scan_many",
        lambda ip_by_key, ports=None, udp_ports=None: scanned_ips.update(ip_by_key)
        or {k: [] for k in ip_by_key},
    )

    device_info.resolve_batch(
        [DeviceInfoJob(key=1, ip="192.168.1.1", needs_ports=True)], FakeVendorDB()
    )
    assert scanned_ips == {1: "192.168.1.1"}


# -- all-IPs-for-a-name lookup --------------------------------------------


def test_resolve_all_ips_skips_a_literal_ip():
    assert device_info.resolve_all_ips("192.168.1.1") == []


def test_resolve_all_ips_skips_an_empty_host():
    assert device_info.resolve_all_ips("") == []


def test_resolve_all_ips_returns_sorted_unique_addresses(monkeypatch):
    def fake_getaddrinfo(host, port, family=None, type=None):
        # getaddrinfo can repeat an address across socket types; dedupe it.
        return [
            (None, None, None, None, ("203.0.113.2", 0)),
            (None, None, None, None, ("203.0.113.1", 0)),
            (None, None, None, None, ("203.0.113.1", 0)),
        ]
    monkeypatch.setattr(device_info.socket, "getaddrinfo", fake_getaddrinfo)
    assert device_info.resolve_all_ips("example.com") == ["203.0.113.1", "203.0.113.2"]


def test_resolve_all_ips_returns_empty_on_resolution_failure(monkeypatch):
    def raise_error(host, port, family=None, type=None):
        raise OSError("not found")
    monkeypatch.setattr(device_info.socket, "getaddrinfo", raise_error)
    assert device_info.resolve_all_ips("bogus.invalid") == []


def test_all_ips_only_looked_up_when_requested(monkeypatch):
    monkeypatch.setattr(device_info.arp, "lookup", lambda ip: "")
    monkeypatch.setattr(device_info.hostname_lookup, "resolve", lambda ip: "")
    lookups = []
    monkeypatch.setattr(
        device_info,
        "resolve_all_ips",
        lambda host: lookups.append(host) or ["203.0.113.1", "203.0.113.2"],
    )

    results = device_info.resolve_batch(
        [
            DeviceInfoJob(key=1, ip="203.0.113.1", host="cdn.example.com", needs_all_ips=True),
            DeviceInfoJob(key=2, ip="192.168.1.2", host="192.168.1.2", needs_all_ips=False),
        ],
        FakeVendorDB(),
    )
    assert lookups == ["cdn.example.com"]
    by_key = {r.key: r for r in results}
    assert by_key[1].all_ips == ["203.0.113.1", "203.0.113.2"]
    assert by_key[1].all_ips_looked_up is True
    assert by_key[2].all_ips == []
    assert by_key[2].all_ips_looked_up is False


def test_all_ips_lookup_failure_still_marks_looked_up(monkeypatch):
    monkeypatch.setattr(device_info.arp, "lookup", lambda ip: "")
    monkeypatch.setattr(device_info.hostname_lookup, "resolve", lambda ip: "")

    def raise_error(host):
        raise OSError("dns failure")
    monkeypatch.setattr(device_info, "resolve_all_ips", raise_error)

    results = device_info.resolve_batch(
        [DeviceInfoJob(key=1, ip="203.0.113.1", host="cdn.example.com", needs_all_ips=True)],
        FakeVendorDB(),
    )
    assert results == [DeviceInfoResult(key=1, all_ips=[], all_ips_looked_up=True)]



def test_dns_name_comes_from_the_system_dns_servers(monkeypatch):
    monkeypatch.setattr(device_info.arp, "lookup", lambda ip: "")
    monkeypatch.setattr(device_info.hostname_lookup, "resolve", lambda ip: "phone.local")
    monkeypatch.setattr(device_info.dns_ptr, "system_nameservers", lambda: ["10.0.0.1"])
    asked = []
    monkeypatch.setattr(
        device_info.dns_ptr, "lookup",
        lambda ip, servers=None: asked.append((ip, servers)) or "pc1.corp.local",
    )
    (result,) = device_info.resolve_batch(
        [DeviceInfoJob(key=1, ip="10.0.0.5", needs_hostname=True, needs_dns_name=True)],
        FakeVendorDB(),
    )
    assert asked == [("10.0.0.5", ["10.0.0.1"])]
    # Two separate columns: Bonjour's name and DNS's name.
    assert (result.hostname, result.dns_name) == ("phone.local", "pc1.corp.local")


def test_mac_and_vendor_are_reported_before_the_slow_name_lookups(monkeypatch):
    """The ARP table and vendor database answer in milliseconds; the sweep
    hands those over before waiting on the networked name lookups."""
    reports = []
    monkeypatch.setattr(device_info.arp, "lookup", lambda ip: "00:11:22:33:44:55")

    def resolve(ip):
        # By the time names are asked for, MAC and vendor are already out.
        assert reports and reports[0][0].vendor == "Acme"
        return "switch-01"

    monkeypatch.setattr(device_info.hostname_lookup, "resolve", resolve)
    results = device_info.resolve_batch(
        [DeviceInfoJob(key=1, ip="192.168.1.5", needs_hostname=True)],
        FakeVendorDB({"00:11:22:33:44:55": "Acme"}), report=reports.append,
    )
    assert [r[0].hostname for r in reports] == ["", "switch-01"]
    assert reports[0][0].mac == "00:11:22:33:44:55"
    assert results[0].hostname == "switch-01"
    assert reports[0][0] is not results[0]  # copies: the sweep keeps writing its own
