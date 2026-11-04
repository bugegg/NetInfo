import subprocess
from pathlib import Path

import pinginfoview.ping.network_interfaces as ni

FIXTURE = (Path(__file__).parent / "fixtures" / "ifconfig_sample.txt").read_text()

#: A loopback-only ifconfig, as if offline or on a locked-down sandbox.
LOOPBACK_ONLY = (
    "lo0: flags=8049<UP,LOOPBACK,RUNNING,MULTICAST> mtu 16384\n"
    "\toptions=1203<RXCSUM,TXCSUM,TXSTATUS,SW_TIMESTAMP>\n"
    "\tinet 127.0.0.1 netmask 0xff000000\n"
    "\tinet6 ::1 prefixlen 128\n"
)

#: A DHCP-assigned /24, the common case.
SIMPLE_EN0 = (
    "en0: flags=8863<UP,BROADCAST,SMART,RUNNING,SIMPLEX,MULTICAST> mtu 1500\n"
    "\tether ea:f1:17:d1:35:87\n"
    "\tinet 192.168.1.105 netmask 0xffffff00 broadcast 192.168.1.255\n"
    "\tstatus: active\n"
)

#: Down interface: UP is absent from the flags.
DOWN_INTERFACE = (
    "en1: flags=8822<BROADCAST,SMART,SIMPLEX,MULTICAST> mtu 1500\n"
    "\tether 36:e4:74:3a:33:00\n"
    "\tinet 10.0.0.5 netmask 0xffffff00 broadcast 10.0.0.255\n"
)

#: A bridge whose UP-flagged line uses hex digits a-f, with a *nested*
#: member-interface flags line that would wrongly look like "the" match for
#: a decimal-only regex (the exact bug this module had).
BRIDGE_WITH_NESTED_MEMBER_FLAGS = (
    "bridge100: flags=8a63<UP,BROADCAST,SMART,RUNNING,ALLMULTI,SIMPLEX,MULTICAST> mtu 1500\n"
    "\tether ae:07:75:41:7c:64\n"
    "\tinet 192.168.153.1 netmask 0xffffff00 broadcast 192.168.153.255\n"
    "\tmember: vmenet0 flags=3<LEARNING,DISCOVER>\n"
    "\tstatus: active\n"
)


def _run_with_fixture(monkeypatch, text):
    monkeypatch.setattr(
        subprocess, "run",
        lambda *a, **k: subprocess.CompletedProcess(a, 0, stdout=text, stderr=""),
    )
    return ni.list_interfaces()


def test_loopback_is_excluded(monkeypatch):
    assert _run_with_fixture(monkeypatch, LOOPBACK_ONLY) == []


def test_simple_dhcp_interface_is_found(monkeypatch):
    (iface,) = _run_with_fixture(monkeypatch, SIMPLE_EN0)
    assert iface.name == "en0"
    assert iface.ip_address == "192.168.1.105"
    assert iface.netmask == "255.255.255.0"
    assert iface.cidr == "192.168.1.0/24"
    assert iface.display_label == "en0  —  192.168.1.105  (192.168.1.0/24)"


def test_interface_without_up_flag_is_excluded(monkeypatch):
    assert _run_with_fixture(monkeypatch, DOWN_INTERFACE) == []


def test_bridge_with_hex_only_flags_and_nested_member_line_is_found(monkeypatch):
    """Regression test: \\d+ alone mismatched flags=8a63 (hex, not decimal)
    and fell through to the nested member's flags=3<...>, which lacks UP."""
    (iface,) = _run_with_fixture(monkeypatch, BRIDGE_WITH_NESTED_MEMBER_FLAGS)
    assert iface.name == "bridge100"
    assert iface.cidr == "192.168.153.0/24"


def test_point_to_point_slash_32_is_excluded(monkeypatch):
    utun = (
        "utun0: flags=8051<UP,POINTOPOINT,RUNNING,MULTICAST> mtu 1500\n"
        "\tinet 10.10.10.2 --> 10.10.10.1 netmask 0xffffffff\n"
    )
    assert _run_with_fixture(monkeypatch, utun) == []


def test_interface_with_no_inet_line_is_excluded(monkeypatch):
    no_inet = (
        "anpi0: flags=8863<UP,BROADCAST,SMART,RUNNING,SIMPLEX,MULTICAST> mtu 1500\n"
        "\tether ca:89:fd:5f:ef:ae\n"
        "\tstatus: inactive\n"
    )
    assert _run_with_fixture(monkeypatch, no_inet) == []


def test_subprocess_failure_returns_empty_list_not_an_exception(monkeypatch):
    def raise_oserror(*a, **k):
        raise OSError("ifconfig not found")
    monkeypatch.setattr(subprocess, "run", raise_oserror)
    assert ni.list_interfaces() == []


def test_real_captured_ifconfig_finds_every_active_ipv4_interface(monkeypatch):
    """Against this machine's real output: en0 plus two virtualization
    bridges, each with hex-only flags words — the exact real-world case
    that exposed the \\d+ bug."""
    interfaces = _run_with_fixture(monkeypatch, FIXTURE)
    names = {iface.name for iface in interfaces}
    assert names == {"en0", "bridge100", "bridge101"}
    by_name = {iface.name: iface for iface in interfaces}
    assert by_name["en0"].cidr == "192.168.1.0/24"
    assert by_name["bridge100"].cidr == "192.168.153.0/24"
    assert by_name["bridge101"].cidr == "172.16.221.0/24"
