"""On Windows, skip the tests of macOS-only code paths: they parse or drive
macOS tools (ifconfig, dscacheutil, route, ditto) or read /dev/bpf through
pipes and select(). tests/test_windows_support.py covers what Windows uses
in their place."""

import sys

import pytest

MACOS_ONLY = (
    "tests/test_network_interfaces.py::",
    "tests/test_hostname.py::test_dscacheutil",
    "tests/test_hostname.py::test_falls_back_to_reverse_dns",
    "tests/test_hostname.py::test_subprocess_failure_falls_through",
    "tests/test_hostname.py::test_trailing_dot",
    "tests/test_hostname.py::test_empty_string_when_neither",
    "tests/test_mtu.py::test_route_mtu_reads_the_loopback_interface",
    "tests/test_lldp_cdp.py::test_listen_reports_each_switch_port_once",
    "tests/test_lldp_cdp.py::test_listen_stops_when_asked",
    "tests/test_lldp_cdp.py::test_ethernet_interfaces_order",
    "tests/test_app_update.py::test_running_app_bundle_when_frozen",
    "tests/test_app_update.py::test_extract_app_finds_the_bundle",
    "tests/test_app_update.py::test_installer_script_swaps",
)


def pytest_collection_modifyitems(config, items):
    if sys.platform != "win32":
        return
    skip = pytest.mark.skip(reason="macOS-only code path")
    for item in items:
        nodeid = item.nodeid.replace("\\", "/")
        if any(nodeid.startswith(prefix) for prefix in MACOS_ONLY):
            item.add_marker(skip)
