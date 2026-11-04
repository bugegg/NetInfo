"""On Windows, skip the tests of macOS-only code paths: they parse or drive
macOS tools (ifconfig, dscacheutil, ping -D, route, ditto) or use features
the Windows build hides (MTU, Trace Path MTU, LLDP/CDP)."""

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
    "tests/test_mtu.py::test_real_ping_reaches_loopback",
    "tests/test_mtu.py::test_mtu_is_checked_automatically",
    "tests/test_mtu.py::test_check_mtu_fills_the_column",
    "tests/test_tracepath.py::test_real_trace_to_loopback",
    "tests/test_tracepath.py::test_menu_opens_a_trace",
    "tests/test_lldp_cdp.py::",
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
