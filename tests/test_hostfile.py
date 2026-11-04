import pytest

from NetInfoView.fileio.hostfile import format_host_list, parse_host_list


def test_plain_host_and_description():
    (host,) = parse_host_list("192.168.1.10 Main Server")
    assert (host.host, host.port, host.description, host.enabled) == (
        "192.168.1.10", None, "Main Server", True,
    )


def test_description_keeps_internal_spacing():
    (host,) = parse_host_list("10.0.0.1 Office   switch  rack 4")
    assert host.description == "Office   switch  rack 4"


def test_port_makes_it_a_tcp_ping():
    (host,) = parse_host_list("192.168.1.30:443 HTTPS Web Site")
    assert (host.host, host.port, host.description) == ("192.168.1.30", 443, "HTTPS Web Site")


def test_hostname_with_port():
    (host,) = parse_host_list("example.com:8080")
    assert (host.host, host.port) == ("example.com", 8080)


def test_hash_prefix_disables_but_keeps_the_entry():
    (host,) = parse_host_list("#192.168.1.14 Host 03")
    assert host.enabled is False
    assert host.host == "192.168.1.14"
    assert host.description == "Host 03"


def test_group_header_applies_until_the_next_one():
    hosts = parse_host_list(
        "Group: Computers Group 1\n"
        "192.168.0.1 Computer01\n"
        "192.168.0.2 Computer02\n"
        "Group: Servers\n"
        "10.0.0.1 Server01\n"
    )
    assert [h.group for h in hosts] == ["Computers Group 1"] * 2 + ["Servers"]


def test_blank_lines_and_whitespace_ignored():
    assert len(parse_host_list("\n\n   \n8.8.8.8\n\n  1.1.1.1  \n")) == 2


def test_full_range_is_inclusive():
    hosts = parse_host_list("192.168.0.10-192.168.0.20")
    assert len(hosts) == 11
    assert hosts[0].host == "192.168.0.10"
    assert hosts[-1].host == "192.168.0.20"


def test_short_range_form():
    hosts = parse_host_list("192.168.0.10-20")
    assert [h.host for h in hosts] == [f"192.168.0.{n}" for n in range(10, 21)]


def test_reversed_range_is_normalised():
    hosts = parse_host_list("192.168.0.20-192.168.0.18")
    assert [h.host for h in hosts] == ["192.168.0.18", "192.168.0.19", "192.168.0.20"]


def test_range_crossing_octet_boundary():
    hosts = parse_host_list("10.0.0.254-10.0.1.2")
    assert [h.host for h in hosts] == [
        "10.0.0.254", "10.0.0.255", "10.0.1.0", "10.0.1.1", "10.0.1.2",
    ]


def test_cidr_excludes_network_and_broadcast():
    hosts = parse_host_list("192.168.0.0/24")
    assert len(hosts) == 254
    assert hosts[0].host == "192.168.0.1"
    assert hosts[-1].host == "192.168.0.254"


def test_cidr_32_is_a_single_host():
    assert [h.host for h in parse_host_list("192.168.0.5/32")] == ["192.168.0.5"]


def test_skip_first_and_last():
    hosts = parse_host_list("192.168.0.10-192.168.0.20", skip_first=True, skip_last=True)
    assert [hosts[0].host, hosts[-1].host] == ["192.168.0.11", "192.168.0.19"]
    assert len(hosts) == 9


def test_expanded_range_inherits_description_group_and_disabled_state():
    hosts = parse_host_list("Group: Lab\n#192.168.0.1-192.168.0.3 Bench")
    assert all(h.group == "Lab" and h.description == "Bench" and not h.enabled for h in hosts)


def test_round_trip_through_format():
    original = (
        "Group: Computers Group 1\n"
        "192.168.0.1 Computer01\n"
        "#192.168.0.2 Computer02\n"
        "192.168.1.30:443 HTTPS Web Site\n"
    )
    reparsed = parse_host_list(format_host_list(parse_host_list(original)))
    assert [(h.host, h.port, h.description, h.group, h.enabled) for h in reparsed] == [
        ("192.168.0.1", None, "Computer01", "Computers Group 1", True),
        ("192.168.0.2", None, "Computer02", "Computers Group 1", False),
        ("192.168.1.30", 443, "HTTPS Web Site", "Computers Group 1", True),
    ]


@pytest.mark.parametrize("token", ["999.1.1.1", "not a host", "10.0.0.1:99999"])
def test_unparseable_tokens_fall_back_to_a_plain_host(token):
    """Anything unrecognised is still offered as a host; DNS decides its fate."""
    hosts = parse_host_list(token)
    assert len(hosts) == 1


def test_ranges_over_the_limit_are_refused_without_expanding():
    import time

    from NetInfoView.fileio.hostfile import HostListError

    started = time.perf_counter()
    for text in ("192.168.1.0/2", "10.0.0.0/8", "10.0.0.0-10.255.255.255"):
        with pytest.raises(HostListError):
            parse_host_list(text)
    assert time.perf_counter() - started < 1.0


def test_a_slash_16_is_still_allowed():
    assert len(parse_host_list("192.168.0.0/16")) == 65534


def test_has_hosts_ignores_blank_group_and_bare_hash_lines():
    from NetInfoView.fileio.hostfile import has_hosts

    assert not has_hosts("")
    assert not has_hosts("  \nGroup: A\n#\n")
    assert has_hosts("Group: A\n#192.168.1.1")
    assert has_hosts("192.168.1.0/2")
