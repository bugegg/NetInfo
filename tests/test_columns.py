from NetInfoView.model.columns import COLUMN_BY_KEY, ip_aware_key
from NetInfoView.model.host import HostEntry


def test_ip_aware_key_orders_octets_numerically():
    ips = ["192.168.1.1", "192.168.1.2", "192.168.1.10", "192.168.1.100", "192.168.1.11"]
    assert sorted(ips, key=ip_aware_key) == [
        "192.168.1.1", "192.168.1.2", "192.168.1.10", "192.168.1.11", "192.168.1.100",
    ]


def test_ip_aware_key_puts_non_ip_text_after_every_real_ip():
    values = ["10.0.0.5", "www.google.com", "1.1.1.1", "", "a-host"]
    ordered = sorted(values, key=ip_aware_key)
    assert ordered[:2] == ["1.1.1.1", "10.0.0.5"]
    assert set(ordered[2:]) == {"", "a-host", "www.google.com"}


def test_ip_address_column_sort_key_uses_ip_aware_ordering():
    column = COLUMN_BY_KEY["ip_address"]
    entries = [HostEntry(i, "h", ip_address=ip) for i, ip in enumerate(
        ["192.168.1.10", "192.168.1.2", "192.168.1.100"]
    )]
    keys = [column.sort_key(e) for e in entries]
    assert sorted(entries, key=lambda e: column.sort_key(e)) == [
        entries[1], entries[0], entries[2]
    ]


def test_host_name_column_sorts_by_bare_host_not_display_name_with_port():
    """A TCP host's ':port' suffix must not break IP parsing for sorting."""
    column = COLUMN_BY_KEY["host_name"]
    a = HostEntry(1, "192.168.1.2", port=443)
    b = HostEntry(2, "192.168.1.10")
    assert column.sort_key(a) < column.sort_key(b)


def test_status_dot_is_grey_for_destination_host_unreachable():
    from types import SimpleNamespace

    from NetInfoView.ping.result import PingStatus
    from NetInfoView.ui.icons import icon_name_for

    def dot(status):
        return icon_name_for(SimpleNamespace(enabled=True, last_status=status))

    assert dot(PingStatus.HOST_UNREACHABLE) == "unreachable"
    assert dot(PingStatus.TIMEOUT) == "failed"
    assert dot(PingStatus.SUCCEEDED) == "succeeded"
    assert dot(None) == "unknown"


def test_dns_name_column():
    column = COLUMN_BY_KEY["dns_name"]
    assert column.title == "DNS Name"
    assert column.display(HostEntry(1, "h", dns_name="pc1.corp.local")) == "pc1.corp.local"
