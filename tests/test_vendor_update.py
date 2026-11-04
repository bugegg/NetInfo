import urllib.error

import pytest

from NetInfoView.ping.vendor_update import (
    VendorUpdateError,
    parse_oui_csv,
    run_update,
)

SAMPLE_CSV = (
    "Registry,Assignment,Organization Name,Organization Address\n"
    'MA-L,E8136E,"Example Networks, Inc.",1 Example Way\n'
    "MA-L,CCF411,Example Mobile Co,2 Example Ave\n"
)


def test_parse_oui_csv_extracts_prefix_and_vendor():
    rows = parse_oui_csv(SAMPLE_CSV)
    assert rows == [
        ("E8136E", "Example Networks, Inc."),
        ("CCF411", "Example Mobile Co"),
    ]


def test_parse_oui_csv_skips_rows_missing_a_vendor_name():
    csv_text = (
        "Registry,Assignment,Organization Name,Organization Address\n"
        "MA-L,AAAAAA,,Address only\n"
        "MA-L,BBBBBB,Has A Name,Address\n"
    )
    assert parse_oui_csv(csv_text) == [("BBBBBB", "Has A Name")]


def test_parse_oui_csv_rejects_unexpected_format():
    with pytest.raises(VendorUpdateError):
        parse_oui_csv("not,the,right,columns\n1,2,3,4\n")


def test_parse_oui_csv_rejects_header_only_with_no_rows():
    with pytest.raises(VendorUpdateError):
        parse_oui_csv("Registry,Assignment,Organization Name,Organization Address\n")


def test_run_update_stores_rows_via_vendor_db(monkeypatch):
    stored = {}

    class FakeVendorDB:
        def replace_all(self, rows, updated_at):
            stored["rows"] = rows
            stored["updated_at"] = updated_at
            return len(rows)

    monkeypatch.setattr(
        "NetInfoView.ping.vendor_update.fetch_oui_csv", lambda url=None: SAMPLE_CSV
    )
    count = run_update(FakeVendorDB())
    assert count == 2
    assert stored["rows"] == [
        ("E8136E", "Example Networks, Inc."),
        ("CCF411", "Example Mobile Co"),
    ]
    assert stored["updated_at"]  # a non-empty timestamp was generated


def test_fetch_failure_raises_vendor_update_error(monkeypatch):
    import urllib.request

    def raise_url_error(*args, **kwargs):
        raise urllib.error.URLError("no network")

    monkeypatch.setattr(urllib.request, "urlopen", raise_url_error)
    from NetInfoView.ping.vendor_update import fetch_oui_csv

    with pytest.raises(VendorUpdateError):
        fetch_oui_csv()
