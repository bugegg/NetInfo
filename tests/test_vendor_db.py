import sqlite3
import time

import pytest

from pinginfoview.fileio.vendor_db import VendorDB, normalise_prefix


@pytest.fixture
def db(tmp_path):
    instance = VendorDB(tmp_path / "vendor.sqlite")
    yield instance
    instance.close()


def test_normalise_prefix_strips_separators_and_uppercases():
    assert normalise_prefix("e8:13:6e:fb:77:bf") == "E8136E"
    assert normalise_prefix("E8-13-6E-FB-77-BF") == "E8136E"
    assert normalise_prefix("e8136efb77bf") == "E8136E"


def test_normalise_prefix_too_short_returns_empty():
    assert normalise_prefix("E8:13") == ""
    assert normalise_prefix("") == ""


def test_lookup_on_empty_database_returns_empty_string(db):
    assert db.lookup("E8:13:6E:FB:77:BF") == ""
    assert db.entry_count() == 0
    assert db.last_updated() is None


def test_replace_all_then_lookup_round_trip(db):
    count = db.replace_all(
        [("E8136E", "Example Networks"), ("CCF411", "Example Mobile")],
        updated_at="2026-10-18T12:00:00",
    )
    assert count == 2
    assert db.lookup("E8:13:6E:FB:77:BF") == "Example Networks"
    assert db.lookup("cc:f4:11:c6:29:11") == "Example Mobile"
    assert db.entry_count() == 2
    assert db.last_updated() == "2026-10-18T12:00:00"


def test_unknown_prefix_after_import_is_still_empty(db):
    db.replace_all([("E8136E", "Example Networks")], updated_at="now")
    assert db.lookup("AA:BB:CC:00:00:00") == ""


def test_replace_all_fully_replaces_previous_contents(db):
    db.replace_all([("AAAAAA", "Old Vendor")], updated_at="t1")
    db.replace_all([("BBBBBB", "New Vendor")], updated_at="t2")
    assert db.lookup("AA:AA:AA:00:00:00") == ""
    assert db.lookup("BB:BB:BB:00:00:00") == "New Vendor"
    assert db.entry_count() == 1


def test_replace_all_skips_rows_with_blank_vendor_or_bad_prefix(db):
    count = db.replace_all(
        [("E8136E", ""), ("", "No Prefix Co"), ("BAD", "Too Short"), ("CCF411", "Good Co")],
        updated_at="now",
    )
    assert count == 1
    assert db.lookup("CC:F4:11:00:00:00") == "Good Co"


def test_data_persists_across_separate_connections(tmp_path):
    path = tmp_path / "vendor.sqlite"
    first = VendorDB(path)
    first.replace_all([("E8136E", "Example Networks")], updated_at="now")
    first.close()

    second = VendorDB(path)
    try:
        assert second.lookup("E8:13:6E:00:00:00") == "Example Networks"
        assert second.entry_count() == 1
    finally:
        second.close()


def test_default_db_path_is_under_application_support():
    from pinginfoview.fileio.vendor_db import default_db_path
    path = default_db_path()
    assert "Application Support" in str(path)
    assert path.name == "vendor.sqlite"
    assert path.parent.name == "PingInfoView"
