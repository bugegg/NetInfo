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
    count = run_update(FakeVendorDB(), urls=("only-one",), min_entries=0)
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


# -- MA-M/MA-S, the size check, GitHub and the monthly check ------------------

MAM_CSV = (
    "Registry,Assignment,Organization Name,Organization Address\n"
    "MA-M,8C1F64A,Small Camera Co,1 Lens Rd\n"
)
OUI36_CSV = (
    "Registry,Assignment,Organization Name,Organization Address\n"
    "MA-S,70B3D5123,Tiny Sensor Ltd,2 Probe St\n"
)


@pytest.fixture
def vendor_db(tmp_path):
    from NetInfoView.fileio.vendor_db import VendorDB

    db = VendorDB(tmp_path / "local.sqlite")
    yield db
    db.close()


def test_run_update_takes_all_three_registries(monkeypatch, vendor_db):
    from NetInfoView.ping import vendor_update

    by_url = {
        vendor_update.IEEE_OUI_CSV_URL: SAMPLE_CSV,
        vendor_update.IEEE_MAM_CSV_URL: MAM_CSV,
        vendor_update.IEEE_OUI36_CSV_URL: OUI36_CSV,
    }
    monkeypatch.setattr(vendor_update, "fetch_oui_csv", lambda url: by_url[url])
    assert run_update(vendor_db, min_entries=0) == 4
    assert vendor_db.lookup("8C:1F:64:A0:00:01") == "Small Camera Co"
    assert vendor_db.lookup("70:B3:D5:12:34:56") == "Tiny Sensor Ltd"


def test_run_update_keeps_the_table_when_too_few_rows_arrive(monkeypatch, vendor_db):
    from NetInfoView.ping import vendor_update

    vendor_db.replace_all([("E8136E", "Kept Co")], updated_at="t1")
    monkeypatch.setattr(vendor_update, "fetch_oui_csv", lambda url: SAMPLE_CSV)
    with pytest.raises(VendorUpdateError):
        run_update(vendor_db)  # 6 rows, far under MIN_ENTRIES
    assert vendor_db.lookup("E8136E") == "Kept Co"


def _published(tmp_path, rows, updated):
    """A vendor database as the vendor-db workflow publishes it."""
    import gzip
    import hashlib
    import json

    from NetInfoView.fileio.vendor_db import VendorDB

    path = tmp_path / "published.sqlite"
    path.unlink(missing_ok=True)
    db = VendorDB(path)
    db.replace_all(rows, updated_at=updated)
    db.close()
    packed = gzip.compress(path.read_bytes())
    manifest = json.dumps({
        "updated": updated, "entries": len(rows),
        "sha256": hashlib.sha256(packed).hexdigest(),
    }).encode()
    return {"manifest": manifest, "db": packed}


def _serve(monkeypatch, files):
    from NetInfoView.ping import vendor_update

    fetched = []

    def fetch(url):
        fetched.append(url)
        if url == vendor_update.GITHUB_MANIFEST_URL:
            return files["manifest"]
        if url == vendor_update.GITHUB_DB_URL:
            return files["db"]
        raise VendorUpdateError(f"no {url}")

    monkeypatch.setattr(vendor_update, "_fetch", fetch)
    return fetched


def test_github_update_imports_a_newer_copy(monkeypatch, tmp_path, vendor_db):
    from NetInfoView.ping.vendor_update import run_github_update

    vendor_db.replace_all([("E8136E", "Old Name")], updated_at="2026-01-01 00:00:00")
    _serve(monkeypatch, _published(tmp_path, [("E8136E", "New Name"), ("CCF411", "B")],
                                   "2026-11-01 03:17:00"))
    assert run_github_update(vendor_db, min_entries=0) == 2
    assert vendor_db.lookup("E8136E") == "New Name"
    assert vendor_db.last_updated() == "2026-11-01 03:17:00"


def test_github_update_skips_the_download_when_not_newer(monkeypatch, tmp_path, vendor_db):
    from NetInfoView.ping import vendor_update

    vendor_db.replace_all([("E8136E", "Mine")], updated_at="2026-11-05 00:00:00")
    fetched = _serve(monkeypatch, _published(tmp_path, [("E8136E", "Theirs")],
                                             "2026-11-01 03:17:00"))
    assert vendor_update.run_github_update(vendor_db, min_entries=0) == 0
    assert fetched == [vendor_update.GITHUB_MANIFEST_URL]
    assert vendor_db.lookup("E8136E") == "Mine"


def test_github_update_rejects_a_checksum_mismatch(monkeypatch, tmp_path, vendor_db):
    from NetInfoView.ping.vendor_update import run_github_update

    files = _published(tmp_path, [("E8136E", "Theirs")], "2026-11-01 03:17:00")
    files["db"] = files["db"][:-4] + b"oops"
    _serve(monkeypatch, files)
    with pytest.raises(VendorUpdateError):
        run_github_update(vendor_db, min_entries=0)
    assert vendor_db.entry_count() == 0


def test_update_falls_back_to_the_other_source(monkeypatch, vendor_db):
    from NetInfoView.ping import vendor_update

    calls = []

    def github(db):
        calls.append("github")
        raise VendorUpdateError("GitHub down")

    def ieee(db):
        calls.append("ieee")
        return 7

    monkeypatch.setattr(vendor_update, "run_github_update", github)
    monkeypatch.setattr(vendor_update, "run_update", ieee)
    assert vendor_update.update(vendor_db, prefer_github=True) == 7
    assert calls == ["github", "ieee"]
    calls.clear()
    assert vendor_update.update(vendor_db, prefer_github=False) == 7
    assert calls == ["ieee"]


def test_auto_check_is_due_monthly(vendor_db):
    from NetInfoView.ping.vendor_update import AUTO_CHECK_DAYS, auto_check_due, mark_checked

    assert auto_check_due(vendor_db, now=1_000_000_000)
    mark_checked(vendor_db, now=1_000_000_000)
    assert not auto_check_due(vendor_db, now=1_000_000_000 + 86400)
    assert auto_check_due(vendor_db, now=1_000_000_000 + AUTO_CHECK_DAYS * 86400)
