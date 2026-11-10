"""Fetches a fresh MAC vendor database for VendorDB.

Two sources, each the other's fallback:

* **GitHub**: .github/workflows/vendor-db.yml builds the database from the
  IEEE registries once a month and publishes it on the ``oui-db``
  release as ``vendor.sqlite.gz`` (about 1 MB), next to a small
  ``vendor-db.json`` saying when it was built, how many entries it holds
  and its SHA-256. The manifest is read first, so a copy that isn't newer
  than the local one is never downloaded. GitHub is fast and doesn't turn
  away automated clients, so the monthly automatic check goes here.
* **IEEE**: the three registries themselves (MA-L, MA-M and MA-S CSVs,
  several MB). Always current, so Update MAC Vendor Database goes here.

Kept free of Qt so it's testable without an event loop;
ui/vendor_update_thread.py runs update() in a QThread.
"""

from __future__ import annotations

import csv
import gzip
import hashlib
import io
import json
import sqlite3
import tempfile
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path

from .. import __version__
from ..https import urlopen

IEEE_OUI_CSV_URL = "https://standards-oui.ieee.org/oui/oui.csv"
IEEE_MAM_CSV_URL = "https://standards-oui.ieee.org/oui28/mam.csv"
IEEE_OUI36_CSV_URL = "https://standards-oui.ieee.org/oui36/oui36.csv"
#: MA-L, MA-M, MA-S: all three are needed, or vendors from the smaller
#: blocks would drop out of the table.
IEEE_CSV_URLS = (IEEE_OUI_CSV_URL, IEEE_MAM_CSV_URL, IEEE_OUI36_CSV_URL)

GITHUB_RELEASE_URL = "https://github.com/bugegg/NetInfo/releases/download/oui-db"
GITHUB_MANIFEST_URL = f"{GITHUB_RELEASE_URL}/vendor-db.json"
GITHUB_DB_URL = f"{GITHUB_RELEASE_URL}/vendor.sqlite.gz"

#: Fewer entries than this means a truncated or broken download (MA-L alone
#: holds well over 30,000), and the table in use is kept instead.
MIN_ENTRIES = 30000
#: How long between automatic checks.
AUTO_CHECK_DAYS = 30
#: VendorDB meta key for when the last automatic check succeeded.
LAST_CHECKED_KEY = "last_checked"

_REQUEST_TIMEOUT_SECONDS = 30
_USER_AGENT = f"NetInfoView/{__version__}"


class VendorUpdateError(Exception):
    """Raised when no source could be fetched, or what came back is unusable."""


def _fetch(url: str) -> bytes:
    request = urllib.request.Request(url, headers={"User-Agent": _USER_AGENT})
    try:
        with urlopen(request, timeout=_REQUEST_TIMEOUT_SECONDS) as response:
            return response.read()
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        raise VendorUpdateError(f"Could not reach {url}: {exc}") from exc


# -- IEEE ------------------------------------------------------------------


def fetch_oui_csv(url: str = IEEE_OUI_CSV_URL) -> str:
    return _fetch(url).decode("utf-8", errors="replace")


def parse_oui_csv(text: str) -> list[tuple[str, str]]:
    """IEEE's CSV columns are Registry, Assignment, Organization Name,
    Organization Address, the same for MA-L, MA-M and MA-S."""
    reader = csv.DictReader(io.StringIO(text))
    if reader.fieldnames is None or "Assignment" not in reader.fieldnames:
        raise VendorUpdateError("Unexpected format from the IEEE OUI registry.")
    rows: list[tuple[str, str]] = []
    for record in reader:
        prefix = (record.get("Assignment") or "").strip()
        vendor = (record.get("Organization Name") or "").strip()
        if prefix and vendor:
            rows.append((prefix, vendor))
    if not rows:
        raise VendorUpdateError("The IEEE OUI registry returned no usable rows.")
    return rows


def run_update(
    vendor_db, urls: tuple[str, ...] = IEEE_CSV_URLS, min_entries: int | None = None
) -> int:
    """Fetch, parse and store all the IEEE registries. Returns the number
    of entries stored. The table in use is left alone unless every registry
    arrived and there are at least `min_entries` rows between them."""
    rows: list[tuple[str, str]] = []
    for url in urls:
        rows += parse_oui_csv(fetch_oui_csv(url))
    minimum = MIN_ENTRIES if min_entries is None else min_entries
    if len(rows) < minimum:
        raise VendorUpdateError(
            f"The IEEE registries held only {len(rows):,} entries; "
            "keeping the current database."
        )
    timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
    return vendor_db.replace_all(rows, updated_at=timestamp)


# -- GitHub ----------------------------------------------------------------


@dataclass(frozen=True)
class Manifest:
    updated: str
    entries: int
    sha256: str


def fetch_manifest(url: str = GITHUB_MANIFEST_URL) -> Manifest:
    try:
        data = json.loads(_fetch(url))
        return Manifest(str(data["updated"]), int(data["entries"]), str(data["sha256"]).lower())
    except (ValueError, KeyError, TypeError) as exc:
        raise VendorUpdateError(f"Unexpected vendor database manifest: {exc}") from exc


def run_github_update(
    vendor_db,
    manifest_url: str = GITHUB_MANIFEST_URL,
    db_url: str = GITHUB_DB_URL,
    min_entries: int | None = None,
) -> int:
    """Download the GitHub copy if it's newer than the local one. Returns
    the number of entries now held, or 0 if the local one is already as new."""
    minimum = MIN_ENTRIES if min_entries is None else min_entries
    manifest = fetch_manifest(manifest_url)
    if vendor_db.entry_count() and (vendor_db.last_updated() or "") >= manifest.updated:
        return 0
    if manifest.entries < minimum:
        raise VendorUpdateError("The published vendor database is too small; not using it.")
    packed = _fetch(db_url)
    if hashlib.sha256(packed).hexdigest() != manifest.sha256:
        raise VendorUpdateError("The downloaded vendor database doesn't match its checksum.")
    try:
        raw = gzip.decompress(packed)
    except (OSError, EOFError) as exc:
        raise VendorUpdateError(f"The downloaded vendor database is corrupt: {exc}") from exc
    with tempfile.TemporaryDirectory() as folder:
        path = Path(folder) / "vendor.sqlite"
        path.write_bytes(raw)
        try:
            count = vendor_db.import_from(path, min_entries=minimum)
        except sqlite3.Error as exc:
            raise VendorUpdateError(
                f"The downloaded vendor database is unreadable: {exc}"
            ) from exc
    if not count:
        raise VendorUpdateError("The downloaded vendor database is too small; not using it.")
    return count


# -- either ----------------------------------------------------------------


def update(vendor_db, prefer_github: bool) -> int:
    """Update from the preferred source, falling back to the other one.
    Returns the entry count now held (0: already up to date). Raises
    VendorUpdateError naming both failures if neither worked."""
    sources = (run_github_update, run_update) if prefer_github else (run_update, run_github_update)
    errors = []
    for source in sources:
        try:
            return source(vendor_db)
        except VendorUpdateError as exc:
            errors.append(str(exc))
    raise VendorUpdateError("\n".join(errors))


def auto_check_due(vendor_db, now: float | None = None) -> bool:
    """True once AUTO_CHECK_DAYS have passed since the last automatic check
    (or there's never been one)."""
    last = vendor_db.get_meta(LAST_CHECKED_KEY)
    try:
        last_time = float(last) if last else 0.0
    except ValueError:
        last_time = 0.0
    now = time.time() if now is None else now
    return now - last_time >= AUTO_CHECK_DAYS * 86400


def mark_checked(vendor_db, now: float | None = None) -> None:
    vendor_db.set_meta(LAST_CHECKED_KEY, str(time.time() if now is None else now))
