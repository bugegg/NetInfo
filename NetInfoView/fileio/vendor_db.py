"""Local, persistent MAC-vendor (IEEE OUI) lookup.

Holds all three IEEE MAC registries: MA-L (24-bit prefixes, 6 hex digits),
MA-M (28-bit, 7) and MA-S (36-bit, 9). A MAC is looked up by its longest
matching prefix, so a camera from a small maker whose block was carved out
of an MA-L one reads as that maker, not "IEEE Registration Authority".

A release build bundles a copy taken on the day it was built
(packaging/make_vendor_db.py); at launch it replaces the local database
when it is newer (VendorDB.seed_from), so updating the app updates the
vendor names too. Between releases ping/vendor_update.py fetches a fresh
copy: by itself once a month, or from Update MAC Vendor Database.
"""

from __future__ import annotations

import os
import re
import shutil
import sqlite3
import threading
from collections.abc import Iterable
from pathlib import Path

from ..osinfo import IS_WINDOWS
from ..settings import APPLICATION, LEGACY_APPLICATION

_HEX_PREFIX = re.compile(r"[0-9A-Fa-f]{6,}")

_SCHEMA = """
CREATE TABLE IF NOT EXISTS oui (
    prefix TEXT PRIMARY KEY,
    vendor TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS meta (
    key TEXT PRIMARY KEY,
    value TEXT
);
"""


#: Shown in the Vendor column for a locally-administered MAC (e.g. an iOS,
#: macOS or Android device's "Private Wi-Fi address") instead of leaving it
#: blank — there's a real reason no vendor was found, not just an
#: out-of-date or not-yet-downloaded database. See ping.arp.is_locally_administered.
PRIVATE_MAC_LABEL = "(Private/Randomized MAC)"


def _app_data_dir() -> Path:
    if IS_WINDOWS:
        return Path(os.environ.get("APPDATA") or Path.home() / "AppData" / "Roaming")
    return Path.home() / "Library" / "Application Support"


def default_db_path() -> Path:
    """``~/Library/Application Support/NetInfoView/vendor.sqlite`` on macOS,
    ``%APPDATA%\\NetInfoView\\vendor.sqlite`` on Windows."""
    return _app_data_dir() / APPLICATION / "vendor.sqlite"


def legacy_db_path() -> Path:
    """Where releases up to 1.4 kept it, under the old PingInfoView name."""
    return _app_data_dir() / LEGACY_APPLICATION / "vendor.sqlite"


def migrate_legacy_db(dest: Path | None = None, legacy: Path | None = None) -> bool:
    """Copy the vendor database from the old location if there's none at
    the new one yet. The old file is kept for older builds. Returns True
    if it copied; never raises (worst case, the user re-downloads it)."""
    dest = dest or default_db_path()
    legacy = legacy or legacy_db_path()
    if dest.exists() or not legacy.is_file():
        return False
    try:
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(legacy, dest)
    except OSError:
        return False
    return True


def bundled_db_path() -> Path:
    """Where the build scripts put the ready-made database inside the app."""
    return Path(__file__).resolve().parent.parent / "data" / "vendor.sqlite"


def normalise_prefix(mac: str) -> str:
    """The first 3 octets of a MAC as 6 uppercase hex digits, no separators.

    Accepts any of the forms the app sees a MAC in: ``E8:13:6E:FB:77:BF``,
    ``e8-13-6e-...``, or already-bare ``E8136E...``. Returns "" if there
    aren't even 6 hex digits to take from.
    """
    hex_digits = "".join(ch for ch in mac if ch in "0123456789abcdefABCDEF")
    return hex_digits[:6].upper() if len(hex_digits) >= 6 else ""


#: Hex digits in an MA-S, MA-M and MA-L assignment, longest first.
PREFIX_LENGTHS = (9, 7, 6)


def normalise_assignment(prefix: str) -> str:
    """An IEEE assignment as bare uppercase hex: 6, 7 or 9 digits for
    MA-L, MA-M or MA-S. "" for anything else."""
    hex_digits = "".join(ch for ch in prefix if ch in "0123456789abcdefABCDEF").upper()
    return hex_digits if len(hex_digits) in PREFIX_LENGTHS else ""


class VendorDB:
    """One SQLite-backed table mapping an OUI prefix to a vendor name.

    The GUI thread polls lookup() on a timer while a background thread may be
    running replace_all() during Update MAC Vendor Database, both through this
    same connection — a lock serialises them so that overlap can't surface as
    an "OperationalError: database is locked" mid-update.
    """

    def __init__(self, path: Path | None = None) -> None:
        self.path = path or default_db_path()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._conn = sqlite3.connect(self.path, check_same_thread=False)
        with self._lock:
            self._conn.executescript(_SCHEMA)
            self._conn.commit()

    def close(self) -> None:
        with self._lock:
            self._conn.close()

    # -- reads ---------------------------------------------------------

    def lookup(self, mac: str) -> str:
        """The vendor for ``mac``'s OUI prefix, or "" if unknown/not downloaded yet."""
        hex_digits = "".join(ch for ch in mac if ch in "0123456789abcdefABCDEF").upper()
        prefixes = [hex_digits[:n] for n in PREFIX_LENGTHS if len(hex_digits) >= n]
        if not prefixes:
            return ""
        with self._lock:
            row = self._conn.execute(
                "SELECT vendor FROM oui WHERE prefix IN (%s)"
                " ORDER BY length(prefix) DESC LIMIT 1" % ",".join("?" * len(prefixes)),
                prefixes,
            ).fetchone()
        return row[0] if row else ""

    def entry_count(self) -> int:
        with self._lock:
            return self._conn.execute("SELECT COUNT(*) FROM oui").fetchone()[0]

    def last_updated(self) -> str | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT value FROM meta WHERE key = 'last_updated'"
            ).fetchone()
        return row[0] if row else None

    # -- writes ----------------------------------------------------------

    def get_meta(self, key: str) -> str | None:
        with self._lock:
            row = self._conn.execute("SELECT value FROM meta WHERE key = ?", (key,)).fetchone()
        return row[0] if row else None

    def set_meta(self, key: str, value: str) -> None:
        with self._lock, self._conn:
            self._conn.execute(
                "INSERT OR REPLACE INTO meta (key, value) VALUES (?, ?)", (key, value)
            )

    def seed_from(self, bundled: Path | None = None) -> int:
        """Take the database bundled with the app when this one is empty or
        older than it (the app was just updated, say).

        Returns the number of entries copied: 0 if this one is at least as
        new or there's no usable bundled copy. Never raises; worst case the
        registry is downloaded instead.
        """
        bundled = bundled or bundled_db_path()
        if not bundled.is_file():
            return 0
        try:
            return self.import_from(bundled, only_if_newer=bool(self.entry_count()))
        except sqlite3.Error:
            return 0

    def import_from(self, path: Path, only_if_newer: bool = False, min_entries: int = 1) -> int:
        """Replace the table with the one in another vendor database file
        (the bundled copy, or one downloaded from GitHub), in one transaction.

        Returns the number of entries now held, or 0 if nothing changed:
        `only_if_newer` and that file isn't newer, or it holds fewer than
        `min_entries` (a broken download must not wipe a good table).
        Raises sqlite3.Error if the file isn't a vendor database.
        """
        with self._lock:
            self._conn.execute("ATTACH DATABASE ? AS other", (str(path),))
            try:
                row = self._conn.execute(
                    "SELECT value FROM other.meta WHERE key = 'last_updated'"
                ).fetchone()
                theirs = row[0] if row else ""
                if only_if_newer:
                    row = self._conn.execute(
                        "SELECT value FROM meta WHERE key = 'last_updated'"
                    ).fetchone()
                    if not theirs or (row and row[0] >= theirs):
                        return 0
                count = self._conn.execute("SELECT COUNT(*) FROM other.oui").fetchone()[0]
                if count < max(1, min_entries):
                    return 0
                with self._conn:
                    self._conn.execute("DELETE FROM oui")
                    self._conn.execute(
                        "INSERT OR REPLACE INTO oui SELECT prefix, vendor FROM other.oui"
                    )
                    self._conn.execute(
                        "INSERT OR REPLACE INTO meta (key, value) VALUES ('last_updated', ?)",
                        (theirs,),
                    )
            finally:
                self._conn.execute("DETACH DATABASE other")
        return self.entry_count()

    def replace_all(self, rows: Iterable[tuple[str, str]], updated_at: str) -> int:
        """Swap in a fresh OUI table in one transaction. Returns the row count.

        Rows with an unparseable prefix are skipped rather than raising, since
        the IEEE feed is third-party data and nothing here should let one bad
        line abort an otherwise-good import.
        """
        clean = [
            (normalise_assignment(prefix), vendor.strip())
            for prefix, vendor in rows
            if vendor and vendor.strip()
        ]
        clean = [(prefix, vendor) for prefix, vendor in clean if prefix]

        with self._lock, self._conn:
            self._conn.execute("DELETE FROM oui")
            self._conn.executemany(
                "INSERT OR REPLACE INTO oui (prefix, vendor) VALUES (?, ?)", clean
            )
            self._conn.execute(
                "INSERT OR REPLACE INTO meta (key, value) VALUES ('last_updated', ?)",
                (updated_at,),
            )
        return len(clean)
