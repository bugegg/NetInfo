"""Local, persistent MAC-vendor (IEEE OUI) lookup.

Deliberately starts empty: there is no bundled seed list, so a lookup returns
"" until the user explicitly runs Options > Update MAC Vendor Database. That
keeps the data's freshness honest, and the whole point of persisting it in
SQLite under Application Support is that this fetch only has to happen once.
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


def normalise_prefix(mac: str) -> str:
    """The first 3 octets of a MAC as 6 uppercase hex digits, no separators.

    Accepts any of the forms the app sees a MAC in: ``E8:13:6E:FB:77:BF``,
    ``e8-13-6e-...``, or already-bare ``E8136E...``. Returns "" if there
    aren't even 6 hex digits to take from.
    """
    hex_digits = "".join(ch for ch in mac if ch in "0123456789abcdefABCDEF")
    return hex_digits[:6].upper() if len(hex_digits) >= 6 else ""


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
        prefix = normalise_prefix(mac)
        if not prefix:
            return ""
        with self._lock:
            row = self._conn.execute(
                "SELECT vendor FROM oui WHERE prefix = ?", (prefix,)
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

    def replace_all(self, rows: Iterable[tuple[str, str]], updated_at: str) -> int:
        """Swap in a fresh OUI table in one transaction. Returns the row count.

        Rows with an unparseable prefix are skipped rather than raising, since
        the IEEE feed is third-party data and nothing here should let one bad
        line abort an otherwise-good import.
        """
        clean = [
            (normalise_prefix(prefix), vendor.strip())
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
