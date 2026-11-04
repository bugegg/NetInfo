"""Fetches the IEEE MA-L (OUI) registry and parses it for VendorDB.replace_all.

Kept network-call and parsing logic separate from Qt so it's testable without
a running event loop; ui/main_window.py wraps run_update() in a QThread.
"""

from __future__ import annotations

import csv
import io
import time
import urllib.error
import urllib.request

from .. import __version__

IEEE_OUI_CSV_URL = "https://standards-oui.ieee.org/oui/oui.csv"
_REQUEST_TIMEOUT_SECONDS = 30


class VendorUpdateError(Exception):
    """Raised when the IEEE registry can't be fetched or doesn't parse."""


def fetch_oui_csv(url: str = IEEE_OUI_CSV_URL) -> str:
    request = urllib.request.Request(url, headers={"User-Agent": f"NetInfo/{__version__}"})
    try:
        with urllib.request.urlopen(request, timeout=_REQUEST_TIMEOUT_SECONDS) as response:
            return response.read().decode("utf-8", errors="replace")
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        raise VendorUpdateError(f"Could not reach the IEEE OUI registry: {exc}") from exc


def parse_oui_csv(text: str) -> list[tuple[str, str]]:
    """IEEE's CSV columns are Registry, Assignment, Organization Name, Organization Address."""
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


def run_update(vendor_db, url: str = IEEE_OUI_CSV_URL) -> int:
    """Fetch, parse and store the registry. Returns the number of entries stored."""
    rows = parse_oui_csv(fetch_oui_csv(url))
    timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
    return vendor_db.replace_all(rows, updated_at=timestamp)
