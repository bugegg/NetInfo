"""Build-time: download the IEEE OUI registry into a ready-made vendor.sqlite
that the build scripts bundle into the app, so a fresh install has MAC vendor
names from its first launch without going online (VendorDB.seed_from).

    python packaging/make_vendor_db.py build/vendor/vendor.sqlite

Exits 1 if the registry can't be fetched; the build scripts then carry on
without it (Options > Update MAC Vendor Database still fetches one).
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from NetInfoView.fileio.vendor_db import VendorDB  # noqa: E402
from NetInfoView.ping.vendor_update import VendorUpdateError, run_update  # noqa: E402


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print(f"usage: {argv[0]} OUTPUT.sqlite", file=sys.stderr)
        return 2
    out = Path(argv[1])
    out.unlink(missing_ok=True)
    out.parent.mkdir(parents=True, exist_ok=True)
    db = VendorDB(out)
    try:
        count = run_update(db)
    except VendorUpdateError as exc:
        db.close()
        out.unlink(missing_ok=True)
        print(f"warning: no bundled MAC vendor database: {exc}", file=sys.stderr)
        return 1
    with db._lock:
        db._conn.execute("VACUUM")
    db.close()
    print(f"Wrote {out} ({count:,} entries)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
