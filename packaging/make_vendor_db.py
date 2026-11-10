"""Build a ready-made vendor.sqlite from the IEEE registries (MA-L, MA-M and
MA-S), for two uses:

* The build scripts bundle it into the app, so a fresh install has MAC
  vendor names from its first launch without going online, and an updated
  one replaces an older local copy (VendorDB.seed_from):

      python packaging/make_vendor_db.py build/vendor/vendor.sqlite

* .github/workflows/vendor-db.yml publishes it monthly on the ``oui-db``
  release for installed copies to fetch (ping/vendor_update.py). ``--publish``
  also writes vendor.sqlite.gz and its manifest, vendor-db.json, beside it:

      python packaging/make_vendor_db.py --publish out/vendor.sqlite

Exits 1 if the registries can't be fetched; the build scripts then carry on
without it (Update MAC Vendor Database still fetches one).
"""

import gzip
import hashlib
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from NetInfoView.fileio.vendor_db import VendorDB  # noqa: E402
from NetInfoView.ping.vendor_update import VendorUpdateError, run_update  # noqa: E402


def publish(out: Path, count: int, updated: str) -> None:
    """vendor.sqlite.gz and vendor-db.json next to `out`."""
    packed = gzip.compress(out.read_bytes(), mtime=0)
    (out.parent / "vendor.sqlite.gz").write_bytes(packed)
    manifest = {
        "updated": updated,
        "entries": count,
        "sha256": hashlib.sha256(packed).hexdigest(),
    }
    (out.parent / "vendor-db.json").write_text(json.dumps(manifest, indent=2) + "\n")
    print(f"Wrote {out.parent / 'vendor.sqlite.gz'} ({len(packed):,} bytes) and vendor-db.json")


def main(argv: list[str]) -> int:
    args = argv[1:]
    publishing = "--publish" in args
    args = [a for a in args if a != "--publish"]
    if len(args) != 1:
        print(f"usage: {argv[0]} [--publish] OUTPUT.sqlite", file=sys.stderr)
        return 2
    out = Path(args[0])
    out.unlink(missing_ok=True)
    out.parent.mkdir(parents=True, exist_ok=True)
    db = VendorDB(out)
    try:
        count = run_update(db)
    except VendorUpdateError as exc:
        db.close()
        out.unlink(missing_ok=True)
        print(f"warning: no MAC vendor database: {exc}", file=sys.stderr)
        return 1
    updated = db.last_updated() or ""
    with db._lock:
        db._conn.execute("VACUUM")
    db.close()
    print(f"Wrote {out} ({count:,} entries)")
    if publishing:
        publish(out, count, updated)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
