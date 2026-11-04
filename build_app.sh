#!/bin/bash
# Build a self-contained dist/NetInfo.app (Python and PyQt6 bundled), to
# copy onto Macs that have no Python. It runs only on the CPU type it was
# built on (arm64 here: Apple Silicon); build on an Intel Mac for Intel.
#
#   ./build_app.sh            # needs .venv with requirements-build.txt
set -euo pipefail
cd "$(dirname "$0")"

# The version lives in pinginfoview/__init__.py; the release workflow sets it
# from the git tag before building.
VERSION=$(sed -n 's/^__version__ = "\(.*\)"$/\1/p' pinginfoview/__init__.py)
[ -n "$VERSION" ] || { echo "No __version__ in pinginfoview/__init__.py" >&2; exit 1; }

rm -rf build dist
.venv/bin/pyinstaller \
    --noconfirm \
    --windowed \
    --paths . \
    --name NetInfo \
    --icon NetInfo.app/Contents/Resources/AppIcon.icns \
    --osx-bundle-identifier net.local.pinginfoview \
    --exclude-module tkinter \
    --exclude-module pytest \
    packaging/launch.py

PLIST=dist/NetInfo.app/Contents/Info.plist
/usr/libexec/PlistBuddy -c "Set :CFBundleShortVersionString $VERSION" "$PLIST"
/usr/libexec/PlistBuddy -c "Set :CFBundleVersion $VERSION" "$PLIST" 2>/dev/null \
    || /usr/libexec/PlistBuddy -c "Add :CFBundleVersion string $VERSION" "$PLIST"
/usr/libexec/PlistBuddy -c "Add :LSApplicationCategoryType string public.app-category.utilities" "$PLIST"

# Ad-hoc sign the whole bundle so Apple Silicon will run it at all.
codesign --force --deep --sign - dist/NetInfo.app

# A zip keeps the bundle's symlinks and permissions intact for copying.
ditto -c -k --keepParent dist/NetInfo.app "dist/NetInfo-$VERSION-$(uname -m).zip"
# dist/NetInfo is PyInstaller's unbundled copy; only the .app is needed.
rm -rf build NetInfo.spec dist/NetInfo
echo "Built dist/NetInfo.app and dist/NetInfo-$VERSION-$(uname -m).zip"
