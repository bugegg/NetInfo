#!/bin/bash
# Build a self-contained dist/NetInfoView.app (Python and PyQt6 bundled), to
# copy onto Macs that have no Python. It runs only on the CPU type it was
# built on (arm64 here: Apple Silicon); build on an Intel Mac for Intel.
#
#   ./build_app.sh            # needs .venv with requirements-build.txt
set -euo pipefail
cd "$(dirname "$0")"

# The version lives in NetInfoView/__init__.py; the release workflow sets it
# from the git tag before building.
VERSION=$(sed -n 's/^__version__ = "\(.*\)"$/\1/p' NetInfoView/__init__.py)
[ -n "$VERSION" ] || { echo "No __version__ in NetInfoView/__init__.py" >&2; exit 1; }

rm -rf build dist
.venv/bin/pyinstaller \
    --noconfirm \
    --windowed \
    --paths . \
    --name NetInfoView \
    --icon NetInfoView.app/Contents/Resources/AppIcon.icns \
    --osx-bundle-identifier net.local.NetInfoView \
    --exclude-module tkinter \
    --exclude-module pytest \
    --add-data NetInfoView/fonts:NetInfoView/fonts \
    --add-data NetInfoView/flags:NetInfoView/flags \
    packaging/launch.py

PLIST=dist/NetInfoView.app/Contents/Info.plist
/usr/libexec/PlistBuddy -c "Set :CFBundleShortVersionString $VERSION" "$PLIST"
/usr/libexec/PlistBuddy -c "Set :CFBundleVersion $VERSION" "$PLIST" 2>/dev/null \
    || /usr/libexec/PlistBuddy -c "Add :CFBundleVersion string $VERSION" "$PLIST"
/usr/libexec/PlistBuddy -c "Add :LSApplicationCategoryType string public.app-category.utilities" "$PLIST"

# Ad-hoc sign the whole bundle so Apple Silicon will run it at all.
codesign --force --deep --sign - dist/NetInfoView.app

# A zip keeps the bundle's symlinks and permissions intact for copying.
ditto -c -k --keepParent dist/NetInfoView.app "dist/NetInfoView-$VERSION-$(uname -m).zip"
# dist/NetInfoView is PyInstaller's unbundled copy; only the .app is needed.
rm -rf build NetInfoView.spec dist/NetInfoView
echo "Built dist/NetInfoView.app and dist/NetInfoView-$VERSION-$(uname -m).zip"
