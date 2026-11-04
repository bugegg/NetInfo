"""Self-update from GitHub Releases.

Each release (built by .github/workflows/release.yml) carries a zip of the
macOS .app per CPU type, named ``NetInfo-<version>-<arch>.zip``, and a
Windows installer, ``NetInfo-<version>-windows-x64-setup.exe``. This module
finds the newest release and downloads the file for this computer. Kept free
of Qt so it's testable without an event loop; ui/app_update_thread.py runs it
off the GUI thread.

Neither OS lets the running app replace itself, so install_update() hands
the swap to another process and the caller then quits: on macOS a small
detached shell script that waits for this process to exit, replaces the
bundle and opens the new one; on Windows the installer itself, run silently,
which closes the app, installs over it and starts it again.
"""

from __future__ import annotations

import json
import os
import platform
import re
import shlex
import subprocess
import sys
import tempfile
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path

from . import __version__
from .osinfo import IS_WINDOWS

#: ``owner/name`` of the public GitHub repository that publishes releases.
GITHUB_REPO = "bugegg/NetInfo"
LATEST_RELEASE_URL = f"https://api.github.com/repos/{GITHUB_REPO}/releases/latest"
_REQUEST_TIMEOUT_SECONDS = 30
_USER_AGENT = f"NetInfo/{__version__}"


class AppUpdateError(Exception):
    """Raised when a release can't be fetched, downloaded or installed."""


@dataclass(frozen=True)
class Release:
    version: str
    notes: str
    page_url: str
    #: Download URL of this computer's zip/installer, or "" if there's none.
    asset_url: str


def parse_version(text: str) -> tuple[int, ...]:
    """``"v1.10.2"`` -> ``(1, 10, 2)``; trailing zeros dropped so 1.0 == 1."""
    numbers = re.findall(r"\d+", text.strip().lstrip("vV").split("-")[0])
    if not numbers:
        raise AppUpdateError(f"Not a version number: {text!r}")
    parts = [int(n) for n in numbers]
    while len(parts) > 1 and parts[-1] == 0:
        parts.pop()
    return tuple(parts)


def is_newer(remote: str, local: str = __version__) -> bool:
    return parse_version(remote) > parse_version(local)


#: The one Windows build: 64-bit Intel/AMD (it also runs on Windows on Arm).
WINDOWS_ASSET_SUFFIX = "-windows-x64-setup.exe"


def _asset_suffix(machine: str | None = None, windows: bool | None = None) -> str:
    if IS_WINDOWS if windows is None else windows:
        return WINDOWS_ASSET_SUFFIX
    return f"-{machine or platform.machine()}.zip"


def parse_release(
    data: dict, machine: str | None = None, windows: bool | None = None
) -> Release:
    """Pick out what the updater needs from the GitHub API's release JSON."""
    tag = data.get("tag_name") or ""
    if not tag:
        raise AppUpdateError("The latest release has no version tag.")
    suffix = _asset_suffix(machine, windows)
    asset_url = next(
        (
            asset.get("browser_download_url", "")
            for asset in data.get("assets") or []
            if str(asset.get("name", "")).endswith(suffix)
        ),
        "",
    )
    return Release(
        version=tag.lstrip("vV"),
        notes=data.get("body") or "",
        page_url=data.get("html_url") or f"https://github.com/{GITHUB_REPO}/releases",
        asset_url=asset_url,
    )


def fetch_latest_release(url: str = LATEST_RELEASE_URL) -> Release:
    request = urllib.request.Request(
        url,
        headers={"User-Agent": _USER_AGENT, "Accept": "application/vnd.github+json"},
    )
    try:
        with urllib.request.urlopen(request, timeout=_REQUEST_TIMEOUT_SECONDS) as response:
            data = json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            raise AppUpdateError("No release has been published yet.") from exc
        raise AppUpdateError(f"Could not check for updates: {exc}") from exc
    except (urllib.error.URLError, TimeoutError, OSError, ValueError) as exc:
        raise AppUpdateError(f"Could not check for updates: {exc}") from exc
    return parse_release(data)


def download(url: str, dest: Path) -> Path:
    request = urllib.request.Request(url, headers={"User-Agent": _USER_AGENT})
    try:
        with urllib.request.urlopen(request, timeout=_REQUEST_TIMEOUT_SECONDS) as response, \
                open(dest, "wb") as out:
            while chunk := response.read(1 << 16):
                out.write(chunk)
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        raise AppUpdateError(f"Could not download the update: {exc}") from exc
    return dest


def running_app_bundle() -> Path | None:
    """The .app this process runs from, or None when run from source (or on
    Windows)."""
    if IS_WINDOWS or not getattr(sys, "frozen", False):
        return None
    # .../NetInfo.app/Contents/MacOS/NetInfo
    bundle = Path(sys.executable).resolve().parents[2]
    return bundle if bundle.suffix == ".app" else None


def extract_app(zip_path: Path, dest_dir: Path) -> Path:
    """Unpack the release zip with ditto (zipfile would lose the bundle's
    symlinks and permissions) and return the .app inside it."""
    result = subprocess.run(
        ["/usr/bin/ditto", "-x", "-k", str(zip_path), str(dest_dir)],
        capture_output=True, text=True,
    )
    if result.returncode != 0:
        raise AppUpdateError(f"Could not unpack the update: {result.stderr.strip()}")
    apps = sorted(dest_dir.glob("*.app"))
    if not apps:
        raise AppUpdateError("The update didn't contain an app.")
    return apps[0]


def self_update_supported() -> bool:
    """True when this is an installed build that install_update() can replace."""
    if IS_WINDOWS:
        return bool(getattr(sys, "frozen", False))
    return running_app_bundle() is not None


def download_and_extract(release: Release) -> Path:
    """Fetch this computer's download from ``release`` into a temp dir and
    return what install_update() takes: the new .app, or the installer."""
    if not release.asset_url:
        raise AppUpdateError(
            f"Version {release.version} has no download for this computer "
            f"({platform.system()} {platform.machine()})."
        )
    work = Path(tempfile.mkdtemp(prefix="NetInfo-update-"))
    if IS_WINDOWS:
        return download(release.asset_url, work / release.asset_url.rsplit("/", 1)[-1])
    zip_path = download(release.asset_url, work / "update.zip")
    return extract_app(zip_path, work / "extracted")


def installer_script(new_app: Path, target_app: Path, pid: int) -> str:
    """Shell script that waits for ``pid`` to exit, swaps the bundle, relaunches.

    The old bundle is moved aside first and only deleted once the new one is
    in place, so a failed copy puts the old app back rather than leaving none.
    """
    new_q, target_q = shlex.quote(str(new_app)), shlex.quote(str(target_app))
    backup_q = shlex.quote(str(target_app) + ".old")
    return f"""#!/bin/bash
while kill -0 {pid} 2>/dev/null; do sleep 0.5; done
rm -rf {backup_q}
mv {target_q} {backup_q} || exit 1
if /usr/bin/ditto {new_q} {target_q}; then
    rm -rf {backup_q}
else
    rm -rf {target_q}
    mv {backup_q} {target_q}
fi
/usr/bin/xattr -dr com.apple.quarantine {target_q} 2>/dev/null
/usr/bin/open {target_q}
rm -rf {shlex.quote(str(new_app.parent.parent))}
"""


def install_and_relaunch(new_app: Path, target_app: Path) -> None:
    """Start the detached swap; the caller must then quit the app."""
    if not os.access(target_app.parent, os.W_OK):
        raise AppUpdateError(
            f"No permission to replace the app in {target_app.parent}."
        )
    script = Path(tempfile.mkstemp(prefix="NetInfo-install-", suffix=".sh")[1])
    script.write_text(installer_script(new_app, target_app, os.getpid()))
    script.chmod(0o700)
    subprocess.Popen(
        ["/bin/bash", str(script)],
        stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        start_new_session=True,
    )


#: Inno Setup switches: no wizard pages, close the running app for us, and
#: no reboot prompt. The installer's own [Run] entry restarts the app.
WINDOWS_INSTALLER_ARGS = ["/SILENT", "/SUPPRESSMSGBOXES", "/CLOSEAPPLICATIONS", "/NORESTART"]


def install_update(downloaded: Path) -> None:
    """Hand the downloaded update to whatever installs it; the caller must
    then quit the app."""
    if IS_WINDOWS:
        flags = getattr(subprocess, "DETACHED_PROCESS", 0) | getattr(
            subprocess, "CREATE_NEW_PROCESS_GROUP", 0
        )
        try:
            subprocess.Popen(
                [str(downloaded), *WINDOWS_INSTALLER_ARGS],
                creationflags=flags, close_fds=True,
            )
        except OSError as exc:
            raise AppUpdateError(f"Could not start the installer: {exc}") from exc
        return
    bundle = running_app_bundle()
    if bundle is None:
        raise AppUpdateError("Only the packaged app can update itself.")
    install_and_relaunch(downloaded, bundle)
