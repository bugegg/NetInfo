import subprocess
import sys
from pathlib import Path

import pytest

from pinginfoview import app_update
from pinginfoview.app_update import (
    AppUpdateError,
    installer_script,
    is_newer,
    parse_release,
    parse_version,
    running_app_bundle,
)

RELEASE_JSON = {
    "tag_name": "v1.2",
    "body": "What's new",
    "html_url": "https://github.com/o/r/releases/tag/v1.2",
    "assets": [
        {"name": "PingInfoView-1.2-x86_64.zip", "browser_download_url": "https://x/intel.zip"},
        {"name": "PingInfoView-1.2-arm64.zip", "browser_download_url": "https://x/arm.zip"},
    ],
}


@pytest.mark.parametrize(
    "text, expected",
    [("1.0", (1,)), ("v1.2", (1, 2)), ("1.10.0", (1, 10)), ("v2.0.1-beta", (2, 0, 1))],
)
def test_parse_version(text, expected):
    assert parse_version(text) == expected


def test_parse_version_rejects_garbage():
    with pytest.raises(AppUpdateError):
        parse_version("latest")


def test_is_newer_compares_numerically_not_as_text():
    assert is_newer("1.10", "1.9")
    assert not is_newer("1.0", "1")
    assert not is_newer("1.1", "1.2")


def test_parse_release_picks_this_macs_asset():
    release = parse_release(RELEASE_JSON, machine="arm64")
    assert release.version == "1.2"
    assert release.asset_url == "https://x/arm.zip"
    assert release.notes == "What's new"
    assert parse_release(RELEASE_JSON, machine="x86_64").asset_url == "https://x/intel.zip"


def test_parse_release_without_matching_asset_leaves_url_empty():
    assert parse_release({"tag_name": "v1.2", "assets": []}, machine="arm64").asset_url == ""


def test_parse_release_requires_a_tag():
    with pytest.raises(AppUpdateError):
        parse_release({"assets": []})


def test_running_app_bundle_is_none_from_source():
    assert running_app_bundle() is None


def test_running_app_bundle_when_frozen(monkeypatch):
    monkeypatch.setattr(sys, "frozen", True, raising=False)
    monkeypatch.setattr(sys, "executable", "/Applications/PingInfoView.app/Contents/MacOS/PingInfoView")
    assert running_app_bundle() == Path("/Applications/PingInfoView.app")


def test_download_and_extract_refuses_release_without_asset():
    release = parse_release({"tag_name": "v9", "assets": []}, machine="arm64")
    with pytest.raises(AppUpdateError):
        app_update.download_and_extract(release)


def test_extract_app_finds_the_bundle(tmp_path):
    src = tmp_path / "src" / "PingInfoView.app" / "Contents"
    src.mkdir(parents=True)
    (src / "Info.plist").write_text("x")
    zip_path = tmp_path / "u.zip"
    subprocess.run(
        ["ditto", "-c", "-k", "--keepParent", str(src.parent), str(zip_path)], check=True
    )
    app = app_update.extract_app(zip_path, tmp_path / "out")
    assert app.name == "PingInfoView.app"
    assert (app / "Contents" / "Info.plist").read_text() == "x"


def test_installer_script_swaps_in_the_new_bundle(tmp_path):
    work = tmp_path / "work"
    new_app = work / "extracted" / "PingInfoView.app"
    (new_app / "Contents").mkdir(parents=True)
    (new_app / "Contents" / "v").write_text("new")
    target = tmp_path / "Apps" / "PingInfoView.app"
    (target / "Contents").mkdir(parents=True)
    (target / "Contents" / "v").write_text("old")

    # A pid that's already gone, and `open` stubbed out so nothing launches.
    script = installer_script(new_app, target, pid=999999).replace("/usr/bin/open", "true")
    subprocess.run(["/bin/bash", "-c", script], check=True)

    assert (target / "Contents" / "v").read_text() == "new"
    assert not Path(str(target) + ".old").exists()
    assert not work.exists()  # temp download cleaned up
