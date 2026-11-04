# PingInfoView for macOS

A desktop ping monitor for macOS. It pings many hosts at a fixed interval over
ICMP or TCP, shows per-host statistics in a sortable grid, and discovers device
details (MAC address, hostname, vendor, open ports) for hosts that answer.
See [spec.md](spec.md) for the full specification.

## Requirements

- macOS 13 (Ventura) or newer
- A Mac with Apple Silicon (M1 or later). The prebuilt app is `arm64` only;
  for an Intel Mac, [build it](#building-from-source) on an Intel Mac.
- No Python, no admin rights, no root. Everything the app needs is bundled.
- **Check LLDP/CDP** (which switch port the Mac is plugged into) reads
  packets through `/dev/bpf`, which macOS only allows for members of the
  `access_bpf` group. Installing [Wireshark](https://www.wireshark.org)
  with its *ChmodBPF* option sets that up.

## Installing

1. Download the latest `PingInfoView-<version>-arm64.zip` from the
   [Releases](../../releases) page.
2. Double-click the zip to unpack it. This gives you `PingInfoView.app`.
3. Drag `PingInfoView.app` into the **Applications** folder.
4. Open it from Applications or Launchpad.

### First launch: "PingInfoView can't be opened"

The app is not signed with an Apple Developer ID, so macOS blocks it the first
time. Allow it once, using either method:

**System Settings**

1. Double-click the app and dismiss the warning.
2. Open **System Settings → Privacy & Security**.
3. Scroll down to the message about PingInfoView and click **Open Anyway**.
4. Confirm with your password or Touch ID, then click **Open**.

**Terminal**

```bash
xattr -dr com.apple.quarantine /Applications/PingInfoView.app
```

After that, the app opens normally.

### Local network access

On macOS 15 and later, the first time the app pings a device on your network,
macOS may ask whether PingInfoView can find devices on the local network.
Click **Allow**. If you denied it, turn it back on under
**System Settings → Privacy & Security → Local Network**.

## Updating

The app checks GitHub Releases a few seconds after it opens. When a newer
version is out it asks whether to **Install and Restart**: it downloads the
new version, replaces itself, and opens again. Your settings are kept. To
check by hand, right-click the host list and choose **Check for Updates...**.

To update manually instead, quit the app and replace
`/Applications/PingInfoView.app` with the new copy from the
[Releases](../../releases) page.

## Releasing a new version

Push a version tag. GitHub Actions runs the tests, builds the app on an Apple
Silicon runner, and publishes `PingInfoView-<version>-arm64.zip` as a release,
which installed copies then offer to update to.

```bash
git tag v1.1
git push origin v1.1
```

The version comes from the tag; there's no file to edit first.

## Uninstalling

1. Quit the app and move `/Applications/PingInfoView.app` to the Trash.
2. To also remove its settings, delete
   `~/Library/Preferences/com.pinginfoview.PingInfoView.plist`.

## Building from source

Builds need Python 3.14 and must run on the CPU type you are building for.

```bash
python3.14 -m venv .venv
.venv/bin/pip install -r requirements-build.txt
./build_app.sh
```

This produces `dist/PingInfoView.app` and `dist/PingInfoView-<version>-<arch>.zip`.
The app icon comes from `PingInfoView.app/Contents/Resources/AppIcon.icns`.

To run from source without building:

```bash
.venv/bin/pip install -r requirements.txt
.venv/bin/python -m pinginfoview [hostlist.txt]
```

Run the tests with:

```bash
.venv/bin/pip install pytest
.venv/bin/python -m pytest
```
