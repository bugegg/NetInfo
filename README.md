# NetInfoView

A desktop ping monitor for macOS and Windows. It pings many hosts at a fixed interval over
ICMP or TCP, shows per-host statistics in a sortable grid, and discovers device
details (MAC address, hostname, vendor, open ports) for hosts that answer.
**Port Scan** (right-click a host, or the sidebar) lists every open TCP and UDP port
on one host — common ports, 1–1024, all 65535, or your own list — with the
service and banner behind each. **Repeat Ping** is a Cisco-style
`ping … repeat`: echoes back to back (100000 is fine), with Cisco's defaults.
See [spec.md](spec.md) for the full specification. NetInfoView was
called NetInfo up to version 1.4, and PingInfoView before that.

## Requirements (macOS)

- macOS 13 (Ventura) or newer
- A Mac with Apple Silicon (M1 or later). The prebuilt app is `arm64` only;
  for an Intel Mac, [build it](#building-from-source) on an Intel Mac.
- No Python, no admin rights, no root. Everything the app needs is bundled.
- **Check LLDP/CDP** (which switch port the Mac is plugged into) reads
  packets through `/dev/bpf`, which macOS only allows for members of the
  `access_bpf` group. Installing [Wireshark](https://www.wireshark.org)
  with its *ChmodBPF* option sets that up.

## Installing on Windows

1. Download the latest `NetInfoView-<version>-windows-x64-setup.exe` from the
   [Releases](../../releases) page and run it. It installs for the current
   user only, so it needs no administrator rights.
2. The installer isn't code-signed, so Windows SmartScreen may say
   *"Windows protected your PC"*. Click **More info → Run anyway**.
3. Start NetInfoView from the Start menu.

Windows 10 or 11, 64-bit. Every feature of the Mac version works on
Windows. **Check LLDP/CDP** also needs [Npcap](https://npcap.com) (the
capture driver Wireshark installs); without it, that window says so. **SSH** and
**Telnet** (right-click a host) use [PuTTY](https://www.putty.org)'s `plink`,
which comes with NetInfoView, so neither needs Windows' own Telnet Client or
OpenSSH, and old network gear's algorithms work without a prompt. Settings
are kept in the registry under
`HKEY_CURRENT_USER\Software\NetInfoView\NetInfoView`; uninstall from
**Settings → Apps**.

## Installing on macOS

1. Download the latest `NetInfoView-<version>-arm64.zip` from the
   [Releases](../../releases) page.
2. Double-click the zip to unpack it. This gives you `NetInfoView.app`.
3. Drag `NetInfoView.app` into the **Applications** folder.
4. Open it from Applications or Launchpad.

### First launch: "NetInfoView can't be opened"

The app is not signed with an Apple Developer ID, so macOS blocks it the first
time. Allow it once, using either method:

**System Settings**

1. Double-click the app and dismiss the warning.
2. Open **System Settings → Privacy & Security**.
3. Scroll down to the message about NetInfoView and click **Open Anyway**.
4. Confirm with your password or Touch ID, then click **Open**.

**Terminal**

```bash
xattr -dr com.apple.quarantine /Applications/NetInfoView.app
```

After that, the app opens normally.

### Local network access

On macOS 15 and later, the first time the app pings a device on your network,
macOS may ask whether NetInfoView can find devices on the local network.
Click **Allow**. If you denied it, turn it back on under
**System Settings → Privacy & Security → Local Network**.

## Updating

The app checks GitHub Releases a few seconds after it opens. When a newer
version is out it asks whether to **Install and Restart**: it downloads the
new version, replaces itself, and opens again. Your settings are kept. To
check by hand, click the **Check for Updates** button (up arrow) in the toolbar.

To update manually instead, quit the app and replace
`/Applications/NetInfoView.app` with the new copy from the
[Releases](../../releases) page; on Windows, run the newer installer.

## Releasing a new version

Push a version tag. GitHub Actions runs the tests, builds the app on an Apple
Silicon runner and a Windows runner, and publishes
`NetInfoView-<version>-arm64.zip` and `NetInfoView-<version>-windows-x64-setup.exe`
as a release,
which installed copies then offer to update to.

```bash
git tag v1.1
git push origin v1.1
```

The version comes from the tag; there's no file to edit first.

## Uninstalling

1. Quit the app and move `/Applications/NetInfoView.app` to the Trash.
2. To also remove its settings and MAC vendor database, delete
   `~/Library/Preferences/com.netinfoview.NetInfoView.plist` and
   `~/Library/Application Support/NetInfoView`. Versions up to 1.4 used
   `com.pinginfoview.PingInfoView.plist` and `Application Support/PingInfoView`;
   1.5 copies those over on first launch, and the old copies can go too.

## Building from source

Builds need Python 3.14 and must run on the CPU type you are building for.

```bash
python3.14 -m venv .venv
.venv/bin/pip install -r requirements-build.txt
./build_app.sh
```

This produces `dist/NetInfoView.app` and `dist/NetInfoView-<version>-<arch>.zip`.
The app icon comes from `NetInfoView.app/Contents/Resources/AppIcon.icns`.

To run from source without building:

```bash
.venv/bin/pip install -r requirements.txt
.venv/bin/python -m NetInfoView [hostlist.txt]
```

Run the tests with:

```bash
.venv/bin/pip install pytest
.venv/bin/python -m pytest
```

### Windows

Needs Python 3.14 and [Inno Setup 6](https://jrsoftware.org/isinfo.php):

```powershell
py -3.14 -m venv .venv
.venv\Scripts\pip install -r requirements-lock.txt pillow
.\build_windows.ps1
```

This produces `dist\NetInfoView-<version>-windows-x64-setup.exe`.
