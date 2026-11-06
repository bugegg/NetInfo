"""Open an SSH or Telnet session to a host in the system's own terminal:
Terminal.app on macOS (its ssh and telnet), a console window on Windows
(PuTTY's plink, bundled with the app, for both)."""

from __future__ import annotations

import ipaddress
import os
import re
import shlex
import shutil
import stat
import subprocess
import tempfile
from pathlib import Path, PureWindowsPath

from ..osinfo import IS_WINDOWS

#: Older network gear (Cisco IOS among it) only offers key exchanges,
#: host keys and ciphers that current OpenSSH turns off by default; allow
#: them as well, after the modern ones.
LEGACY_SSH_OPTIONS = (
    "-o", "KexAlgorithms=+diffie-hellman-group14-sha1,diffie-hellman-group-exchange-sha1,"
          "diffie-hellman-group1-sha1",
    "-o", "HostKeyAlgorithms=+ssh-rsa",
    "-o", "PubkeyAcceptedAlgorithms=+ssh-rsa",
    "-o", "Ciphers=+aes128-cbc,aes256-cbc,3des-cbc",
)

#: plink, shipped next to the app's other data by build_windows.ps1 (PuTTY,
#: MIT licence; see PuTTY-LICENCE.txt beside it). Windows has no telnet
#: unless the user turns the feature on, and Windows 10's OpenSSH is too old
#: for some of LEGACY_SSH_OPTIONS; plink does both, old algorithms included.
BUNDLED_PLINK = Path(__file__).resolve().parent.parent / "putty" / "plink.exe"
#: The saved PuTTY session plink loads (HKCU\Software\SimonTatham\PuTTY\
#: Sessions\NetInfoView): every algorithm on, old ones above the "warn
#: below here" line, so old network gear connects without a prompt.
PUTTY_SESSION = "NetInfoView"
PUTTY_SETTINGS = {
    "Cipher": "aes,chacha20,aesgcm,3des,WARN,des,blowfish,arcfour",
    "KEX": "ntru-curve25519,mlkem-curve25519,mlkem-nist,ecdh,dh-group18-sha512,"
           "dh-group17-sha512,dh-group16-sha512,dh-group15-sha512,dh-gex-sha1,"
           "dh-group14-sha1,dh-group1-sha1,rsa,WARN",
    "HostKey": "ed25519,ed448,ecdsa,rsa,dsa,WARN",
}


def plink_path() -> str:
    """The bundled plink.exe, else one on the PATH (running from source)."""
    if BUNDLED_PLINK.is_file():
        return str(BUNDLED_PLINK)
    return shutil.which("plink") or "plink"


def save_putty_session() -> None:
    """Write PUTTY_SETTINGS into the NetInfoView PuTTY session (Windows)."""
    import winreg

    path = rf"Software\SimonTatham\PuTTY\Sessions\{PUTTY_SESSION}"
    with winreg.CreateKey(winreg.HKEY_CURRENT_USER, path) as key:
        for name, value in PUTTY_SETTINGS.items():
            winreg.SetValueEx(key, name, 0, winreg.REG_SZ, value)


_USERNAME = re.compile(r"^[A-Za-z0-9._@\\-]{1,64}$")


def valid_username(name: str) -> bool:
    return bool(_USERNAME.match(name))


def ssh_command(ip: str, username: str = "") -> list[str]:
    ipaddress.ip_address(ip)  # only ever an address, never shell text
    if username and not valid_username(username):
        raise ValueError(f"Not a valid user name: {username!r}")
    if IS_WINDOWS:
        user = ["-l", username] if username else []  # else plink asks "login as:"
        return [plink_path(), "-load", PUTTY_SESSION, "-ssh", *user, ip]
    target = f"{username}@{ip}" if username else ip
    return ["ssh", *LEGACY_SSH_OPTIONS, target]


def telnet_command(ip: str) -> list[str]:
    """`-K`: no automatic login. Without it macOS's telnet offers the
    device Kerberos and, with no realm set up, prints "Kerberos: No default
    realm defined" right after a Cisco's Password: prompt."""
    ipaddress.ip_address(ip)
    if IS_WINDOWS:
        return [plink_path(), "-load", PUTTY_SESSION, "-telnet", ip]
    return ["telnet", "-K", ip]


#: A session that fails sooner than this was most likely refused or timed
#: out, so its window waits for a key to let the error be read.
QUICK_FAILURE_SECONDS = 5

#: Closes this script's own Terminal window once the shell has gone. Run in
#: the background and detached, so Terminal sees no running process and
#: doesn't ask whether to terminate one; Terminal's own default is to leave
#: a finished window open on "[Process completed]".
_CLOSE_WINDOW = (
    'tty_name=$(tty)\n'
    '( sleep 0.3; osascript -e "tell application \\"Terminal\\" to close '
    '(every window whose tty of selected tab is \\"$tty_name\\")" ) '
    '</dev/null >/dev/null 2>&1 &!\n'
)


def backspace_wrapped(command: list[str]) -> list[str]:
    """`command` run under macOS's own `expect`, turning the Delete key's DEL
    (^?) into Backspace (^H): network gear such as HPE/H3C Comware and older
    Cisco only erases on ^H, and ignores Terminal's default DEL. Window
    resizes are passed on, and the session's exit status is kept."""
    script = (
        "trap {stty rows [stty rows] columns [stty columns] < $spawn_out(slave,name)} WINCH; "
        # Braces keep each word literal to Tcl (a DOMAIN\user name included);
        # ssh_command/telnet_command never let a brace through.
        f"spawn -noecho {' '.join('{' + word + '}' for word in command)}; "
        'interact "\\177" {send "\\010"}; '
        "catch wait result; exit [lindex $result 3]"
    )
    return ["/usr/bin/expect", "-c", script]


def macos_script(command: list[str]) -> str:
    """A .command script for Terminal: a login shell so Homebrew's telnet
    is on the PATH, and a hint when the program isn't installed. The window
    closes when the session ends, unless it failed straight away."""
    program = command[0]
    hint = "brew install telnet" if program == "telnet" else f"install {program}"
    return (
        "#!/bin/zsh -l\n"
        'rm -f "$0"\n'  # a one-off script: tidy it away once it's started
        f"if ! command -v {program} >/dev/null; then\n"
        f"  echo '{program} is not installed ({hint}).'\n"
        "  exit 1\n"
        "fi\n"
        "started=$SECONDS\n"
        "if [[ -x /usr/bin/expect ]]; then\n"
        f"  {shlex.join(backspace_wrapped(command))}\n"
        "else\n"
        f"  {shlex.join(command)}\n"
        "fi\n"
        f"if (( $? != 0 && SECONDS - started < {QUICK_FAILURE_SECONDS} )); then\n"
        "  read -sk1 '?Press any key to close.'\n"
        "fi\n"
        f"{_CLOSE_WINDOW}"
        "exit 0\n"
    )


#: Only when running from source: the installed app has its own plink.
_WINDOWS_HINTS = {"plink": "Install PuTTY (https://www.putty.org), or reinstall NetInfoView."}


def _ps_quote(text: str) -> str:
    return "'" + text.replace("'", "''") + "'"


def windows_script(command: list[str]) -> str:
    """A PowerShell script for a console window of its own: a hint when the
    program isn't installed, and a window that closes when the session
    ends, unless it failed straight away (so the error can be read)."""
    program = command[0]
    name = PureWindowsPath(program).stem if program.lower().endswith(".exe") else program
    hint = _WINDOWS_HINTS.get(name, f"Install {name}.")
    wait = "Write-Host 'Press any key to close.'; [void][Console]::ReadKey($true)"
    return (
        f"if (-not (Get-Command {_ps_quote(program)} -ErrorAction SilentlyContinue)) {{ "
        f"Write-Host {_ps_quote(f'{name} is not installed. {hint}')}; {wait}; exit 1 }}; "
        "$started = [Diagnostics.Stopwatch]::StartNew(); "
        f"& {' '.join(_ps_quote(word) for word in command)}; "
        f"if ($LASTEXITCODE -ne 0 -and $started.Elapsed.TotalSeconds -lt {QUICK_FAILURE_SECONDS}) "
        f"{{ {wait} }}"
    )


def open_in_terminal(command: list[str]) -> None:
    """Run `command` in a new terminal window, and return straight away."""
    if IS_WINDOWS:
        try:
            save_putty_session()
        except OSError:
            pass  # plink still runs, only asking about old algorithms
        subprocess.Popen(
            ["powershell", "-NoLogo", "-NoProfile", "-Command", windows_script(command)],
            creationflags=getattr(subprocess, "CREATE_NEW_CONSOLE", 0),
        )
        return
    fd, path = tempfile.mkstemp(prefix="netinfoview-", suffix=".command")
    with os.fdopen(fd, "w") as script:
        script.write(macos_script(command))
    os.chmod(path, stat.S_IRWXU)
    # If this launches Terminal, don't let it reopen last time's windows as
    # well: they'd be left behind as stray empty shells once the session's
    # own window closes. (Arguments only apply when Terminal isn't running.)
    subprocess.Popen(
        ["open", "-a", "Terminal", path, "--args", "-ApplePersistenceIgnoreState", "YES"]
    )
