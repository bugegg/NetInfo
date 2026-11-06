"""Open an SSH or Telnet session to a host in the system's own terminal:
Terminal.app on macOS, a console window on Windows."""

from __future__ import annotations

import ipaddress
import os
import re
import shlex
import stat
import subprocess
import tempfile

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
#: OpenSSH before 8.5 (Windows 10 ships 7.7 or 8.1) calls
#: PubkeyAcceptedAlgorithms PubkeyAcceptedKeyTypes, and refuses to start
#: at all on an option it doesn't know.
_RENAMED_IN_8_5 = ("PubkeyAcceptedAlgorithms=", "PubkeyAcceptedKeyTypes=")
_OPENSSH_VERSION = re.compile(r"OpenSSH\w*?_(\d+)\.(\d+)")
_ssh_version: tuple[int, int] | None = None


def ssh_version() -> tuple[int, int] | None:
    """The installed OpenSSH client's (major, minor), from `ssh -V`; None
    if there's no ssh or it can't be told. Asked once."""
    global _ssh_version
    if _ssh_version is None:
        try:
            out = subprocess.run(
                ["ssh", "-V"], capture_output=True, text=True, timeout=5,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            )
            match = _OPENSSH_VERSION.search(out.stderr + out.stdout)
            _ssh_version = (int(match[1]), int(match[2])) if match else (0, 0)
        except (OSError, subprocess.SubprocessError):
            _ssh_version = (0, 0)
    return _ssh_version if _ssh_version != (0, 0) else None


def legacy_ssh_options(version: tuple[int, int] | None) -> list[str]:
    """LEGACY_SSH_OPTIONS, spelt for OpenSSH `version` (None: current)."""
    if version is None or version >= (8, 5):
        return list(LEGACY_SSH_OPTIONS)
    old, new = _RENAMED_IN_8_5
    return [option.replace(old, new) for option in LEGACY_SSH_OPTIONS]

_USERNAME = re.compile(r"^[A-Za-z0-9._@\\-]{1,64}$")


def valid_username(name: str) -> bool:
    return bool(_USERNAME.match(name))


def ssh_command(ip: str, username: str = "") -> list[str]:
    ipaddress.ip_address(ip)  # only ever an address, never shell text
    if username and not valid_username(username):
        raise ValueError(f"Not a valid user name: {username!r}")
    target = f"{username}@{ip}" if username else ip
    return ["ssh", *legacy_ssh_options(ssh_version()), target]


def telnet_command(ip: str) -> list[str]:
    """`-K`: no automatic login. Without it macOS's telnet offers the
    device Kerberos and, with no realm set up, prints "Kerberos: No default
    realm defined" right after a Cisco's Password: prompt. Windows' telnet
    has no such option and needs none."""
    ipaddress.ip_address(ip)
    return ["telnet", ip] if IS_WINDOWS else ["telnet", "-K", ip]


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


#: Where to get each program on Windows, where neither is a given: the
#: Telnet Client is off by default, and OpenSSH Client can be removed.
_WINDOWS_HINTS = {
    "telnet": "Turn on Telnet Client: Control Panel > Programs > Turn Windows features "
              "on or off, or run as administrator: dism /online /Enable-Feature "
              "/FeatureName:TelnetClient",
    "ssh": "Add OpenSSH Client: Settings > System > Optional features",
}


def _ps_quote(text: str) -> str:
    return "'" + text.replace("'", "''") + "'"


def windows_script(command: list[str]) -> str:
    """A PowerShell script for a console window of its own: a hint when the
    program isn't installed, and a window that closes when the session
    ends, unless it failed straight away (so the error can be read)."""
    program = command[0]
    hint = _WINDOWS_HINTS.get(program, f"Install {program}.")
    wait = "Write-Host 'Press any key to close.'; [void][Console]::ReadKey($true)"
    return (
        f"if (-not (Get-Command {_ps_quote(program)} -ErrorAction SilentlyContinue)) {{ "
        f"Write-Host {_ps_quote(f'{program} is not installed. {hint}')}; {wait}; exit 1 }}; "
        "$started = [Diagnostics.Stopwatch]::StartNew(); "
        f"& {' '.join(_ps_quote(word) for word in command)}; "
        f"if ($LASTEXITCODE -ne 0 -and $started.Elapsed.TotalSeconds -lt {QUICK_FAILURE_SECONDS}) "
        f"{{ {wait} }}"
    )


def open_in_terminal(command: list[str]) -> None:
    """Run `command` in a new terminal window, and return straight away."""
    if IS_WINDOWS:
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
