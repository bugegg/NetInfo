"""Which OS the app runs on, and what that leaves it able to do.

NetInfo began as a macOS app; on Windows a few features that read packets or
lean on macOS command-line tools aren't available yet (see the FEATURES_*
flags), and the UI hides them rather than offering something that can't work.
"""

from __future__ import annotations

import subprocess
import sys

IS_WINDOWS = sys.platform == "win32"
IS_MACOS = sys.platform == "darwin"

#: Check MTU and Trace Path MTU drive the system's ping/route tools.
FEATURE_MTU = not IS_WINDOWS
#: Check LLDP/CDP reads raw frames through /dev/bpf.
FEATURE_LLDP_CDP = not IS_WINDOWS
#: The hop details' Whois runs /usr/bin/whois.
FEATURE_WHOIS = not IS_WINDOWS


def run_quietly(args: list[str], timeout: float) -> str:
    """stdout of a command, or "" if it can't be run.

    On Windows a GUI app's child console program would flash up a console
    window for each call; CREATE_NO_WINDOW keeps it hidden.
    """
    flags = getattr(subprocess, "CREATE_NO_WINDOW", 0) if IS_WINDOWS else 0
    try:
        return subprocess.run(
            args, capture_output=True, text=True, timeout=timeout,
            creationflags=flags, errors="replace",
        ).stdout
    except (OSError, subprocess.SubprocessError):
        return ""
