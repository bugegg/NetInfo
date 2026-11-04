"""Which OS the app runs on, and helpers that differ between them.

NetInfoView began as a macOS app. On Windows every feature works too, through
Windows' own APIs where macOS uses its command-line tools; Check LLDP/CDP
additionally needs Npcap (https://npcap.com) installed.
"""

from __future__ import annotations

import subprocess
import sys

IS_WINDOWS = sys.platform == "win32"
IS_MACOS = sys.platform == "darwin"

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
