"""Worker threads that must not outlive the app while still running.

Qt aborts the whole process ("QThread: Destroyed while thread is still
running") if a QThread is destroyed mid-run, which is what happens when the
app quits while a window's thread is busy, or after a window has let go of
one to finish in the background. Windows `track` each thread they start and
`retire` one they let go of; when the app is about to quit, every thread
still running is asked to stop and waited for.
"""

from __future__ import annotations

import time

from PyQt6.QtCore import QCoreApplication, QThread

#: How long quitting waits for the threads still running, all together.
QUIT_WAIT_MS = 5000

_running: set[QThread] = set()
_hooked = False


def track(thread: QThread) -> QThread:
    """Remember `thread` until it finishes, so quitting waits for it."""
    global _hooked
    _running.add(thread)
    thread.finished.connect(lambda: _running.discard(thread))
    app = QCoreApplication.instance()
    if app is not None and not _hooked:
        app.aboutToQuit.connect(stop_all)
        _hooked = True
    return thread


def retire(thread: QThread) -> None:
    """Let a thread its window no longer listens to finish on its own: the
    app owns it from now on and deletes it once it has finished."""
    track(thread)
    thread.setParent(QCoreApplication.instance())
    thread.finished.connect(thread.deleteLater)


def stop_all(timeout_ms: int = QUIT_WAIT_MS) -> bool:
    """Ask every running thread to stop and wait for them; True if they all
    did within `timeout_ms`."""
    threads = [t for t in list(_running) if t.isRunning()]
    for thread in threads:
        stop = getattr(thread, "stop", None)
        if callable(stop):
            stop()
    deadline = time.monotonic() + timeout_ms / 1000
    for thread in threads:
        left = int((deadline - time.monotonic()) * 1000)
        if left <= 0 or not thread.wait(left):
            return False
    return True
