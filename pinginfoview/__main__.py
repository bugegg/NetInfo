"""Entry point: ``python -m pinginfoview``."""

from __future__ import annotations

import sys

from PyQt6.QtWidgets import QApplication

from .fileio.hostfile import HostListError, parse_host_list
from .settings import APPLICATION, ORGANISATION, Settings

#: launchd starts GUI apps (anything opened via Finder or `open`, as the
#: packaged .app is) with a soft file-descriptor limit of just 256 — far
#: below what a big device-info sweep needs (ping.port_scan.MAX_WORKERS
#: alone can have 300 sockets in flight). A plain `python -m pinginfoview`
#: from Terminal already inherits a much higher shell limit, so this only
#: actually matters for the packaged app, but it's harmless either way.
FILE_DESCRIPTOR_LIMIT = 4096


def _raise_file_descriptor_limit() -> None:
    """Best-effort: raise our own soft RLIMIT_NOFILE toward the hard limit.

    Every process is free to raise its own soft limit up to the hard one
    without special privilege; macOS's hard limit is effectively unlimited,
    so this just undoes launchd's unusually low default. Never fatal if it
    fails (a locked-down environment, say) — the app still runs, just with
    less headroom for a large concurrent sweep.
    """
    try:
        import resource
    except ImportError:
        return  # not on a POSIX platform
    try:
        soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
        # hard is RLIM_INFINITY (a huge sentinel) when there's no real
        # ceiling, so min() alone is enough — no need to special-case it.
        target = min(FILE_DESCRIPTOR_LIMIT, hard)
        if target > soft:
            resource.setrlimit(resource.RLIMIT_NOFILE, (target, hard))
    except (OSError, ValueError):
        pass


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv if argv is None else argv)
    _raise_file_descriptor_limit()

    app = QApplication(argv)
    app.setApplicationName(APPLICATION)
    app.setOrganizationName(ORGANISATION)

    from .ui.main_window import MainWindow

    settings = Settings.load()
    window = MainWindow(settings)

    # A host-list file may be passed on the command line, as /loadfile does.
    for path in argv[1:]:
        if path.startswith("-"):
            continue
        try:
            with open(path, encoding="utf-8", errors="replace") as handle:
                window._model.set_entries(
                    window._entries_from_parsed(parse_host_list(handle.read()))
                )
        except (OSError, HostListError):
            continue
        window._current_file = path
        window._update_status_bar()
        break

    window.show()
    if settings.start_ping_immediately and window._model.rowCount():
        window.start_pinging()
    return app.exec()


if __name__ == "__main__":
    raise SystemExit(main())
