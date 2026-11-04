"""Runs ping.device_info.resolve_batch off the GUI thread.

One fetch-and-done sweep per device-info timer tick (ui/main_window.py's
DEVICE_INFO_REFRESH_MS), shaped like ui/vendor_update_thread.py rather than
EngineThread's repeating asyncio loop.
"""

from __future__ import annotations

from PyQt6.QtCore import QThread, pyqtSignal

from ..ping.device_info import DeviceInfoJob, resolve_batch
from ..ping.port_scan import ParsedPorts


class DeviceInfoThread(QThread):
    #: list[DeviceInfoResult]
    results_ready = pyqtSignal(list)

    def __init__(
        self,
        jobs: list[DeviceInfoJob],
        vendor_db,
        ports: ParsedPorts | None = None,
        snmp_routers: list[str] | None = None,
        snmp_community: str = "public",
        snmp_auto: bool = False,
    ) -> None:
        super().__init__()
        self._jobs = jobs
        self._vendor_db = vendor_db
        self._ports = ports
        self._snmp_routers = snmp_routers
        self._snmp_community = snmp_community
        self._snmp_auto = snmp_auto

    def run(self) -> None:  # noqa: D102 - QThread entry point
        try:
            results = resolve_batch(
                self._jobs, self._vendor_db, ports=self._ports,
                snmp_routers=self._snmp_routers, snmp_community=self._snmp_community,
                snmp_auto=self._snmp_auto,
            )
        except Exception:
            # A sweep that fails shouldn't take the refresh timer down with it;
            # the next tick just tries again.
            results = []
        self.results_ready.emit(results)
