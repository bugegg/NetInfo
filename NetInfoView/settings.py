"""Application options, mirroring PingInfoView's Options and Advanced Options.

The dataclass itself is plain Python so the ping engine and the file writers can
use it without importing Qt; persistence pulls in QSettings lazily.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, fields
from enum import Enum

from .ping.port_scan import DEFAULT_PORTS_TEXT as _DEFAULT_PORT_SCAN_PORTS

#: Where settings and the vendor database are stored.
ORGANISATION = "NetInfoView"
APPLICATION = "NetInfoView"
#: Where releases up to 1.4 stored them, under the app's original name.
#: migrate_legacy_settings() and vendor_db.migrate_legacy_db() carry them over.
LEGACY_ORGANISATION = "pinginfoview"
LEGACY_APPLICATION = "PingInfoView"


class DisplayMode(str, Enum):
    """Which hosts the main grid shows."""

    ALL = "all"
    SUCCEEDED = "succeeded"
    FAILED = "failed"


class HistoryMode(str, Enum):
    """Which pings the lower pane records."""

    ALL = "all"
    STATUS_CHANGES = "changes"
    FAILED_ONLY = "failed"


@dataclass
class Settings:
    # -- ping ----------------------------------------------------------------
    ping_interval_seconds: float = 1.0
    ping_timeout_ms: int = 3000
    ping_size: int = 32
    ttl: int = 64
    dont_fragment: bool = False
    max_concurrent_pings: int = 500
    resolve_every_ping: bool = False
    #: 0 means keep pinging until stopped.
    stop_after_pings: int = 0
    start_ping_immediately: bool = True
    #: Comma/space-separated ports the device-info sweep probes on each
    #: successfully-pinged host, for a best-effort device-type guess
    #: (ping.port_scan.parse_ports does the parsing). Empty disables the
    #: scan entirely; defaults to the same list as port_scan.STATIC_PORTS.
    port_scan_ports: str = _DEFAULT_PORT_SCAN_PORTS
    #: Comma/space-separated routers whose ARP table is read over SNMP for
    #: the MAC of a host beyond the local link (ping.snmp_arp). Empty
    #: disables it: only the Mac's own ARP table is used.
    snmp_arp_routers: str = ""
    #: Also try the usual gateway addresses (.254 and .1) of each host's
    #: network, so no router has to be configured.
    snmp_arp_auto: bool = True
    snmp_community: str = "public"

    # -- grid ----------------------------------------------------------------
    display_mode: DisplayMode = DisplayMode.ALL
    hide_disabled: bool = False
    mark_odd_even_rows: bool = True
    dark_background: bool = False
    always_on_top: bool = False
    font_family: str = ""
    font_size: int = 0

    # -- route monitor colours ------------------------------------------------
    #: Latency (ms) and packet loss (%) from which a hop is Warning / Critical
    #: in Route Monitor: Net Path's thresholds (ping/netpath.py). Loss 0 is off.
    route_latency_warn_ms: float = 25.0
    route_latency_crit_ms: float = 100.0
    route_loss_warn_percent: float = 5.0
    route_loss_crit_percent: float = 10.0
    #: Route Monitor log files older than this many days are deleted.
    route_log_keep_days: int = 30

    # -- lower pane ----------------------------------------------------------
    history_mode: HistoryMode = HistoryMode.ALL
    max_accumulated_pings: int = 50000
    auto_scroll_history: bool = True
    show_history_pane: bool = True

    # -- add hosts dialog ----------------------------------------------------
    #: What was last entered in Add Hosts, offered again next time it opens.
    last_added_hosts: str = ""
    add_hosts_skip_first: bool = False
    add_hosts_skip_last: bool = False
    #: Add Hosts replaces the current list rather than adding to it.
    add_hosts_replace: bool = True

    def sanitised(self) -> "Settings":
        """Clamp values the dialogs or a config file could put out of range."""
        self.ping_interval_seconds = max(0.1, float(self.ping_interval_seconds))
        self.ping_timeout_ms = max(1, int(self.ping_timeout_ms))
        self.ping_size = min(65500, max(0, int(self.ping_size)))
        self.ttl = min(255, max(1, int(self.ttl)))
        self.max_concurrent_pings = max(1, int(self.max_concurrent_pings))
        self.stop_after_pings = max(0, int(self.stop_after_pings))
        self.max_accumulated_pings = max(100, int(self.max_accumulated_pings))
        self.route_log_keep_days = min(3650, max(1, int(self.route_log_keep_days)))
        self.route_latency_warn_ms = max(1.0, float(self.route_latency_warn_ms))
        self.route_latency_crit_ms = max(self.route_latency_warn_ms + 1,
                                         float(self.route_latency_crit_ms))
        self.route_loss_warn_percent = min(100.0, max(0.0, float(self.route_loss_warn_percent)))
        self.route_loss_crit_percent = min(100.0, max(0.0, float(self.route_loss_crit_percent)))
        if self.route_loss_crit_percent and self.route_loss_crit_percent < self.route_loss_warn_percent:
            self.route_loss_crit_percent = self.route_loss_warn_percent
        return self

    # -- persistence ---------------------------------------------------------

    def save(self) -> None:
        from PyQt6.QtCore import QSettings

        store = QSettings(ORGANISATION, APPLICATION)
        for key, value in asdict(self).items():
            store.setValue(key, value.value if isinstance(value, Enum) else value)

    @classmethod
    def load(cls) -> "Settings":
        from PyQt6.QtCore import QSettings

        store = QSettings(ORGANISATION, APPLICATION)
        loaded = cls()
        for field in fields(cls):
            stored = store.value(field.name, None)
            if stored is None:
                continue
            try:
                setattr(loaded, field.name, _coerce(field.type, stored))
            except (TypeError, ValueError):
                pass  # keep the default rather than fail to start
        return loaded.sanitised()



def migrate_legacy_settings(store=None, legacy=None) -> bool:
    """Copy settings saved under the old PingInfoView name into the new
    store, once: only when the new one is still empty. The old store is
    left alone so an older build still finds its settings. Returns True
    if anything was copied."""
    from PyQt6.QtCore import QSettings

    store = store if store is not None else QSettings(ORGANISATION, APPLICATION)
    legacy = legacy if legacy is not None else QSettings(LEGACY_ORGANISATION, LEGACY_APPLICATION)
    if store.allKeys() or not legacy.allKeys():
        return False
    for key in legacy.allKeys():
        store.setValue(key, legacy.value(key))
    store.sync()
    return True

def _coerce(field_type: object, value: object):
    """QSettings hands everything back as a string; put it back in its type."""
    name = field_type if isinstance(field_type, str) else getattr(field_type, "__name__", "")
    if name == "bool":
        return value if isinstance(value, bool) else str(value).lower() in ("true", "1")
    if name == "int":
        return int(value)
    if name == "float":
        return float(value)
    if name == "DisplayMode":
        return DisplayMode(value)
    if name == "HistoryMode":
        return HistoryMode(value)
    return value
