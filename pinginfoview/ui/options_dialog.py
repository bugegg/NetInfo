"""The Options dialog, covering PingInfoView's ping and advanced settings."""

from __future__ import annotations

from dataclasses import replace

from PyQt6.QtWidgets import (
    QCheckBox,
    QDialog,
    QDialogButtonBox,
    QDoubleSpinBox,
    QFormLayout,
    QGroupBox,
    QLineEdit,
    QPlainTextEdit,
    QSpinBox,
    QVBoxLayout,
)

from ..settings import Settings


class OptionsDialog(QDialog):
    def __init__(self, settings: Settings, parent=None, dont_fragment_supported=True) -> None:
        super().__init__(parent)
        self.setWindowTitle("Options")
        self._settings = replace(settings)

        self._interval = QDoubleSpinBox()
        self._interval.setRange(0.1, 86400.0)
        self._interval.setDecimals(1)
        self._interval.setSingleStep(0.5)
        self._interval.setSuffix(" seconds")
        self._interval.setValue(settings.ping_interval_seconds)

        self._timeout = QSpinBox()
        self._timeout.setRange(1, 600000)
        self._timeout.setSuffix(" ms")
        self._timeout.setValue(settings.ping_timeout_ms)

        self._size = QSpinBox()
        self._size.setRange(0, 65500)
        self._size.setSuffix(" bytes")
        self._size.setValue(settings.ping_size)

        self._ttl = QSpinBox()
        self._ttl.setRange(1, 255)
        self._ttl.setValue(settings.ttl)

        self._dont_fragment = QCheckBox("Don't fragment")
        self._dont_fragment.setChecked(settings.dont_fragment)
        if not dont_fragment_supported:
            self._dont_fragment.setChecked(False)
            self._dont_fragment.setEnabled(False)
            self._dont_fragment.setToolTip(
                "macOS rejects IP_DONTFRAG on the unprivileged ICMP socket this app uses."
            )

        self._stop_after = QSpinBox()
        self._stop_after.setRange(0, 1000000)
        self._stop_after.setSpecialValueText("Unlimited")
        self._stop_after.setValue(settings.stop_after_pings)

        self._max_concurrent = QSpinBox()
        self._max_concurrent.setRange(1, 10000)
        self._max_concurrent.setValue(settings.max_concurrent_pings)

        self._resolve_every_ping = QCheckBox("Resolve host name to IP address on every ping")
        self._resolve_every_ping.setChecked(settings.resolve_every_ping)

        self._start_immediately = QCheckBox("Start pinging immediately on startup")
        self._start_immediately.setChecked(settings.start_ping_immediately)

        self._port_scan_ports = QPlainTextEdit(settings.port_scan_ports)
        self._port_scan_ports.setPlaceholderText("Leave empty to disable port scanning")
        self._port_scan_ports.setToolTip(
            "Ports to probe on each host that answers a ping, to fill in the\n"
            "Open Ports and Device Type columns — useful for a device with a\n"
            "randomized MAC, which has no vendor to look up. Separate with\n"
            "commas, spaces, and/or newlines (e.g. \"22, 80, 443\"). A bare\n"
            "number probes TCP; add \"/udp\" (e.g. \"53/udp\") to probe UDP\n"
            "instead. Anything after a \"#\" on a line is a comment and is\n"
            "ignored, e.g. \"53/udp  # DNS\". Leave empty to disable."
        )
        self._port_scan_ports.setLineWrapMode(QPlainTextEdit.LineWrapMode.WidgetWidth)
        self._port_scan_ports.setFixedHeight(
            self._port_scan_ports.fontMetrics().lineSpacing() * 6
            + self._port_scan_ports.frameWidth() * 2 + 8
        )

        self._snmp_arp_routers = QLineEdit(settings.snmp_arp_routers)
        self._snmp_arp_routers.setPlaceholderText("e.g. 192.168.104.254")
        self._snmp_arp_routers.setToolTip(
            "Routers or layer-3 switches whose ARP table is read over SNMP to\n"
            "find the MAC of a host beyond this Mac's own network (behind a\n"
            "router or a VPN), where the local ARP table can't see it. Give\n"
            "the gateway of each network you ping, separated with commas or\n"
            "spaces. Leave empty to use the local ARP table only."
        )
        self._snmp_arp_auto = QCheckBox("Also ask each network's usual gateway (.254 and .1)")
        self._snmp_arp_auto.setChecked(settings.snmp_arp_auto)
        self._snmp_arp_auto.setToolTip(
            "For a host with no MAC, read the ARP table of x.x.x.254 and then\n"
            "x.x.x.1 in its network over SNMP, so no router has to be listed."
        )
        self._snmp_community = QLineEdit(settings.snmp_community)
        self._snmp_community.setToolTip("SNMP v2c read community for the routers above.")

        self._max_accumulated = QSpinBox()
        self._max_accumulated.setRange(100, 10000000)
        self._max_accumulated.setValue(settings.max_accumulated_pings)

        ping_box = QGroupBox("Ping")
        ping_form = QFormLayout(ping_box)
        ping_form.addRow("Ping every:", self._interval)
        ping_form.addRow("Ping timeout:", self._timeout)
        ping_form.addRow("Ping size:", self._size)
        ping_form.addRow("Time to live (TTL):", self._ttl)
        ping_form.addRow("", self._dont_fragment)
        ping_form.addRow("Stop after:", self._stop_after)

        advanced_box = QGroupBox("Advanced")
        advanced_form = QFormLayout(advanced_box)
        advanced_form.addRow("Maximum concurrent pings:", self._max_concurrent)
        advanced_form.addRow("", self._resolve_every_ping)
        advanced_form.addRow("", self._start_immediately)
        advanced_form.addRow("Probe ports:", self._port_scan_ports)
        advanced_form.addRow("MAC from routers (SNMP):", self._snmp_arp_routers)
        advanced_form.addRow("", self._snmp_arp_auto)
        advanced_form.addRow("SNMP community:", self._snmp_community)
        advanced_form.addRow("Keep at most (lower pane):", self._max_accumulated)

        buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel
        )
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)

        layout = QVBoxLayout(self)
        layout.addWidget(ping_box)
        layout.addWidget(advanced_box)
        layout.addWidget(buttons)

    def result_settings(self) -> Settings:
        """The edited settings; only valid after the dialog is accepted."""
        updated = replace(
            self._settings,
            ping_interval_seconds=self._interval.value(),
            ping_timeout_ms=self._timeout.value(),
            ping_size=self._size.value(),
            ttl=self._ttl.value(),
            dont_fragment=self._dont_fragment.isChecked(),
            stop_after_pings=self._stop_after.value(),
            max_concurrent_pings=self._max_concurrent.value(),
            resolve_every_ping=self._resolve_every_ping.isChecked(),
            start_ping_immediately=self._start_immediately.isChecked(),
            port_scan_ports=self._port_scan_ports.toPlainText(),
            snmp_arp_routers=self._snmp_arp_routers.text().strip(),
            snmp_community=self._snmp_community.text(),
            snmp_arp_auto=self._snmp_arp_auto.isChecked(),
            max_accumulated_pings=self._max_accumulated.value(),
        )
        return updated.sanitised()
