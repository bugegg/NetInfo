"""This Mac's (or PC's) own link to the network, for Speed Test's "This
device" card: the interface the default route uses, its address, whether
it's Wi-Fi or Ethernet, the link speed, and for Wi-Fi the network name, band
and signal.

macOS: ``route``, ``ifconfig``, ``networksetup`` and ``system_profiler
SPAirPortDataType`` (no admin rights). macOS hides the Wi-Fi network's name
from apps without Location Services access ("<redacted>"); it's left blank
then. Windows: PowerShell's Get-NetAdapter and ``netsh wlan show
interfaces``. Qt-free.
"""

from __future__ import annotations

import json
import re
import socket
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, replace

from ..osinfo import IS_WINDOWS, run_quietly
from .network_interfaces import hardware_ports


@dataclass(frozen=True)
class DeviceLink:
    interface: str = ""        # en0, "Wi-Fi", ...
    kind: str = ""             # "Wi-Fi", "Ethernet", or the port's name
    local_ip: str = ""
    link_mbps: float | None = None
    ssid: str = ""             # "" when unknown or hidden
    band: str = ""             # "5 GHz"
    phy: str = ""              # "802.11ax"
    channel: str = ""
    signal_dbm: int | None = None
    signal_percent: int | None = None  # Windows reports a percentage
    port: str = ""             # the adapter: "USB 10/100/1000 LAN", "Thunderbolt Ethernet"
    duplex: str = ""           # "Full duplex" / "Half duplex" (wired)
    active: bool | None = None  # the cable's link is up

    @property
    def wifi(self) -> bool:
        return self.kind == "Wi-Fi"

    @property
    def connected(self) -> bool:
        return bool(self.local_ip)


_GENERATIONS = {"b": "1", "a": "2", "g": "3", "n": "4", "ac": "5", "ax": "6", "be": "7"}


def wifi_generation(phy: str, band: str = "") -> str:
    """"Wi-Fi 6" for "802.11ax" (the Wi-Fi Alliance's numbering, 1-7);
    802.11ax on 6 GHz is "Wi-Fi 6E". "" when it isn't known."""
    match = re.search(r"802\.11\s*([a-z]+)", phy.lower())
    number = _GENERATIONS.get(match.group(1)) if match else None
    if number is None:
        return ""
    if number == "6" and band.startswith("6"):
        return "Wi-Fi 6E"
    return f"Wi-Fi {number}"


def strength(link: DeviceLink) -> tuple[str, int]:
    """("Strong"/"Good"/"Fair"/"Weak", bars out of 4) for a Wi-Fi signal."""
    if link.signal_dbm is not None:
        dbm = link.signal_dbm
        if dbm >= -60:
            return "Strong", 4
        if dbm >= -67:
            return "Good", 3
        if dbm >= -75:
            return "Fair", 2
        return "Weak", 1
    if link.signal_percent is not None:
        pct = link.signal_percent
        return (("Strong", 4) if pct >= 75 else ("Good", 3) if pct >= 55
                else ("Fair", 2) if pct >= 35 else ("Weak", 1))
    return "", 0


def local_address() -> str:
    """The address this machine reaches the Internet from (a UDP socket's
    source address; nothing is sent)."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("192.0.2.1", 9))  # TEST-NET-1: routed like the Internet
            return s.getsockname()[0]
    except OSError:
        return ""


# ------------------------------------------------------------------ macOS


def default_interface_macos(route_output: str) -> str:
    match = re.search(r"interface:\s*(\S+)", route_output)
    return match.group(1) if match else ""


def ethernet_mbps(ifconfig_output: str) -> float | None:
    """From "media: autoselect (1000baseT <full-duplex>)", 1000; 10Gbase-T is
    10000, 2500Base-T 2500."""
    match = re.search(r"media:.*?\((\d+(?:\.\d+)?)(G?)base", ifconfig_output, re.IGNORECASE)
    if not match:
        return None
    value = float(match.group(1))
    return value * 1000 if match.group(2).upper() == "G" else value


def duplex_of(ifconfig_output: str) -> str:
    media = re.search(r"media:([^\n]*)", ifconfig_output)
    text = media.group(1).lower() if media else ""
    if "full-duplex" in text:
        return "Full duplex"
    if "half-duplex" in text:
        return "Half duplex"
    return ""


def link_active(ifconfig_output: str) -> bool | None:
    status = re.search(r"status:\s*(\w+)", ifconfig_output)
    return None if not status else status.group(1) == "active"


def parse_airport(data: object, interface: str) -> dict:
    """system_profiler's current network on `interface`: rate, band,
    channel, signal and (if not hidden) the name."""
    try:
        interfaces = [i for item in data["SPAirPortDataType"]
                      for i in item.get("spairport_airport_interfaces", [])]
    except (KeyError, TypeError):
        return {}
    for entry in interfaces:
        if entry.get("_name") != interface:
            continue
        current = entry.get("spairport_current_network_information") or {}
        if not current:
            return {}
        out: dict = {}
        name = str(current.get("_name") or "")
        if name and name != "<redacted>":
            out["ssid"] = name
        rate = current.get("spairport_network_rate")
        if isinstance(rate, (int, float)) and rate > 0:
            out["link_mbps"] = float(rate)
        channel = str(current.get("spairport_network_channel") or "")
        if channel:
            out["channel"] = channel.split()[0]
            band = re.search(r"(\d+(?:\.\d+)?)\s*GHz", channel)
            if band:
                out["band"] = f"{band.group(1)} GHz"
        phy = str(current.get("spairport_network_phymode") or "")
        if phy.startswith("802.11"):
            out["phy"] = phy
        signal = re.match(r"\s*(-?\d+)\s*dBm", str(current.get("spairport_signal_noise") or ""))
        if signal:
            out["signal_dbm"] = int(signal.group(1))
        return out
    return {}


def _macos() -> DeviceLink:
    interface = default_interface_macos(run_quietly(["/sbin/route", "-n", "get", "default"], 5))
    if not interface:
        return DeviceLink()
    ifconfig = run_quietly(["/sbin/ifconfig", interface], 5)
    ip = re.search(r"inet (\d+\.\d+\.\d+\.\d+)", ifconfig)
    port = hardware_ports().get(interface, "")
    kind = "Wi-Fi" if port.lower() in ("wi-fi", "airport") else ("Ethernet" if port else "")
    if kind == "" and interface.startswith("en"):
        kind = "Ethernet"
    fields: dict = {}
    if kind == "Wi-Fi":
        # It takes 5-20 s (longer while macOS scans for networks), and nearby
        # networks' names can hold control characters a strict parse rejects.
        try:
            data = json.loads(run_quietly(
                ["/usr/sbin/system_profiler", "SPAirPortDataType", "-json"], 40) or "{}",
                strict=False)
        except ValueError:
            data = {}
        fields = parse_airport(data, interface)
    else:
        fields.update(link_mbps=ethernet_mbps(ifconfig), duplex=duplex_of(ifconfig),
                      active=link_active(ifconfig), port=port)
    return DeviceLink(interface=interface, kind=kind or port or interface,
                      local_ip=ip.group(1) if ip else local_address(), **fields)


# ---------------------------------------------------------------- Windows


def parse_windows_adapter(output: str) -> dict:
    """PowerShell's adapter for the local address, as JSON."""
    try:
        data = json.loads(output)
    except ValueError:
        return {}
    if isinstance(data, list):
        data = data[0] if data else {}
    return data if isinstance(data, dict) else {}


def windows_speed_mbps(link_speed: object) -> float | None:
    """Get-NetAdapter's ReceiveLinkSpeed is in bit/s."""
    try:
        bits = float(link_speed)
    except (TypeError, ValueError):
        return None
    return bits / 1e6 if bits > 0 else None


def parse_netsh_wlan(output: str) -> dict:
    """``netsh wlan show interfaces``: SSID, band, radio type (802.11ax),
    channel, signal %, and the receive rate. Windows translates the labels ("Signal" is "สัญญาณ" in
    Thai), so where the English label isn't there, the values are told
    apart by their form: "86%" is the signal, "5 GHz" the band, and the
    first label with "(Mbps)" in it the receive rate."""
    pairs = []
    for line in output.splitlines():
        key, sep, value = line.partition(" : ")
        if not sep:
            key, sep, value = line.partition(":")
        if sep and key.strip():
            pairs.append((key.strip(), value.strip()))

    def labelled(*names: str) -> str:
        return next((v for k, v in pairs if k.casefold() in names), "")

    out: dict = {}
    ssid = labelled("ssid")
    if ssid:
        out["ssid"] = ssid
    band = labelled("band") or next((v for _, v in pairs if re.fullmatch(r"\d+(\.\d+)?\s*GHz", v)), "")
    band_match = re.search(r"(\d+(?:\.\d+)?)\s*GHz", band)
    if band_match:
        out["band"] = f"{band_match.group(1)} GHz"
    phy = labelled("radio type") or next(
        (v for _, v in pairs if re.fullmatch(r"802\.11\s*[a-z]+", v)), "")
    if phy:
        out["phy"] = phy
    channel = labelled("channel")
    if channel:
        out["channel"] = channel
    signal = labelled("signal") or next((v for _, v in pairs if re.fullmatch(r"\d+\s*%", v)), "")
    signal_match = re.match(r"(\d+)\s*%", signal)
    if signal_match:
        out["signal_percent"] = int(signal_match.group(1))
    rate = labelled("receive rate (mbps)") or next(
        (v for k, v in pairs if "(mbps)" in k.casefold()), "")
    rate_match = re.match(r"(\d+(?:\.\d+)?)", rate)
    if rate_match:
        out["link_mbps"] = float(rate_match.group(1))
    return out


#: PowerShell takes 1-5 s to start, so the adapter it describes is kept
#: for this long (or until the local address changes); the Wi-Fi details
#: come from netsh, which answers at once, on every read.
ADAPTER_TTL_S = 60.0
_adapter_cache: dict = {"ip": "", "at": 0.0, "adapter": {}}


def _windows_adapter(ip: str) -> dict:
    script = (f"Get-NetIPAddress -IPAddress '{ip}' | Get-NetAdapter | "
              "Select-Object Name,InterfaceDescription,ReceiveLinkSpeed,PhysicalMediaType,MediaType,"
              "FullDuplex,Status | "
              "ConvertTo-Json -Compress")
    return parse_windows_adapter(run_quietly(
        ["powershell", "-NoProfile", "-NonInteractive", "-Command", script], 15))


def _cached_adapter(ip: str, now: float | None = None) -> dict:
    """The adapter for `ip`: PowerShell's last answer while it's fresh,
    asked again otherwise. On a first ask, netsh runs meanwhile."""
    now = time.monotonic() if now is None else now
    cache = _adapter_cache
    if cache["adapter"] and cache["ip"] == ip and now - cache["at"] < ADAPTER_TTL_S:
        return cache["adapter"]
    adapter = _windows_adapter(ip)
    if adapter:
        cache.update(ip=ip, at=now, adapter=adapter)
    return adapter


def _windows() -> DeviceLink:
    ip = local_address()
    if not ip:
        return DeviceLink()
    # netsh runs alongside PowerShell, so a first read waits for the slower one only.
    with ThreadPoolExecutor(max_workers=1) as pool:
        wlan = pool.submit(run_quietly, ["netsh", "wlan", "show", "interfaces"], 10)
        adapter = _cached_adapter(ip)
        netsh = wlan.result()
    media = f"{adapter.get('PhysicalMediaType', '')} {adapter.get('MediaType', '')}".lower()
    wifi = "802.11" in media or "wireless" in media
    fields: dict = {"link_mbps": windows_speed_mbps(adapter.get("ReceiveLinkSpeed"))}
    if not wifi and adapter:
        duplex = adapter.get("FullDuplex")
        fields.update(port=str(adapter.get("InterfaceDescription") or ""),
                      duplex="Full duplex" if duplex is True else "Half duplex" if duplex is False else "",
                      active=str(adapter.get("Status") or "").lower() == "up")
    if wifi:
        fields.update({k: v for k, v in parse_netsh_wlan(netsh).items() if v})
    return DeviceLink(interface=str(adapter.get("Name") or ""),
                      kind="Wi-Fi" if wifi else ("Ethernet" if adapter else ""),
                      local_ip=ip, **fields)


_WIFI_FIELDS = ("link_mbps", "band", "phy", "channel", "signal_dbm", "signal_percent", "ssid")


def carry_over(previous: DeviceLink | None, current: DeviceLink) -> DeviceLink:
    """A read that came back without the Wi-Fi details (the tool timed out
    or answered badly) keeps the last ones, while it's the same Wi-Fi
    interface; anything it did read wins."""
    if (previous is None or not current.wifi or not previous.wifi
            or current.interface != previous.interface):
        return current
    missing = {f: getattr(previous, f) for f in _WIFI_FIELDS
               if getattr(current, f) in (None, "") and getattr(previous, f) not in (None, "")}
    return replace(current, **missing) if missing else current


def device_link() -> DeviceLink:
    """The link the default route uses; an empty DeviceLink when offline."""
    try:
        return _windows() if IS_WINDOWS else _macos()
    except Exception:  # a tool's odd output mustn't break the window
        return DeviceLink(local_ip=local_address())
