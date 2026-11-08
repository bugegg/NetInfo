from NetInfoView.ping import device_link as dl
from NetInfoView.ping.device_link import DeviceLink, strength

AIRPORT = {"SPAirPortDataType": [{"spairport_airport_interfaces": [
    {"_name": "en0", "spairport_current_network_information": {
        "_name": "<redacted>", "spairport_network_channel": "40 (5GHz, 160MHz)",
        "spairport_network_rate": 1297, "spairport_network_phymode": "802.11ax",
        "spairport_signal_noise": "-58 dBm / -93 dBm"}},
    {"_name": "awdl0", "spairport_current_network_information": {}},
]}]}

NETSH = """
There is 1 interface on the system:

    Name                   : Wi-Fi
    Description            : Intel(R) Wi-Fi 6 AX201 160MHz
    State                  : connected
    SSID                   : Home Network
    BSSID                  : aa:bb:cc:dd:ee:ff
    Radio type             : 802.11ax
    Band                   : 5 GHz
    Channel                : 36
    Receive rate (Mbps)    : 1201
    Transmit rate (Mbps)   : 960
    Signal                 : 86%
"""


def test_parse_airport_hides_a_redacted_name():
    assert dl.parse_airport(AIRPORT, "en0") == {
        "link_mbps": 1297.0, "channel": "40", "band": "5 GHz", "phy": "802.11ax",
        "signal_dbm": -58}
    assert dl.parse_airport(AIRPORT, "awdl0") == {}
    assert dl.parse_airport({}, "en0") == {}


def test_parse_airport_keeps_a_visible_name():
    data = {"SPAirPortDataType": [{"spairport_airport_interfaces": [{"_name": "en0",
            "spairport_current_network_information": {"_name": "Office"}}]}]}
    assert dl.parse_airport(data, "en0") == {"ssid": "Office"}


def test_default_interface_and_ethernet_speed():
    assert dl.default_interface_macos("   route to: default\n  interface: en7\n") == "en7"
    assert dl.ethernet_mbps("\tmedia: autoselect (1000baseT <full-duplex>)") == 1000
    assert dl.ethernet_mbps("\tmedia: autoselect (10Gbase-T <full-duplex>)") == 10000
    assert dl.ethernet_mbps("\tmedia: autoselect (2500Base-T <full-duplex>)") == 2500
    assert dl.ethernet_mbps("\tmedia: autoselect") is None


def test_parse_netsh_wlan():
    assert dl.parse_netsh_wlan(NETSH) == {
        "ssid": "Home Network", "band": "5 GHz", "phy": "802.11ax", "channel": "36",
        "signal_percent": 86, "link_mbps": 1201.0}


def test_windows_adapter_parsing():
    assert dl.parse_windows_adapter('{"Name":"Ethernet","ReceiveLinkSpeed":1000000000}')["Name"] == "Ethernet"
    assert dl.parse_windows_adapter('[{"Name":"A"},{"Name":"B"}]')["Name"] == "A"
    assert dl.parse_windows_adapter("") == {}
    assert dl.windows_speed_mbps(1000000000) == 1000
    assert dl.windows_speed_mbps(None) is None


def test_strength():
    assert strength(DeviceLink(signal_dbm=-55)) == ("Strong", 4)
    assert strength(DeviceLink(signal_dbm=-65)) == ("Good", 3)
    assert strength(DeviceLink(signal_dbm=-72)) == ("Fair", 2)
    assert strength(DeviceLink(signal_dbm=-85)) == ("Weak", 1)
    assert strength(DeviceLink(signal_percent=86)) == ("Strong", 4)
    assert strength(DeviceLink()) == ("", 0)


def test_wired_media_line():
    line = "\tmedia: autoselect (1000baseT <full-duplex,flow-control>)\n\tstatus: active\n"
    assert dl.ethernet_mbps(line) == 1000
    assert dl.duplex_of(line) == "Full duplex"
    assert dl.link_active(line) is True
    assert dl.duplex_of("\tmedia: autoselect (100baseTX <half-duplex>)") == "Half duplex"
    assert dl.link_active("\tstatus: inactive") is False
    assert dl.duplex_of("\tmedia: none") == "" and dl.link_active("") is None


def test_lenient_json_and_carry_over():
    import json
    raw = '{"SPAirPortDataType": [{"spairport_airport_interfaces": [{"_name": "en0", ' \
          '"spairport_current_network_information": {"_name": "Wi\x01Fi", "spairport_network_rate": 1814}}]}]}'
    assert dl.parse_airport(json.loads(raw, strict=False), "en0")["link_mbps"] == 1814
    before = DeviceLink(interface="en0", kind="Wi-Fi", local_ip="10.0.0.2", link_mbps=1814.0,
                        band="5 GHz", signal_dbm=-53)
    blank = DeviceLink(interface="en0", kind="Wi-Fi", local_ip="10.0.0.2")
    kept = dl.carry_over(before, blank)
    assert (kept.link_mbps, kept.band, kept.signal_dbm) == (1814.0, "5 GHz", -53)
    fresh = DeviceLink(interface="en0", kind="Wi-Fi", local_ip="10.0.0.2", link_mbps=866.0)
    assert dl.carry_over(before, fresh).link_mbps == 866.0  # a new reading wins
    wired = DeviceLink(interface="en7", kind="Ethernet", local_ip="10.0.0.3", link_mbps=None)
    assert dl.carry_over(before, wired) is wired  # a different link keeps nothing


NETSH_THAI = """
มีอินเทอร์เฟซ 1 รายการบนระบบ:

    ชื่อ                   : Wi-Fi
    สถานะ                 : เชื่อมต่อแล้ว
    SSID                   : Home Network
    ชนิดของวิทยุ           : 802.11ax
    แบนด์                  : 5 GHz
    ช่องสัญญาณ             : 36
    อัตราการรับ (Mbps)     : 1201
    อัตราการส่ง (Mbps)     : 960
    สัญญาณ                 : 86%
"""


def test_parse_netsh_wlan_in_another_language():
    assert dl.parse_netsh_wlan(NETSH_THAI) == {
        "ssid": "Home Network", "band": "5 GHz", "phy": "802.11ax", "signal_percent": 86,
        "link_mbps": 1201.0}


def test_wifi_generation():
    assert dl.wifi_generation("802.11ax") == "Wi-Fi 6"
    assert dl.wifi_generation("802.11ax", "6 GHz") == "Wi-Fi 6E"
    assert dl.wifi_generation("802.11be", "6 GHz") == "Wi-Fi 7"
    assert [dl.wifi_generation(f"802.11{x}") for x in ("b", "a", "g", "n", "ac")] == [
        f"Wi-Fi {n}" for n in range(1, 6)]
    assert dl.wifi_generation("") == dl.wifi_generation("802.11zz") == ""


def test_windows_adapter_is_cached_until_stale_or_the_address_changes(monkeypatch):
    calls = []
    monkeypatch.setattr(dl, "_windows_adapter", lambda ip: calls.append(ip) or {"Name": ip})
    monkeypatch.setattr(dl, "_adapter_cache", {"ip": "", "at": 0.0, "adapter": {}})
    assert dl._cached_adapter("10.0.0.2", now=100.0) == {"Name": "10.0.0.2"}
    dl._cached_adapter("10.0.0.2", now=100.0 + dl.ADAPTER_TTL_S - 1)
    assert calls == ["10.0.0.2"]
    dl._cached_adapter("10.0.0.3", now=101.0)
    dl._cached_adapter("10.0.0.3", now=101.0 + dl.ADAPTER_TTL_S)
    assert calls == ["10.0.0.2", "10.0.0.3", "10.0.0.3"]
