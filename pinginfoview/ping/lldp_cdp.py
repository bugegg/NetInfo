"""LLDP and CDP announcements heard on the Mac's own network ports: which
switch, port and VLAN each wired interface is plugged into.

Switches send an LLDP frame (IEEE 802.1AB, EtherType 0x88cc to
01:80:c2:00:00:0e) every 30 s by default, and Cisco gear a CDP frame
(802.3 + SNAP 00000c/2000 to 01:00:0c:cc:cc:cc) every 60 s. Neither crosses
a router, so they're read straight off each active ``enN`` interface through
BPF (/dev/bpf*), with a kernel filter so only those frames reach Python.
BPF needs no root when the user is in the ``access_bpf`` group, which
Wireshark's ChmodBPF sets up; otherwise opening it fails with a clear error.
"""

from __future__ import annotations

import ctypes
import fcntl
import ipaddress
import os
import select
import struct
import time
from collections.abc import Callable
from dataclasses import dataclass, field

#: Long enough for a 60 s CDP announcement to arrive.
DEFAULT_LISTEN_SECONDS = 65

LLDP_ETHERTYPE = 0x88CC
CDP_MULTICAST = bytes.fromhex("01000ccccccc")
_SNAP_CDP = bytes.fromhex("aaaa0300000c2000")

# <net/bpf.h> ioctls: _IO/_IOW/_IOWR('B', n, type).
_IOC_OUT, _IOC_IN = 0x40000000, 0x80000000


def _ioc(direction: int, number: int, size: int) -> int:
    return direction | ((size & 0x1FFF) << 16) | (ord("B") << 8) | number


BIOCSBLEN = _ioc(_IOC_IN | _IOC_OUT, 102, 4)
BIOCSETF = _ioc(_IOC_IN, 103, 16)  # struct bpf_program on 64-bit
BIOCPROMISC = _ioc(0x20000000, 105, 0)
BIOCGDLT = _ioc(_IOC_OUT, 106, 4)
BIOCSETIF = _ioc(_IOC_IN, 108, 32)  # struct ifreq
BIOCIMMEDIATE = _ioc(_IOC_IN, 112, 4)
BIOCSSEESENT = _ioc(_IOC_IN, 119, 4)
DLT_EN10MB = 1
BUFFER_SIZE = 1 << 16

#: Classic BPF: accept LLDP by EtherType, or anything sent to CDP's
#: multicast address; drop the rest in the kernel.
_FILTER = (
    (0x28, 0, 0, 12),  # ldh [12]            EtherType / 802.3 length
    (0x15, 4, 0, LLDP_ETHERTYPE),  # jeq 0x88cc -> accept
    (0x20, 0, 0, 0),  # ld [0]              first 4 bytes of the destination
    (0x15, 0, 3, 0x01000CCC),  # jeq 01:00:0c:cc -> next, else drop
    (0x28, 0, 0, 4),  # ldh [4]             last 2 bytes of the destination
    (0x15, 0, 1, 0xCCCC),  # jeq cc:cc -> accept, else drop
    (0x06, 0, 0, 0x40000),  # ret: accept (whole frame)
    (0x06, 0, 0, 0),  # ret: drop
)

#: LLDP system capability bits, low bit first.
LLDP_CAPABILITIES = (
    "Other", "Repeater", "Bridge", "WLAN AP", "Router", "Phone",
    "DOCSIS", "Station", "C-VLAN", "S-VLAN", "TPMR",
)
#: CDP capability bits.
CDP_CAPABILITIES = (
    (0x001, "Router"), (0x002, "Bridge"), (0x004, "Source-Route Bridge"),
    (0x008, "Switch"), (0x010, "Host"), (0x020, "IGMP"), (0x040, "Repeater"),
    (0x080, "Phone"), (0x100, "Remotely Managed"), (0x200, "CVTA"),
    (0x400, "TPMR"),
)


#: dot3MauType (RFC 4836) of the commonest links.
MAU_TYPES = {
    10: "10BASE-T half duplex", 11: "10BASE-T full duplex",
    15: "100BASE-TX half duplex", 16: "100BASE-TX full duplex",
    22: "1000BASE-X full duplex", 24: "1000BASE-LX full duplex",
    26: "1000BASE-SX full duplex", 29: "1000BASE-T half duplex",
    30: "1000BASE-T full duplex",
}
#: LLDP-MED device types and network policy applications (ANSI/TIA-1057).
MED_DEVICE_TYPES = {
    1: "Endpoint Class I", 2: "Endpoint Class II", 3: "Endpoint Class III",
    4: "Network Connectivity",
}
MED_APPLICATIONS = {
    1: "Voice", 2: "Voice Signaling", 3: "Guest Voice", 4: "Guest Voice Signaling",
    5: "Softphone Voice", 6: "Video Conferencing", 7: "Streaming Video",
    8: "Video Signaling",
}
#: LLDP-MED inventory TLV subtypes.
MED_INVENTORY = {
    5: "Hardware Revision", 6: "Firmware Revision", 7: "Software Revision",
    8: "Serial Number", 9: "Manufacturer", 10: "Model", 11: "Asset ID",
}
_OUI_8021, _OUI_8023, _OUI_MED = b"\x00\x80\xc2", b"\x00\x12\x0f", b"\x00\x12\xbb"


class CaptureError(OSError):
    """BPF couldn't be opened or set up for an interface."""


@dataclass(slots=True)
class Neighbor:
    interface: str  # the Mac's own interface it was heard on, e.g. "en7"
    protocol: str  # "LLDP" or "CDP"
    name: str  # the switch's system name / device ID
    port: str  # the switch port this Mac is plugged into, by name if known
    port_id: str = ""  # LLDP's raw port ID, when it isn't already `port`
    port_description: str = ""
    vlan: str = ""  # port / native VLAN
    address: str = ""  # management IPv4 address
    #: Where `address` came from when the switch didn't send one, e.g. "ARP".
    address_source: str = ""
    #: Every management address it advertised, e.g. "MAC dc:68:0c:70:ad:71".
    management: list[str] = field(default_factory=list)
    platform: str = ""  # model / OS, one line
    capabilities: str = ""
    chassis_id: str = ""  # LLDP only, usually a MAC
    description: str = ""  # the full system description / software version
    #: Everything else it said, as (field, value) in the order it came.
    details: list[tuple[str, str]] = field(default_factory=list)

    @property
    def key(self) -> tuple[str, str, str, str]:
        """Repeat announcements from the same switch port share this."""
        return (self.interface, self.protocol, self.chassis_id or self.name, self.port)

    @property
    def macs(self) -> list[str]:
        """The switch's own MACs it gave (chassis, port, management), for
        finding its IP in the ARP table when it didn't advertise one."""
        candidates = [self.chassis_id, self.port_id or self.port]
        candidates += [m.removeprefix("MAC ") for m in self.management if m.startswith("MAC ")]
        return list(dict.fromkeys(
            c for c in candidates if len(c) == 17 and c.count(":") == 5
        ))


# -- decoding ----------------------------------------------------------------


def _text(value: bytes) -> str:
    """A string field as text, or as hex when it isn't printable."""
    value = value.rstrip(b"\0")
    try:
        text = value.decode("utf-8")
    except UnicodeDecodeError:
        return _hex(value)
    if all(c.isprintable() or c in "\r\n\t" for c in text):
        return text.strip()
    return _hex(value)


def _hex(value: bytes) -> str:
    return ":".join(f"{b:02x}" for b in value)


def _first_line(text: str) -> str:
    return next((line.strip() for line in text.splitlines() if line.strip()), "")


def _lldp_id(subtype: int, value: bytes, mac_subtype: int, address_subtype: int) -> str:
    """A chassis or port ID: a MAC, an address (IANA family 1 = IPv4), or text."""
    if subtype == mac_subtype and len(value) == 6:
        return _hex(value)
    if subtype == address_subtype and len(value) == 5 and value[0] == 1:
        return ".".join(map(str, value[1:]))
    return _text(value)


def lldp_capabilities(mask: int) -> str:
    return ", ".join(name for bit, name in enumerate(LLDP_CAPABILITIES) if mask & (1 << bit))


def cdp_capabilities(mask: int) -> str:
    return ", ".join(name for bit, name in CDP_CAPABILITIES if mask & bit)


def _management_address(value: bytes) -> str:
    """An LLDP Management Address: string length (subtype + address),
    IANA address family, the address; then interface numbering and an OID,
    which aren't shown."""
    if len(value) < 2:
        return ""
    address = value[2:1 + value[0]]
    family = value[1]
    if family == 1 and len(address) == 4:
        return f"IPv4 {ipaddress.IPv4Address(address)}"
    if family == 2 and len(address) == 16:
        return f"IPv6 {ipaddress.IPv6Address(address)}"
    if family == 6 and len(address) == 6:  # all802: a MAC
        return f"MAC {_hex(address)}"
    return f"family {family} {_hex(address)}"


def _link_aggregation(value: bytes) -> str:
    """802.1/802.3 Link Aggregation: status bits, then the aggregate's port."""
    if len(value) < 5:
        return ""
    status, port = value[0], int.from_bytes(value[1:5], "big")
    if not status & 0x01:
        return "not capable"
    if status & 0x02:
        return f"aggregated (port {port})"
    return "capable, not aggregated"


def _org_specific(oui: bytes, subtype: int, value: bytes, fields: dict[str, str],
                  details: list[tuple[str, str]]) -> None:
    """The IEEE 802.1 / 802.3 and LLDP-MED extension TLVs."""
    if oui == _OUI_8021:
        if subtype == 1 and len(value) >= 2:
            fields["vlan"] = str(int.from_bytes(value[:2], "big"))  # Port VLAN ID
        elif subtype == 2 and len(value) >= 3:
            vid = int.from_bytes(value[1:3], "big")
            if vid:
                details.append(("Protocol VLAN", str(vid)))
        elif subtype == 3 and len(value) >= 3:
            vid, name = int.from_bytes(value[:2], "big"), _text(value[3:3 + value[2]])
            details.append(("VLAN Name", f"{vid} {name}".strip()))
        elif subtype == 7:
            details.append(("Link Aggregation", _link_aggregation(value)))
        else:
            details.append((f"802.1 TLV {subtype}", _hex(value)))
    elif oui == _OUI_8023:
        if subtype == 1 and len(value) >= 5:
            autoneg, mau = value[0], int.from_bytes(value[3:5], "big")
            link = MAU_TYPES.get(mau, f"MAU type {mau}")
            if autoneg & 0x01:
                link += ", auto-negotiation " + ("on" if autoneg & 0x02 else "off")
            details.append(("Link", link))
        elif subtype == 2 and value:
            flags = value[0]
            kind = "PSE (switch supplies power)" if flags & 0x01 else "PD (powered device)"
            if not flags & 0x02:
                state = "not supported"
            else:
                state = "enabled" if flags & 0x04 else "disabled"
            details.append(("PoE", f"{kind}, {state}"))
        elif subtype == 3:
            details.append(("Link Aggregation", _link_aggregation(value)))
        elif subtype == 4 and len(value) >= 2:
            details.append(("Max Frame Size", f"{int.from_bytes(value[:2], 'big')} bytes"))
        else:
            details.append((f"802.3 TLV {subtype}", _hex(value)))
    elif oui == _OUI_MED:
        if subtype == 1 and len(value) >= 3:
            details.append(("MED Device Type", MED_DEVICE_TYPES.get(value[2], str(value[2]))))
        elif subtype == 2 and len(value) >= 4:
            bits = int.from_bytes(value[1:4], "big")
            app = MED_APPLICATIONS.get(value[0], f"application {value[0]}")
            if bits & 0x800000:
                details.append(("Network Policy", f"{app}: not configured"))
            else:
                vlan = (bits >> 9) & 0xFFF
                tagged = "tagged" if bits & 0x400000 else "untagged"
                details.append((
                    "Network Policy",
                    f"{app}: VLAN {vlan} {tagged}, priority {(bits >> 6) & 7}, DSCP {bits & 0x3F}",
                ))
        elif subtype == 4 and len(value) >= 3:
            watts = int.from_bytes(value[1:3], "big") / 10
            if watts:
                details.append(("PoE Power", f"{watts:g} W"))
        elif subtype in MED_INVENTORY:
            text = _text(value)
            if text:
                details.append((MED_INVENTORY[subtype], text))
    else:
        details.append((f"TLV {_hex(oui)}/{subtype}", _hex(value)))


def parse_lldp(payload: bytes, interface: str = "") -> Neighbor | None:
    """An LLDPDU (the frame after its EtherType), or None if malformed."""
    fields: dict[str, str] = {}
    details: list[tuple[str, str]] = []
    management: list[str] = []
    chassis = port = ""
    port_is_mac = False
    capabilities = supported = 0
    offset = 0
    while offset + 2 <= len(payload):
        header = int.from_bytes(payload[offset:offset + 2], "big")
        kind, length = header >> 9, header & 0x1FF
        value = payload[offset + 2:offset + 2 + length]
        offset += 2 + length
        if kind == 0 or len(value) < length:
            break  # End of LLDPDU, or truncated
        if kind == 1 and value:
            chassis = _lldp_id(value[0], value[1:], mac_subtype=4, address_subtype=5)
        elif kind == 2 and value:
            port = _lldp_id(value[0], value[1:], mac_subtype=3, address_subtype=4)
            port_is_mac = value[0] == 3
        elif kind == 3 and len(value) >= 2:
            details.append(("TTL", f"{int.from_bytes(value[:2], 'big')} s"))
        elif kind == 4:
            fields["port_description"] = _text(value)
        elif kind == 5:
            fields["name"] = _text(value)
        elif kind == 6:
            fields["description"] = _text(value)
        elif kind == 7 and len(value) >= 4:
            supported, enabled = struct.unpack("!HH", value[:4])
            capabilities = enabled or supported
        elif kind == 8:
            address = _management_address(value)
            if address:
                management.append(address)
        elif kind == 127 and len(value) >= 4:
            _org_specific(value[:3], value[3], value[4:], fields, details)
        else:
            details.append((f"TLV {kind}", _hex(value)))
    if not chassis and not port:
        return None
    if supported and supported != capabilities:
        details.insert(0, ("Capabilities Supported", lldp_capabilities(supported)))
    description = fields.get("description", "")
    port_description = fields.get("port_description", "")
    ipv4 = next((a.removeprefix("IPv4 ") for a in management if a.startswith("IPv4 ")), "")
    return Neighbor(
        interface=interface,
        protocol="LLDP",
        name=fields.get("name") or chassis,
        # A MAC says little to a person (HPE Comware sends one); the
        # description names the port there.
        port=(port_description if port_is_mac else port) or port or port_description,
        port_id=port if port_is_mac and port_description else "",
        port_description=port_description,
        vlan=fields.get("vlan", ""),
        address=ipv4,
        management=management,
        platform=_first_line(description),
        capabilities=lldp_capabilities(capabilities),
        chassis_id=chassis,
        description=description,
        details=details,
    )


def _cdp_addresses(value: bytes) -> list[str]:
    """IPv4 entries of a CDP Addresses TLV."""
    if len(value) < 4:
        return []
    count = int.from_bytes(value[:4], "big")
    addresses = []
    offset = 4
    for _ in range(count):
        if offset + 2 > len(value):
            break
        proto_type, proto_len = value[offset], value[offset + 1]
        proto = value[offset + 2:offset + 2 + proto_len]
        offset += 2 + proto_len
        addr_len = int.from_bytes(value[offset:offset + 2], "big")
        address = value[offset + 2:offset + 2 + addr_len]
        offset += 2 + addr_len
        if proto_type == 1 and proto == b"\xcc" and len(address) == 4:  # NLPID IP
            addresses.append(".".join(map(str, address)))
    return addresses


def parse_cdp(payload: bytes, interface: str = "") -> Neighbor | None:
    """A CDP packet (after the SNAP header), or None if malformed."""
    if len(payload) < 4:
        return None
    fields: dict[str, str] = {}
    addresses: list[str] = []
    capabilities = 0
    offset = 4  # version, TTL, checksum
    while offset + 4 <= len(payload):
        kind, length = struct.unpack("!HH", payload[offset:offset + 4])
        if length < 4 or offset + length > len(payload):
            break  # malformed or truncated
        value = payload[offset + 4:offset + length]
        offset += length
        if kind == 0x01:
            fields["name"] = _text(value)
        elif kind in (0x02, 0x16):  # Addresses, Management Addresses
            addresses += _cdp_addresses(value)
        elif kind == 0x03:
            fields["port"] = _text(value)
        elif kind == 0x04 and len(value) >= 4:
            capabilities = int.from_bytes(value[:4], "big")
        elif kind == 0x05:
            fields["description"] = _text(value)
        elif kind == 0x06:
            fields["platform"] = _text(value)
        elif kind == 0x0A and len(value) >= 2:
            fields["vlan"] = str(int.from_bytes(value[:2], "big"))
    if "name" not in fields:
        return None
    return Neighbor(
        interface=interface,
        protocol="CDP",
        name=fields["name"],
        port=fields.get("port", ""),
        vlan=fields.get("vlan", ""),
        address=addresses[0] if addresses else "",
        platform=fields.get("platform") or _first_line(fields.get("description", "")),
        capabilities=cdp_capabilities(capabilities),
        description=fields.get("description", ""),
    )


def parse_frame(frame: bytes, interface: str = "") -> Neighbor | None:
    """An Ethernet frame carrying LLDP or CDP, or None for anything else."""
    if len(frame) < 14:
        return None
    ethertype = int.from_bytes(frame[12:14], "big")
    if ethertype == 0x8100 and len(frame) >= 18:  # 802.1Q-tagged
        ethertype = int.from_bytes(frame[16:18], "big")
        body = frame[18:]
    else:
        body = frame[14:]
    if ethertype == LLDP_ETHERTYPE:
        return parse_lldp(body, interface)
    if frame[:6] == CDP_MULTICAST and ethertype <= 1500 and body[:8] == _SNAP_CDP:
        return parse_cdp(body[8:], interface)
    return None


def split_bpf_buffer(buffer: bytes) -> list[bytes]:
    """The captured frames in one read() from /dev/bpf. Each has a struct
    bpf_hdr in front (32-bit timeval on macOS, then caplen, datalen and
    hdrlen) and the next one starts at a 4-byte boundary."""
    frames = []
    offset = 0
    while offset + 18 <= len(buffer):
        caplen = int.from_bytes(buffer[offset + 8:offset + 12], "little")
        hdrlen = int.from_bytes(buffer[offset + 16:offset + 18], "little")
        if not hdrlen:
            break
        frames.append(buffer[offset + hdrlen:offset + hdrlen + caplen])
        offset += (hdrlen + caplen + 3) & ~3
    return frames


# -- capture -----------------------------------------------------------------


class _BpfInsn(ctypes.Structure):
    _fields_ = [
        ("code", ctypes.c_uint16), ("jt", ctypes.c_uint8),
        ("jf", ctypes.c_uint8), ("k", ctypes.c_uint32),
    ]


class _BpfProgram(ctypes.Structure):
    _fields_ = [("bf_len", ctypes.c_uint), ("bf_insns", ctypes.POINTER(_BpfInsn))]


def open_bpf(interface: str) -> int:
    """A /dev/bpf descriptor bound to `interface`, filtered to LLDP and CDP
    frames from others, in promiscuous mode (the NIC may not otherwise
    accept those multicast addresses)."""
    fd = -1
    denied = False
    for number in range(256):
        try:
            fd = os.open(f"/dev/bpf{number}", os.O_RDONLY | os.O_NONBLOCK)
            break
        except FileNotFoundError:
            break
        except PermissionError:
            denied = True
            break
        except OSError:
            continue  # busy; try the next one
    if fd < 0:
        if denied:
            raise CaptureError(
                "No permission to capture packets (/dev/bpf). Install Wireshark's "
                "ChmodBPF, or add this user to the access_bpf group"
            )
        raise CaptureError("No free /dev/bpf device")
    try:
        fcntl.ioctl(fd, BIOCSBLEN, struct.pack("I", BUFFER_SIZE))
        fcntl.ioctl(fd, BIOCSETIF, interface.encode().ljust(32, b"\0"))
        dlt = struct.unpack("I", fcntl.ioctl(fd, BIOCGDLT, b"\0" * 4))[0]
        if dlt != DLT_EN10MB:
            raise CaptureError(f"{interface} is not an Ethernet interface")
        fcntl.ioctl(fd, BIOCIMMEDIATE, struct.pack("I", 1))
        fcntl.ioctl(fd, BIOCSSEESENT, struct.pack("I", 0))
        insns = (_BpfInsn * len(_FILTER))(*(_BpfInsn(*insn) for insn in _FILTER))
        program = _BpfProgram(len(_FILTER), insns)
        fcntl.ioctl(fd, BIOCSETF, bytes(program))
        try:
            fcntl.ioctl(fd, BIOCPROMISC)
        except OSError:
            pass  # still hears whatever the NIC already accepts
    except OSError as error:
        os.close(fd)
        if isinstance(error, CaptureError):
            raise
        raise CaptureError(f"Can't capture on {interface}: {error.strerror or error}") from error
    return fd


def listen(
    interfaces: list[str],
    on_neighbor: Callable[[Neighbor], None],
    seconds: float = DEFAULT_LISTEN_SECONDS,
    stopped: Callable[[], bool] = lambda: False,
    on_error: Callable[[str, str], None] = lambda interface, message: None,
) -> None:
    """Listen on each interface for `seconds`, reporting each switch port
    once, as soon as it's heard. Interfaces that can't be opened are
    reported through on_error and skipped."""
    descriptors: dict[int, str] = {}
    for interface in interfaces:
        try:
            descriptors[open_bpf(interface)] = interface
        except CaptureError as error:
            on_error(interface, str(error))
    seen: set[tuple[str, str, str, str]] = set()
    deadline = time.monotonic() + seconds
    try:
        while descriptors and not stopped():
            left = deadline - time.monotonic()
            if left <= 0:
                break
            ready, _, _ = select.select(list(descriptors), [], [], min(left, 0.25))
            for fd in ready:
                try:
                    buffer = os.read(fd, BUFFER_SIZE)
                except BlockingIOError:
                    continue
                except OSError as error:  # e.g. the adapter was unplugged
                    on_error(descriptors.pop(fd), str(error))
                    os.close(fd)
                    continue
                for frame in split_bpf_buffer(buffer):
                    neighbor = parse_frame(frame, descriptors[fd])
                    if neighbor is not None and neighbor.key not in seen:
                        seen.add(neighbor.key)
                        on_neighbor(neighbor)
    finally:
        for fd in descriptors:
            os.close(fd)
