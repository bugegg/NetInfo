"""Port Scan: which TCP and UDP ports one host has open.

A plain scan of one host over a list or range of ports the user picks, run
on demand from its own window (ui/port_scan_window.py). Unlike
ping/port_scan.py (a short fixed probe that feeds the grid's Open Ports
column and device-type guess for every host), this covers any range, up to
all 65535 ports, and says what each open port is: its usual service and,
when the service speaks first (SSH, FTP, SMTP, Telnet, ...), the first line
it sends.

TCP is an ordinary connect(): open (handshake done), closed (refused) or
filtered (no answer). UDP has no handshake, so each well-known UDP service
is sent a real request of its own kind (a DNS query to 53, an NTP request
to 123, an SNMP GET to 161, ...) that it will answer, and any other port an
empty datagram: a reply means open, an ICMP port-unreachable means closed,
and silence is "open|filtered" — the port may be open but ignoring us, or a
firewall may drop it; no scanner can tell those apart from outside.

Still no SYN/stealth scanning and no OS or product fingerprinting.
"""

from __future__ import annotations

import random
import re
import socket
import ssl
import struct
import time
from collections.abc import Callable, Iterable
from concurrent.futures import FIRST_COMPLETED, Future, ThreadPoolExecutor, wait
from dataclasses import dataclass

from . import dhcp_probe, dns_ptr, netbios, snmp, ssdp, tls_cert

TCP, UDP = "tcp", "udp"
#: A scan job's protocol for one UDP try without a retry (recheck_udp).
UDP_ONCE = "udp-once"
OPEN, CLOSED, FILTERED = "open", "closed", "filtered"
#: A UDP port that sent nothing back: open but silent, or firewalled.
OPEN_FILTERED = "open|filtered"

DEFAULT_TIMEOUT = 1.0
#: How long an open TCP port is given to send a greeting of its own.
BANNER_TIMEOUT = 1.0
#: A silent UDP port is asked this many times (the timeout split between
#: them), since a single datagram or its reply can simply be lost.
UDP_ATTEMPTS = 2
#: Most rounds recheck_udp asks the silent UDP ports again.
RECHECK_MAX_ROUNDS = 600
#: Probes in flight at once. Kept under the raised file-descriptor limit
#: (__main__.py) with plenty to spare for the rest of the app.
MAX_WORKERS = 256

#: Well-known TCP ports and the service usually behind them. The "Common
#: ports" preset scans exactly these; any other port is named from the OS's
#: services database, if it knows it.
COMMON_SERVICES: dict[int, str] = {
    20: "FTP-data", 21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    79: "Finger", 80: "HTTP", 81: "HTTP-alt", 88: "Kerberos", 110: "POP3",
    111: "RPCbind", 113: "Ident", 119: "NNTP", 135: "MS-RPC", 139: "NetBIOS",
    143: "IMAP", 179: "BGP", 389: "LDAP", 427: "SLP", 443: "HTTPS", 445: "SMB",
    465: "SMTPS", 513: "rlogin", 514: "rsh", 515: "LPD", 548: "AFP",
    554: "RTSP", 587: "SMTP Submission", 631: "IPP", 636: "LDAPS", 646: "LDP",
    830: "NETCONF", 873: "rsync", 902: "VMware", 990: "FTPS", 993: "IMAPS",
    995: "POP3S", 1080: "SOCKS", 1194: "OpenVPN", 1433: "MS SQL",
    1521: "Oracle", 1723: "PPTP", 1883: "MQTT", 2000: "Cisco SCCP",
    2049: "NFS", 2222: "SSH-alt", 2375: "Docker", 2376: "Docker TLS",
    3000: "HTTP-dev", 3128: "Squid", 3268: "LDAP GC", 3306: "MySQL",
    3389: "RDP", 3690: "SVN", 4443: "HTTPS-alt", 4786: "Cisco Smart Install",
    5000: "UPnP/HTTP", 5060: "SIP", 5061: "SIP-TLS", 5222: "XMPP",
    5432: "PostgreSQL", 5555: "ADB", 5601: "Kibana", 5900: "VNC",
    5901: "VNC-1", 5985: "WinRM", 5986: "WinRM-HTTPS", 6000: "X11",
    6379: "Redis", 6443: "Kubernetes API", 6667: "IRC", 7547: "TR-069",
    8000: "HTTP-alt", 8006: "Proxmox", 8008: "HTTP-alt", 8080: "HTTP-proxy",
    8081: "HTTP-alt", 8088: "HTTP-alt", 8291: "MikroTik Winbox",
    8443: "HTTPS-alt", 8728: "MikroTik API", 8729: "MikroTik API-SSL",
    8883: "MQTT-TLS", 8888: "HTTP-alt", 9000: "HTTP-alt", 9090: "HTTP-alt",
    9100: "RAW Print", 9200: "Elasticsearch", 9418: "Git", 9443: "HTTPS-alt",
    10000: "Webmin", 11211: "Memcached", 27017: "MongoDB", 62078: "iOS Sync",
}

#: Well-known UDP ports, for the "Common ports" preset with UDP. Those in
#: _UDP_PROBES get a request they answer; the rest an empty datagram.
COMMON_UDP_SERVICES: dict[int, str] = {
    53: "DNS", 67: "DHCP Server", 69: "TFTP", 111: "RPCbind", 123: "NTP",
    137: "NetBIOS-NS", 138: "NetBIOS-DGM", 161: "SNMP", 162: "SNMP Trap",
    177: "XDMCP", 500: "IKE", 514: "Syslog", 520: "RIP", 623: "IPMI",
    1194: "OpenVPN", 1434: "MS SQL Browser", 5683: "CoAP", 1645: "RADIUS (old)",
    1701: "L2TP", 1812: "RADIUS", 1813: "RADIUS Accounting", 1900: "SSDP/UPnP",
    2049: "NFS", 2055: "NetFlow", 3478: "STUN", 3702: "WS-Discovery",
    4500: "IPsec NAT-T", 4789: "VXLAN", 5060: "SIP", 5351: "NAT-PMP",
    5353: "mDNS", 5355: "LLMNR", 6343: "sFlow", 10001: "Ubiquiti Discovery",
    11211: "Memcached", 47808: "BACnet",
}

COMMON = "common"
#: The window's port presets: label -> port spec (parse_port_spec), or
#: COMMON for the common list of each protocol. Empty means "type your own".
PRESETS: tuple[tuple[str, str], ...] = (
    ("Common ports", COMMON),
    ("Well-known (1–1024)", "1-1024"),
    ("All ports (1–65535)", "1-65535"),
    ("Custom…", ""),
)


@dataclass(slots=True)
class PortResult:
    port: int
    state: str
    service: str = ""
    #: The first line the service sent (TCP greeting, UDP reply), if any.
    banner: str = ""
    #: Time to the handshake (TCP) or the reply (UDP), for an open port.
    rtt_ms: float = 0.0
    protocol: str = TCP

    @property
    def label(self) -> str:
        return f"{self.port}/{self.protocol}"


@dataclass(slots=True)
class ScanSummary:
    host: str
    ip: str = ""
    #: Why the scan couldn't run (bad ports, name doesn't resolve); empty
    #: when it ran.
    error: str = ""
    total: int = 0
    scanned: int = 0
    open: int = 0
    closed: int = 0
    filtered: int = 0
    open_filtered: int = 0
    stopped: bool = False
    elapsed_s: float = 0.0

    def count(self, state: str) -> None:
        self.scanned += 1
        if state == OPEN:
            self.open += 1
        elif state == CLOSED:
            self.closed += 1
        elif state == OPEN_FILTERED:
            self.open_filtered += 1
        else:
            self.filtered += 1


def parse_port_spec(text: str) -> list[int]:
    """Ports from text like ``"22, 80 443 8000-8100"``, sorted, no repeats.

    Commas and whitespace separate; ``a-b`` is a range (either way round).
    Raises ValueError naming the first bad piece, since this runs only when
    Scan is pressed and silently scanning less than asked would mislead.
    """
    ports: set[int] = set()
    for token in text.replace(",", " ").split():
        first, dash, last = token.partition("-")
        try:
            low = int(first)
            high = int(last) if dash else low
        except ValueError:
            raise ValueError(f"\"{token}\" is not a port or range") from None
        if low > high:
            low, high = high, low
        if not (1 <= low and high <= 65535):
            raise ValueError(f"\"{token}\" is outside 1–65535")
        ports.update(range(low, high + 1))
    return sorted(ports)


def jobs_for(spec: str, protocols: Iterable[str]) -> list[tuple[str, int]]:
    """Every (protocol, port) to probe: `spec` is a port spec or COMMON."""
    jobs: list[tuple[str, int]] = []
    for protocol in protocols:
        if spec == COMMON:
            ports = sorted(COMMON_SERVICES if protocol == TCP else COMMON_UDP_SERVICES)
        else:
            ports = parse_port_spec(spec)
        jobs += [(protocol, port) for port in ports]
    return jobs


def service_name(port: int, protocol: str = TCP) -> str:
    known = COMMON_SERVICES if protocol == TCP else COMMON_UDP_SERVICES
    if port in known:
        return known[port]
    try:
        return socket.getservbyport(port, protocol)
    except OSError:
        return ""


def resolve(host: str) -> str:
    """The address to scan for a name or address, IPv4 preferred. Raises
    OSError if it doesn't resolve."""
    infos = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
    if not infos:
        raise OSError(f"{host} has no address")
    infos.sort(key=lambda info: info[0] != socket.AF_INET)
    return infos[0][4][0]


#: Telnet option negotiation (IAC, command, option) that a Telnet server
#: sends before any text.
_TELNET_IAC = re.compile(rb"\xff[\xfb-\xfe].|\xff[\xf0-\xfa]", re.DOTALL)


def clean_banner(data: bytes) -> str:
    """The first non-empty line of a greeting, printable characters only
    (Telnet negotiation and other binary bytes dropped)."""
    text = _TELNET_IAC.sub(b"", data).decode("utf-8", "replace")
    for line in text.splitlines():
        line = "".join(ch for ch in line if ch.isprintable() and ch != "\ufffd").strip()
        if line:
            return line[:200]
    return ""


#: Ports where a TLS handshake is tried before plain HTTP.
TLS_FIRST_PORTS = {443, 465, 636, 990, 993, 995, 2376, 4443, 5061, 5986, 6443, 8006,
                   8443, 8729, 8883, 9443}


def _recv_some(sock: socket.socket, timeout: float, limit: int = 4096) -> bytes:
    """What arrives within `timeout` (until the peer closes or `limit`)."""
    sock.settimeout(timeout)
    data = b""
    deadline = time.monotonic() + timeout
    try:
        while len(data) < limit:
            sock.settimeout(max(deadline - time.monotonic(), 0.01))
            chunk = sock.recv(limit - len(data))
            if not chunk:
                break
            data += chunk
            if b"\r\n\r\n" in data:
                break
    except OSError:
        pass
    return data


def read_greeting(sock: socket.socket, timeout: float) -> str:
    """The first line of text a service sends by itself within `timeout`.
    Reads on past Telnet negotiation, which comes before the text."""
    data = b""
    deadline = time.monotonic() + timeout
    try:
        while len(data) < 2048:
            sock.settimeout(max(deadline - time.monotonic(), 0.01))
            chunk = sock.recv(1024)
            if not chunk:
                break
            data += chunk
            text = _TELNET_IAC.sub(b"", data)
            if clean_banner(text) and b"\n" in text.lstrip(b"\r\n"):
                break
    except OSError:
        pass
    return clean_banner(data)


def describe_http(response: bytes) -> str:
    """"HTTP 200 · nginx/1.24" from a response's status line and Server
    header, or "" if it isn't an HTTP response."""
    if not response.startswith(b"HTTP/"):
        return ""
    head = response.split(b"\r\n\r\n", 1)[0].decode("latin-1", "replace").splitlines()
    status = head[0].split(" ", 2)
    text = f"HTTP {status[1]}" if len(status) > 1 else "HTTP"
    for line in head[1:]:
        name, _, value = line.partition(":")
        if name.strip().lower() == "server" and value.strip():
            text += f" · {clean_banner(value.encode('latin-1', 'replace'))}"
            break
    return text


def _http_request(ip: str) -> bytes:
    return f"HEAD / HTTP/1.0\r\nHost: {ip}\r\nUser-Agent: NetInfoView\r\n\r\n".encode()


def _identify_http(ip: str, port: int, timeout: float) -> tuple[str, bool]:
    """(description, looks like TLS) from a plain HTTP request."""
    try:
        with socket.create_connection((ip, port), timeout=timeout) as sock:
            sock.sendall(_http_request(ip))
            reply = _recv_some(sock, timeout)
    except OSError:
        return "", False
    # A TLS alert, or a web server complaining it got plain HTTP.
    tls = reply[:1] == b"\x15" or b"HTTPS port" in reply or b"TLS" in reply[:200]
    return ("" if tls else describe_http(reply)), tls


def _identify_tls(ip: str, port: int, timeout: float) -> str:
    """"TLSv1.3 · CN=router.lan · HTTP 200 · nginx" or "" if no TLS."""
    try:
        with socket.create_connection((ip, port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            with tls_cert.open_tls(sock) as tls:
                parts = [tls.version() or "TLS"]
                try:
                    common_name, alt_names = tls_cert.certificate_names(
                        tls.getpeercert(binary_form=True) or b"")
                    name = common_name or (alt_names[0] if alt_names else "")
                    if name:
                        parts.append(f"CN={name}")
                except (ValueError, IndexError, StopIteration):
                    pass
                try:
                    tls.sendall(_http_request(ip))
                    http = describe_http(_recv_some(tls, timeout))
                except OSError:
                    http = ""
                if http:
                    parts.append(http)
                return " · ".join(parts)
    except (OSError, ssl.SSLError, ValueError):
        return ""


def identify_service(ip: str, port: int, timeout: float) -> str:
    """For an open port that sent no greeting: ask it as a web server,
    plain and over TLS, the way most silent TCP services are spoken to."""
    if port in TLS_FIRST_PORTS:
        return _identify_tls(ip, port, timeout) or _identify_http(ip, port, timeout)[0]
    http, tls = _identify_http(ip, port, timeout)
    if http:
        return http
    return _identify_tls(ip, port, timeout) if tls else ""


def probe(ip: str, port: int, timeout: float = DEFAULT_TIMEOUT,
          banner_timeout: float = BANNER_TIMEOUT) -> PortResult:
    """Connect to one TCP port: open (handshake done), closed (refused) or
    filtered (no answer, or the network said it can't get there). An open
    port's greeting is read, or if it sends none it's asked as a web server
    (identify_service); a banner_timeout of 0 skips both."""
    started = time.monotonic()
    try:
        sock = socket.create_connection((ip, port), timeout=timeout)
    except ConnectionRefusedError:
        return PortResult(port, CLOSED)
    except OSError:
        return PortResult(port, FILTERED)
    with sock:
        rtt_ms = (time.monotonic() - started) * 1000
        try:
            # A TCP self-connect (see ping/port_scan._check_tcp_port):
            # nothing is listening, the socket just met itself.
            if sock.getsockname() == sock.getpeername():
                return PortResult(port, CLOSED)
        except OSError:
            return PortResult(port, CLOSED)
        banner = read_greeting(sock, banner_timeout) if banner_timeout > 0 else ""
    if not banner and banner_timeout > 0:
        banner = identify_service(ip, port, banner_timeout)
    return PortResult(port, OPEN, service_name(port), banner, rtt_ms)


# -- UDP probes -------------------------------------------------------------
#
# Each builder takes (ip, attempt) and returns (payload, decoder): decoder
# turns the reply into a short description, or None to show it as is.

Decoder = Callable[[bytes], str] | None
UdpProbe = Callable[[str, int], tuple[bytes, Decoder]]

_RCODES = {0: "NOERROR", 1: "FORMERR", 2: "SERVFAIL", 3: "NXDOMAIN", 4: "NOTIMP", 5: "REFUSED"}


def _dns(ip: str, attempt: int) -> tuple[bytes, Decoder]:
    # A reverse lookup of the target itself: any DNS server answers it, even
    # if only to refuse; an mDNS/LLMNR responder answers with its own name.
    query_id = random.randrange(1 << 16)
    query = dns_ptr.build_query(dns_ptr.reverse_name(ip), query_id)

    def decode(reply: bytes) -> str:
        try:
            name = dns_ptr.parse_ptr_answer(reply, query_id)
        except (ValueError, IndexError, struct.error):
            name = ""
        rcode = _RCODES.get(reply[3] & 0x0F, str(reply[3] & 0x0F))
        return f"DNS answered ({rcode})" + (f" · {name.rstrip('.')}" if name else "")
    return query, decode


def _ntp(ip: str, attempt: int) -> tuple[bytes, Decoder]:
    def decode(reply: bytes) -> str:
        version, stratum = (reply[0] >> 3) & 7, reply[1]
        state = "unsynchronised" if stratum in (0, 16) else f"stratum {stratum}"
        return f"NTPv{version} · {state}"
    return b"\x1b" + b"\0" * 47, decode  # NTP v3 client request


def _snmp(ip: str, attempt: int) -> tuple[bytes, Decoder]:
    # The Settings community first, then "public".
    communities = snmp.communities()
    community = communities[min(attempt, len(communities) - 1)]
    request_id = random.randrange(1, 1 << 31)

    def decode(reply: bytes) -> str:
        name = snmp.parse_response(reply, request_id)
        return f"SNMP v2c \"{community.decode('utf-8', 'replace')}\"" + (
            f" · sysName {name}" if name else "")
    return snmp.build_get(request_id, community, snmp.VERSION_2C), decode


def _netbios(ip: str, attempt: int) -> tuple[bytes, Decoder]:
    query_id = random.randrange(1 << 16)

    def decode(reply: bytes) -> str:
        name = netbios.parse_node_status(reply, query_id)
        return f"NetBIOS name {name}" if name else "NetBIOS answered"
    return netbios.build_query(query_id), decode


def _header_decoder(*headers: str) -> Callable[[bytes], str]:
    """The first line, plus the first of `headers` the reply has."""
    def decode(reply: bytes) -> str:
        lines = reply.decode("latin-1", "replace").splitlines()
        text = clean_banner(reply)
        for wanted in headers:
            for line in lines[1:]:
                name, _, value = line.partition(":")
                if name.strip().lower() == wanted and value.strip():
                    return f"{text} · {value.strip()[:120]}"
        return text
    return decode


def _ssdp(ip: str, attempt: int) -> tuple[bytes, Decoder]:
    return ssdp.m_search(ip, "ssdp:all"), _header_decoder("server")


def _sip(ip: str, attempt: int) -> tuple[bytes, Decoder]:
    tag = random.randrange(1 << 30)
    payload = (
        f"OPTIONS sip:{ip} SIP/2.0\r\nVia: SIP/2.0/UDP 0.0.0.0:5060;branch=z9hG4bK{tag}\r\n"
        f"Max-Forwards: 70\r\nTo: <sip:{ip}>\r\nFrom: <sip:probe@0.0.0.0>;tag={tag}\r\n"
        f"Call-ID: {tag}@netinfoview\r\nCSeq: 1 OPTIONS\r\nContent-Length: 0\r\n\r\n"
    ).encode()
    return payload, _header_decoder("server", "user-agent")


def _nat_pmp(ip: str, attempt: int) -> tuple[bytes, Decoder]:
    def decode(reply: bytes) -> str:
        if len(reply) >= 12 and reply[1] == 128:
            return "NAT-PMP · external IP " + ".".join(str(b) for b in reply[8:12])
        return "NAT-PMP answered"
    return b"\x00\x00", decode  # external address request


def _rpc_null(program: int, version: int) -> UdpProbe:
    """An ONC RPC NULL call (portmapper, NFS): any RPC server answers it."""
    def build(ip: str, attempt: int) -> tuple[bytes, Decoder]:
        payload = struct.pack("!IIIIII", random.randrange(1 << 32), 0, 2, program, version, 0)
        return payload + b"\0" * 16, lambda reply: "RPC answered"
    return build


def _ike(ip: str, attempt: int) -> tuple[bytes, Decoder]:
    """IKEv1 Main Mode with one common proposal (AES-128, SHA1, PSK, DH 2):
    a VPN gateway answers even if only to say no proposal was chosen."""
    attributes = b"".join(struct.pack("!HH", 0x8000 | kind, value) for kind, value in (
        (1, 7), (14, 128), (2, 2), (3, 1), (4, 2), (11, 1), (12, 28800)))
    transform = struct.pack("!BBHBBH", 0, 0, 8 + len(attributes), 1, 1, 0) + attributes
    proposal = struct.pack("!BBHBBBB", 0, 0, 8 + len(transform), 1, 1, 0, 1) + transform
    sa = struct.pack("!BBHII", 0, 0, 12 + len(proposal), 1, 1) + proposal
    header = random.randbytes(8) + b"\0" * 8 + struct.pack("!BBBBII", 1, 0x10, 2, 0, 0, 28 + len(sa))
    return header + sa, lambda reply: "IKE answered"


def _fixed(payload: bytes, description: str = "") -> UdpProbe:
    return lambda ip, attempt: (payload, (lambda reply: description) if description else None)


_UDP_PROBES: dict[int, UdpProbe] = {
    53: _dns,
    5353: _dns,
    5355: _dns,
    69: _fixed(b"\x00\x01netinfoview-probe\x00octet\x00"),  # TFTP read: answered with an error
    111: _rpc_null(100000, 2),
    123: _ntp,
    137: _netbios,
    161: _snmp,
    177: _fixed(b"\x00\x01\x00\x02\x00\x01\x00", "XDMCP answered"),  # Query
    500: _ike,
    520: _fixed(b"\x01\x02\x00\x00" + b"\0" * 16 + b"\x00\x00\x00\x10", "RIP answered"),  # full table
    623: _fixed(bytes.fromhex("0600ff06000011be80000000"), "IPMI answered"),  # RMCP presence ping
    1194: lambda ip, attempt: (  # OpenVPN hard reset, no tls-auth
        b"\x38" + random.randbytes(8) + b"\x00" + b"\0" * 4, lambda reply: "OpenVPN answered"),
    1434: _fixed(b"\x02"),  # SQL Server browser: list instances
    1900: _ssdp,
    2049: _rpc_null(100003, 3),
    3478: lambda ip, attempt: (  # STUN binding request
        struct.pack("!HHI", 0x0001, 0, 0x2112A442) + random.randbytes(12), lambda reply: "STUN answered"),
    3702: lambda ip, attempt: (  # WS-Discovery probe (printers, cameras, Windows)
        ('<?xml version="1.0" encoding="utf-8"?><soap:Envelope '
         'xmlns:soap="http://www.w3.org/2003/05/soap-envelope" '
         'xmlns:wsa="http://schemas.xmlsoap.org/ws/2004/08/addressing" '
         'xmlns:wsd="http://schemas.xmlsoap.org/ws/2005/04/discovery"><soap:Header>'
         '<wsa:To>urn:schemas-xmlsoap-org:ws:2005:04:discovery</wsa:To>'
         '<wsa:Action>http://schemas.xmlsoap.org/ws/2005/04/discovery/Probe</wsa:Action>'
         f'<wsa:MessageID>urn:uuid:{random.randbytes(16).hex()}</wsa:MessageID></soap:Header>'
         '<soap:Body><wsd:Probe/></soap:Body></soap:Envelope>').encode(),
        lambda reply: "WS-Discovery answered"),
    5060: _sip,
    5351: _nat_pmp,
    5683: lambda ip, attempt: (  # CoAP GET /.well-known/core
        b"\x40\x01" + random.randbytes(2) + b"\xbb.well-known\x04core", lambda reply: "CoAP answered"),
    10001: _fixed(b"\x01\x00\x00\x00", "Ubiquiti discovery answered"),
    11211: _fixed(b"\x00\x01\x00\x00\x00\x01\x00\x00version\r\n"),  # memcached
    47808: _fixed(bytes.fromhex("810b000c0120ffff00ff1008"), "BACnet answered"),  # Who-Is
}


def udp_payload(ip: str, port: int, attempt: int = 0) -> tuple[bytes, Decoder]:
    build = _UDP_PROBES.get(port)
    return build(ip, attempt) if build is not None else (b"", None)


def describe_reply(data: bytes) -> str:
    """A UDP reply's first line if it's plain text (SSDP, SIP, memcached),
    else just its size (DNS, NTP, SNMP, ... are binary)."""
    first = data.lstrip(b"\r\n").split(b"\n", 1)[0].rstrip(b"\r")
    if first and all(0x20 <= b < 0x7F or b == 0x09 for b in first):
        return clean_banner(first)
    return f"replied ({len(data)} bytes)"


def probe_udp(ip: str, port: int, timeout: float = DEFAULT_TIMEOUT,
              attempts: int = UDP_ATTEMPTS) -> PortResult:
    """Send one UDP port its probe: open (it replied), closed (ICMP port
    unreachable) or open|filtered (silence, even after `attempts` tries
    sharing the timeout). DHCP (67) is asked as a relay would
    (ping/dhcp_probe.py), since a server never answers the port a request
    came from; without a reply it gets the ordinary probe below."""
    service = service_name(port, UDP)
    if port == dhcp_probe.SERVER_PORT:
        started = time.monotonic()
        options = dhcp_probe.ask(ip, timeout)
        if options is not None:
            rtt_ms = (time.monotonic() - started) * 1000
            return PortResult(port, OPEN, service, dhcp_probe.describe(options), rtt_ms, UDP)
    try:
        with socket.socket(socket.AF_INET6 if ":" in ip else socket.AF_INET,
                           socket.SOCK_DGRAM) as sock:
            # Connected, so the kernel hands an ICMP port-unreachable back
            # to this socket: ConnectionRefusedError on macOS/Linux,
            # ConnectionResetError (WSAECONNRESET) on Windows.
            sock.connect((ip, port))
            sock.settimeout(max(timeout / attempts, 0.05))
            for attempt in range(attempts):
                payload, decode = udp_payload(ip, port, attempt)
                started = time.monotonic()
                sock.send(payload)
                try:
                    data = sock.recv(4096)
                except (socket.timeout, TimeoutError):
                    continue
                rtt_ms = (time.monotonic() - started) * 1000
                text = ""
                if decode is not None:
                    try:
                        text = decode(data)
                    except (ValueError, IndexError, struct.error):
                        text = ""
                return PortResult(port, OPEN, service, text or describe_reply(data), rtt_ms, UDP)
    except (ConnectionRefusedError, ConnectionResetError):
        return PortResult(port, CLOSED, service, protocol=UDP)
    except OSError:
        return PortResult(port, FILTERED, service, protocol=UDP)
    return PortResult(port, OPEN_FILTERED, service, protocol=UDP)


def recheck_udp(
    ip: str,
    ports: list[int],
    on_result: Callable[[PortResult], None],
    should_stop: Callable[[], bool] = lambda: False,
    timeout: float = DEFAULT_TIMEOUT,
    on_round: Callable[[int, int], None] | None = None,
    max_rounds: int = RECHECK_MAX_ROUNDS,
) -> bool:
    """Ask the UDP ports that stayed silent again, round after round.

    Hosts rate-limit ICMP port unreachable (Linux sends about one a second
    after a burst of six), so in a fast first pass most closed ports look
    silent. Each round asks every port still silent once and settles
    whichever now answer or are refused; rounds go on while they settle
    something, so a host without a limit costs one round and a limited one
    as many as it needs. on_result gets every port that settles, on_round
    (round, ports still silent) each round. False if stopped.
    """
    silent = list(ports)
    for round_number in range(1, max_rounds + 1):
        if not silent or should_stop():
            break
        if on_round is not None:
            on_round(round_number, len(silent))
        settled: list[PortResult] = []

        def collect(result: PortResult) -> None:
            if result.state != OPEN_FILTERED:
                settled.append(result)

        if not scan(ip, [(UDP_ONCE, port) for port in silent], collect, should_stop,
                    timeout=timeout):
            break
        for result in settled:
            on_result(result)
        if not settled:
            break
        done = {result.port for result in settled}
        silent = [port for port in silent if port not in done]
    return not should_stop()


# -- scanning ---------------------------------------------------------------

def scan(
    ip: str,
    jobs: Iterable[tuple[str, int] | int],
    on_result: Callable[[PortResult], None],
    should_stop: Callable[[], bool] = lambda: False,
    timeout: float = DEFAULT_TIMEOUT,
    banner_timeout: float = BANNER_TIMEOUT,
    workers: int = MAX_WORKERS,
) -> bool:
    """Probe every (protocol, port) — a bare int is a TCP port — calling
    on_result for each as it finishes (from this thread, in no particular
    order). Only `workers` probes are in flight at a time, so stopping takes
    at most one timeout and an all-ports scan doesn't queue every job up
    front. False if stopped."""
    pending = iter(jobs)
    in_flight: set[Future] = set()
    with ThreadPoolExecutor(max_workers=max(1, workers)) as pool:
        def fill() -> None:
            while len(in_flight) < workers and not should_stop():
                job = next(pending, None)
                if job is None:
                    return
                protocol, port = (TCP, job) if isinstance(job, int) else job
                if protocol == UDP:
                    in_flight.add(pool.submit(probe_udp, ip, port, timeout))
                elif protocol == UDP_ONCE:
                    in_flight.add(pool.submit(probe_udp, ip, port, timeout, 1))
                else:
                    in_flight.add(pool.submit(probe, ip, port, timeout, banner_timeout))

        fill()
        while in_flight:
            done, _ = wait(in_flight, timeout=0.2, return_when=FIRST_COMPLETED)
            for future in done:
                in_flight.discard(future)
                on_result(future.result())
            if should_stop():
                for future in in_flight:
                    future.cancel()
                # Those already running finish within one timeout; their
                # results are dropped.
                return False
            fill()
    return not should_stop()


def sort_key(result: PortResult) -> tuple[int, str]:
    return (result.port, result.protocol)


def summary_text(summary: ScanSummary) -> str:
    if summary.error:
        return f"✗ {summary.error}"
    verb = "Stopped after" if summary.stopped else "Scanned"
    text = (f"{verb} {summary.scanned:,} of {summary.total:,} ports in {summary.elapsed_s:.1f} s: "
            f"{summary.open} open, {summary.closed:,} closed")
    if summary.filtered:
        text += f", {summary.filtered:,} filtered"
    if summary.open_filtered:
        text += f", {summary.open_filtered:,} UDP open|filtered (no reply)"
    return text
