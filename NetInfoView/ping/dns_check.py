"""DNS Check: a domain's DNS and e-mail records, each checked and graded.

NS (do the nameservers answer for the domain?), A/AAAA, MX, SPF (syntax and
the 10-lookup limit), DMARC (policy), DKIM (needs a selector) and PTR (needs
the sending IP; forward-confirmed). Speaks DNS over UDP itself, with a TCP
retry for truncated answers, like ping/dns_ptr.py, so it needs no
dependencies. Queries go to the system's DNS servers unless one is given.
"""

from __future__ import annotations

import base64
import ipaddress
import json
import random
import re
import socket
import struct
from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict, dataclass, field

from . import ber
from .dns_ptr import _read_name, system_nameservers

DNS_PORT = 53
DEFAULT_TIMEOUT = 2.5
CLASS_IN = 1
TYPES = {"A": 1, "NS": 2, "CNAME": 5, "SOA": 6, "PTR": 12, "MX": 15, "TXT": 16, "AAAA": 28}
TYPE_NAMES = {number: name for name, number in TYPES.items()}
RCODE_NOERROR, RCODE_SERVFAIL, RCODE_NXDOMAIN, RCODE_REFUSED = 0, 2, 3, 5
RCODE_NAMES = {0: "NOERROR", 1: "FORMERR", 2: "SERVFAIL", 3: "NXDOMAIN", 4: "NOTIMP", 5: "REFUSED"}
#: SPF's limit on DNS-querying terms (RFC 7208 §4.6.4).
SPF_LOOKUP_LIMIT = 10

PASS, NOTICE, FAIL, INPUT, ERROR, INFO = "pass", "notice", "fail", "input", "error", "info"
STATUS_LABELS = {PASS: "Passed", NOTICE: "Notice", FAIL: "Failed", INPUT: "Needs input",
                 ERROR: "Error", INFO: "Info"}
#: The checks in the order shown.
CHECKS = ("ns", "soa", "address", "mx", "provider", "spf", "dmarc", "dkim", "ptr", "blacklist",
          "ssl", "whois")
CHECK_TITLES = {"ns": "NS", "soa": "SOA", "address": "A / AAAA", "mx": "MX",
                "provider": "Mail provider", "spf": "SPF", "dmarc": "DMARC", "dkim": "DKIM",
                "ptr": "PTR", "blacklist": "Blocklist", "ssl": "SSL / HTTPS",
                "whois": "Registration"}
#: Selectors tried when none is given: the big mail services' defaults.
COMMON_SELECTORS = (
    "google", "selector1", "selector2", "default", "dkim", "mail", "k1", "k2", "k3", "s1", "s2",
    "smtp", "email", "key1", "key2", "sig1", "fm1", "fm2", "fm3", "protonmail", "protonmail2",
    "protonmail3", "zoho", "zmail", "mxvault", "everlytickey1", "everlytickey2", "mandrill",
    "mailjet", "pm", "scph0521", "dkim1", "dkim2", "mx", "x", "a1", "200608", "20161025",
)
#: IP blacklists (DNSBL) asked about each mail server address: name -> zone.
IP_BLACKLISTS = (
    ("Spamhaus ZEN", "zen.spamhaus.org"),
    ("SpamCop", "bl.spamcop.net"),
    ("Barracuda", "b.barracudacentral.org"),
    ("PSBL", "psbl.surriel.com"),
    ("UCEPROTECT L1", "dnsbl-1.uceprotect.net"),
    ("Mailspike", "bl.mailspike.net"),
)
#: A detail line starting with one of these marks and a space reports one
#: item's own result; the window draws the matching status icon in its place.
DETAIL_MARKS = {"✓": PASS, "✗": FAIL, "!": NOTICE, "–": INPUT}
#: Domain blacklists asked about the domain itself.
DOMAIN_BLACKLISTS = (("Spamhaus DBL", "dbl.spamhaus.org"), ("SURBL", "multi.surbl.org"))

_HEADER = struct.Struct("!HHHHHH")
_RR = struct.Struct("!HHIH")
_LABEL = re.compile(r"^(?!-)[a-z0-9_-]{1,63}(?<!-)$", re.IGNORECASE)


class DnsError(Exception):
    """No server answered (timeout, network error)."""


# -- DNS client ---------------------------------------------------------------


@dataclass
class Soa:
    mname: str
    rname: str
    serial: int
    refresh: int
    retry: int
    expire: int
    minimum: int

    @property
    def email(self) -> str:
        """The admin mailbox: the first unescaped dot of rname is the @."""
        local, _, rest = self.rname.partition(".")
        return f"{local}@{rest}" if rest else self.rname


@dataclass
class Response:
    rcode: int
    authoritative: bool
    #: (type, value) of each answer: an address or name as text, (preference,
    #: name) for MX, the joined strings for TXT.
    answers: list[tuple[int, object]]

    def values(self, rtype: int) -> list:
        return [value for kind, value in self.answers if kind == rtype]


#: Second-level labels that country domains register under (example.co.th,
#: example.com.au, example.ac.uk), so the registered name keeps one more label.
_SECOND_LEVEL = {"ac", "co", "com", "edu", "go", "gob", "gov", "gr", "in", "ltd", "mi",
                 "mil", "ne", "net", "nic", "or", "org", "plc", "sch"}


def registered_domain(name: str) -> str:
    """The domain someone registered, without host labels in front
    (internal.penso.co.th -> penso.co.th, www.google.com -> google.com)."""
    labels = name.split(".")
    keep = 3 if len(labels) >= 3 and len(labels[-1]) == 2 and labels[-2] in _SECOND_LEVEL else 2
    return ".".join(labels[-keep:])


def normalise_domain(text: str) -> str:
    """What was typed, as a bare lower-case registered domain ("" if it
    isn't one): a URL or e-mail address is cut down to its domain, and host
    labels in front (www., mail., internal.) dropped."""
    text = text.strip().lower()
    text = re.sub(r"^[a-z][a-z0-9+.-]*://", "", text)
    text = text.split("/")[0].split("?")[0]
    text = text.rsplit("@", 1)[-1].split(":")[0].strip(".")
    try:
        text = text.encode("idna").decode("ascii")
    except UnicodeError:
        return ""
    labels = text.split(".")
    if len(labels) < 2 or len(text) > 253 or not all(_LABEL.match(label) for label in labels):
        return ""
    return registered_domain(text)


def build_query(name: str, qtype: int, query_id: int, recursion: bool = True) -> bytes:
    flags = 0x0100 if recursion else 0
    header = _HEADER.pack(query_id, flags, 1, 0, 0, 0)
    labels = b"".join(
        bytes([len(part)]) + part.encode("ascii") for part in name.rstrip(".").split(".") if part
    )
    # No EDNS0: some home routers' DNS forwarders answer an OPT query with
    # nothing. A long answer comes back truncated and is asked again over TCP.
    return header + labels + b"\0" + struct.pack("!HH", qtype, CLASS_IN)


def _rdata(message: bytes, rtype: int, start: int, length: int) -> object:
    data = message[start:start + length]
    if rtype == TYPES["A"] and length == 4:
        return socket.inet_ntop(socket.AF_INET, data)
    if rtype == TYPES["AAAA"] and length == 16:
        return socket.inet_ntop(socket.AF_INET6, data)
    if rtype in (TYPES["NS"], TYPES["CNAME"], TYPES["PTR"]):
        return _read_name(message, start)[0].lower()
    if rtype == TYPES["SOA"]:
        mname, offset = _read_name(message, start)
        rname, offset = _read_name(message, offset)
        return Soa(mname.lower(), rname.lower(), *struct.unpack_from("!IIIII", message, offset))
    if rtype == TYPES["MX"]:
        return struct.unpack_from("!H", message, start)[0], _read_name(message, start + 2)[0].lower()
    if rtype == TYPES["TXT"]:
        parts, offset = [], 0
        while offset < length:
            size = data[offset]
            parts.append(data[offset + 1:offset + 1 + size])
            offset += 1 + size
        return b"".join(parts).decode("utf-8", "replace")
    return data.hex()


def parse_response(message: bytes, query_id: int) -> tuple[Response, bool] | None:
    """The response and whether it was truncated, or None if the message
    isn't the reply to `query_id`."""
    ident, flags, questions, answers, _, _ = _HEADER.unpack_from(message)
    if ident != query_id or not flags & 0x8000:
        return None
    offset = _HEADER.size
    for _ in range(questions):
        _, offset = _read_name(message, offset)
        offset += 4
    records: list[tuple[int, object]] = []
    for _ in range(answers):
        _, offset = _read_name(message, offset)
        rtype, rclass, _, length = _RR.unpack_from(message, offset)
        offset += _RR.size
        if rclass == CLASS_IN and rtype in TYPE_NAMES:
            records.append((rtype, _rdata(message, rtype, offset, length)))
        offset += length
    response = Response(rcode=flags & 0x000F, authoritative=bool(flags & 0x0400), answers=records)
    return response, bool(flags & 0x0200)


def _family(server: str) -> int:
    return socket.AF_INET6 if ipaddress.ip_address(server).version == 6 else socket.AF_INET


def _query_tcp(packet: bytes, query_id: int, server: str, timeout: float, port: int) -> Response:
    with socket.socket(_family(server), socket.SOCK_STREAM) as sock:
        sock.settimeout(timeout)
        sock.connect((server, port))
        sock.sendall(struct.pack("!H", len(packet)) + packet)
        data = b""
        while len(data) < 2 or len(data) < 2 + struct.unpack("!H", data[:2])[0]:
            chunk = sock.recv(65535)
            if not chunk:
                raise DnsError("connection closed")
            data += chunk
        parsed = parse_response(data[2:], query_id)
        if parsed is None:
            raise DnsError("unexpected reply")
        return parsed[0]


def query(name: str, rtype: str, server: str, timeout: float = DEFAULT_TIMEOUT,
          recursion: bool = True, port: int = DNS_PORT) -> Response:
    """Ask `server` for `name`'s `rtype` records. Raises DnsError if it
    doesn't answer."""
    qtype = TYPES[rtype]
    query_id = random.randrange(1 << 16)
    packet = build_query(name, qtype, query_id, recursion)
    try:
        with socket.socket(_family(server), socket.SOCK_DGRAM) as sock:
            sock.settimeout(timeout)
            sock.connect((server, port))
            for attempt in range(2):
                sock.send(packet)
                try:
                    while True:
                        try:
                            parsed = parse_response(sock.recv(65535), query_id)
                        except (ValueError, IndexError, struct.error):
                            continue
                        if parsed is not None:
                            break
                except socket.timeout:
                    if attempt:
                        raise
                    continue
                response, truncated = parsed
                # Some firewalls rewrite UDP DNS and answer A records for
                # every type asked; TCP gets past them.
                mismatched = any(kind not in (qtype, TYPES["CNAME"])
                                 for kind, _ in response.answers)
                if truncated or mismatched:
                    return _query_tcp(packet, query_id, server, timeout, port)
                return response
    except (OSError, ValueError, struct.error) as error:
        raise DnsError(str(error) or "no answer") from error
    raise DnsError("no answer")


class Resolver:
    """Recursive lookups through the given servers (default: the system's),
    trying each in turn, with answers cached for the length of one check."""

    def __init__(self, servers: list[str] | None = None, timeout: float = DEFAULT_TIMEOUT,
                 port: int = DNS_PORT) -> None:
        self.servers = [s for s in (servers or []) if s] or system_nameservers()
        self.timeout = timeout
        self.port = port
        self._cache: dict[tuple[str, str], Response] = {}

    def resolve(self, name: str, rtype: str) -> Response:
        key = (name.lower().rstrip("."), rtype)
        if key in self._cache:
            return self._cache[key]
        if not self.servers:
            raise DnsError("no DNS server is configured")
        last: Exception | None = None
        for server in self.servers:
            try:
                response = query(key[0], rtype, server, self.timeout, port=self.port)
            except DnsError as error:
                last = error
                continue
            if response.rcode in (RCODE_SERVFAIL, RCODE_REFUSED) and server != self.servers[-1]:
                continue
            self._cache[key] = response
            return response
        raise DnsError(f"DNS servers didn't answer ({last})" if last else "DNS servers failed")

    def values(self, name: str, rtype: str) -> list:
        return self.resolve(name, rtype).values(TYPES[rtype])

    def addresses(self, name: str) -> list[str]:
        found: list[str] = []
        for rtype in ("A", "AAAA"):
            try:
                found += self.values(name, rtype)
            except DnsError:
                pass
        return found

    def txt(self, name: str) -> list[str]:
        return self.values(name, "TXT")


# -- results ------------------------------------------------------------------


@dataclass
class CheckResult:
    key: str
    status: str
    summary: str
    #: The records found, as they'd be copied.
    records: list[str] = field(default_factory=list)
    #: Plain-language notes on what was found.
    details: list[str] = field(default_factory=list)

    @property
    def title(self) -> str:
        return CHECK_TITLES[self.key]


@dataclass
class Report:
    domain: str
    results: list[CheckResult] = field(default_factory=list)
    server: str = ""

    def counts(self) -> dict[str, int]:
        counts = dict.fromkeys(STATUS_LABELS, 0)
        for result in self.results:
            counts[result.status] += 1
        return counts

    def result(self, key: str) -> CheckResult | None:
        return next((r for r in self.results if r.key == key), None)


def counts_text(report: Report) -> str:
    counts = report.counts()
    parts = [f"{counts[PASS]} passed"]
    if counts[NOTICE]:
        parts.append(f"{counts[NOTICE]} notice{'s' if counts[NOTICE] != 1 else ''}")
    if counts[FAIL] or counts[ERROR]:
        parts.append(f"{counts[FAIL] + counts[ERROR]} failed")
    if counts[INPUT]:
        parts.append(f"{counts[INPUT]} need input")
    return " | ".join(parts)


def summary_text(report: Report) -> str:
    """The report as plain text, for Copy summary and Export."""
    lines = [f"DNS check: {report.domain}", counts_text(report), ""]
    width = max(len(r.title) for r in report.results) if report.results else 0
    for result in report.results:
        lines.append(f"{result.title:<{width}}  {STATUS_LABELS[result.status]:<11}  {result.summary}")
        lines += [f"{'':<{width}}    {record}" for record in result.records]
        lines += [f"{'':<{width}}    - {note}" for note in result.details]
    return "\n".join(lines)


def report_json(report: Report) -> str:
    data = {"domain": report.domain, "server": report.server or "system",
            "results": [dict(asdict(r), title=r.title) for r in report.results]}
    return json.dumps(data, indent=2)


def _failed_lookup(key: str, error: Exception) -> CheckResult:
    return CheckResult(key, ERROR, "Lookup failed", details=[str(error)])


# -- the checks ----------------------------------------------------------------


def _ns_answers(nameserver: str, domain: str, resolver: Resolver) -> tuple[str, bool, str]:
    """(nameserver, answers authoritatively?, note)."""
    addresses = resolver.addresses(nameserver)
    if not addresses:
        return nameserver, False, f"{nameserver} has no address"
    for address in addresses:
        try:
            response = query(domain, "SOA", address, resolver.timeout, recursion=False,
                             port=resolver.port)
        except DnsError:
            continue
        if response.rcode == RCODE_NOERROR and response.authoritative:
            return nameserver, True, ""
        return nameserver, False, (f"{nameserver} ({address}) answered "
                                   f"{RCODE_NAMES.get(response.rcode, response.rcode)}"
                                   f"{'' if response.authoritative else ', not authoritatively'}")
    return nameserver, False, f"{nameserver} doesn't answer"


def check_ns(domain: str, resolver: Resolver) -> CheckResult:
    try:
        response = resolver.resolve(domain, "NS")
    except DnsError as error:
        return _failed_lookup("ns", error)
    if response.rcode == RCODE_NXDOMAIN:
        return CheckResult("ns", FAIL, "Domain doesn't exist (NXDOMAIN)")
    nameservers = sorted(set(response.values(TYPES["NS"])))
    if not nameservers:
        return CheckResult("ns", FAIL, "No NS records",
                           details=["The domain has no nameservers of its own; it may be a "
                                    "subdomain served by its parent zone."])
    with ThreadPoolExecutor(max_workers=min(8, len(nameservers))) as pool:
        probes = list(pool.map(lambda ns: _ns_answers(ns, domain, resolver), nameservers))
    bad = [note for _, ok, note in probes if not ok]
    records = [f"NS {ns}" for ns in nameservers]
    if len(bad) == len(probes):
        return CheckResult("ns", FAIL, "Nameservers don't respond", records, bad)
    if bad:
        return CheckResult("ns", NOTICE, f"{len(bad)} of {len(probes)} nameservers don't respond",
                           records, bad)
    if len(nameservers) < 2:
        return CheckResult("ns", NOTICE, "Only one nameserver", records,
                           ["Two or more nameservers (RFC 2182) keep the domain up if one fails."])
    return CheckResult("ns", PASS, "Nameservers respond", records,
                       [f"All {len(nameservers)} answer authoritatively for {domain}."])


def check_address(domain: str, resolver: Resolver) -> CheckResult:
    try:
        v4 = resolver.values(domain, "A")
        v6 = resolver.values(domain, "AAAA")
    except DnsError as error:
        return _failed_lookup("address", error)
    records = [f"A {a}" for a in v4] + [f"AAAA {a}" for a in v6]
    if not records:
        return CheckResult("address", NOTICE, "No address records",
                           details=["Fine if the domain is only used for mail; a website "
                                    "on it won't load."])
    details = []
    if not v6:
        details.append("No IPv6 (AAAA) address.")
    return CheckResult("address", PASS, "Address records found", records, details)


def check_mx(domain: str, resolver: Resolver) -> CheckResult:
    try:
        exchanges = sorted(resolver.values(domain, "MX"))
    except DnsError as error:
        return _failed_lookup("mx", error)
    if not exchanges:
        if resolver.addresses(domain):
            return CheckResult("mx", NOTICE, "No MX: mail goes to the A record",
                               details=["Without MX, senders fall back to the domain's own "
                                        "address (implicit MX)."])
        return CheckResult("mx", FAIL, "No mail servers")
    records = [f"MX {pref} {host or '.'}" for pref, host in exchanges]
    if len(exchanges) == 1 and exchanges[0][1] in ("", "."):
        return CheckResult("mx", NOTICE, "Accepts no mail (null MX)", records,
                           ["A null MX (RFC 7505) says the domain receives no e-mail."])
    problems = []
    for _, host in exchanges:
        try:
            ipaddress.ip_address(host)
            problems.append(f"{host} is an IP address; MX must name a host.")
            continue
        except ValueError:
            pass
        if not resolver.addresses(host):
            problems.append(f"{host} doesn't resolve to an address.")
    if len(problems) == len(exchanges):
        return CheckResult("mx", FAIL, "Mail servers don't resolve", records, problems)
    if problems:
        return CheckResult("mx", NOTICE, "Some mail servers don't resolve", records, problems)
    return CheckResult("mx", PASS, "Mail servers found", records)


def _spf_records(texts: list[str]) -> list[str]:
    return [t for t in texts if t.lower() == "v=spf1" or t.lower().startswith("v=spf1 ")]


_SPF_MECHANISM = re.compile(r"^([+\-~?]?)(all|include|a|mx|ptr|ip4|ip6|exists)(?:([:/])(.*))?$",
                            re.IGNORECASE)
_SPF_MODIFIER = re.compile(r"^([a-z][a-z0-9_.-]*)=(.*)$", re.IGNORECASE)


@dataclass
class SpfAnalysis:
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    lookups: int = 0
    all_qualifier: str = ""  # "+", "-", "~", "?" or "" (no all)
    redirect: str = ""


def parse_spf(record: str) -> SpfAnalysis:
    """The syntax of one SPF record, without following include/redirect."""
    result = SpfAnalysis()
    terms = record.split()[1:]
    for term in terms:
        modifier = _SPF_MODIFIER.match(term)
        mechanism = _SPF_MECHANISM.match(term)
        if mechanism:
            qualifier, name, sep, value = mechanism.groups()
            name = name.lower()
            value = value or ""
            if name == "all":
                if sep:
                    result.errors.append(f"\"{term}\": all takes no value")
                result.all_qualifier = qualifier or "+"
                if result.all_qualifier == "+":
                    result.warnings.append("\"+all\" lets any server send as this domain.")
            elif name in ("include", "exists"):
                if sep != ":" or not value:
                    result.errors.append(f"\"{term}\": {name} needs a domain")
                result.lookups += 1
            elif name in ("ip4", "ip6"):
                try:
                    network = ipaddress.ip_network(value, strict=False)
                    if sep != ":" or network.version != int(name[2]):
                        raise ValueError
                except ValueError:
                    result.errors.append(f"\"{term}\": not a valid {name} address")
            else:  # a, mx, ptr
                result.lookups += 1
                if name == "ptr":
                    result.warnings.append("\"ptr\" is deprecated (RFC 7208) and slow.")
        elif modifier:
            name, value = modifier.group(1).lower(), modifier.group(2)
            if name == "redirect":
                if result.redirect:
                    result.errors.append("more than one redirect=")
                result.redirect = value
                result.lookups += 1
            elif name == "exp":
                pass
        else:
            result.errors.append(f"\"{term}\" is not a valid SPF term")
    return result


def _spf_lookups(domain: str, resolver: Resolver, seen: set[str], depth: int = 0) -> tuple[int, list[str]]:
    """The DNS lookups SPF evaluation of `domain` needs in total, following
    include: and redirect=, and problems found along the way."""
    if depth > 10 or domain in seen:
        return 0, [f"SPF include loop at {domain}"] if domain in seen else []
    seen.add(domain)
    try:
        records = _spf_records(resolver.txt(domain))
    except DnsError:
        return 0, [f"couldn't look up SPF for {domain}"]
    if len(records) != 1:
        return 0, [f"{domain} has {'no' if not records else len(records)} SPF record"
                   f"{'s' if len(records) != 1 else ''}"]
    analysis = parse_spf(records[0])
    total, problems = analysis.lookups, [f"{domain}: {e}" for e in analysis.errors]
    targets = []
    for term in records[0].split()[1:]:
        match = _SPF_MECHANISM.match(term)
        if match and match.group(2).lower() == "include" and match.group(4):
            targets.append(match.group(4))
        # Each mx term also costs a lookup per MX host (max 10); not counted.
    if analysis.redirect and analysis.all_qualifier == "":
        targets.append(analysis.redirect)
    for target in targets:
        if "%" in target:
            continue  # macros can't be followed without a sender
        count, more = _spf_lookups(target.lower().rstrip("."), resolver, seen, depth + 1)
        total += count
        problems += more
    return total, problems


def check_spf(domain: str, resolver: Resolver) -> CheckResult:
    try:
        records = _spf_records(resolver.txt(domain))
    except DnsError as error:
        return _failed_lookup("spf", error)
    if not records:
        return CheckResult("spf", FAIL, "No SPF record",
                           details=["Add a TXT record starting \"v=spf1\" listing the servers "
                                    "that send this domain's mail."])
    if len(records) > 1:
        return CheckResult("spf", FAIL, "Multiple SPF records", records,
                           ["Only one SPF record is allowed; receivers treat two as an error "
                            "(permerror)."])
    record = records[0]
    analysis = parse_spf(record)
    if analysis.errors:
        return CheckResult("spf", FAIL, "Syntax error", records, analysis.errors)
    lookups, problems = _spf_lookups(domain, resolver, set())
    details = list(analysis.warnings)
    details.append(f"{lookups} of {SPF_LOOKUP_LIMIT} DNS lookups used.")
    if lookups > SPF_LOOKUP_LIMIT:
        return CheckResult("spf", FAIL, f"Too many DNS lookups ({lookups})", records,
                           details + problems)
    if analysis.all_qualifier == "+":
        return CheckResult("spf", FAIL, "+all allows any sender", records, details + problems)
    if problems:
        return CheckResult("spf", NOTICE, "Included record has problems", records,
                           details + problems)
    if analysis.all_qualifier in ("", "?") and not analysis.redirect:
        return CheckResult("spf", NOTICE, "No ~all or -all: neutral policy", records,
                           details + ["End the record with ~all or -all."])
    if analysis.warnings:
        return CheckResult("spf", NOTICE, "Syntax passed with warnings", records, details)
    return CheckResult("spf", PASS, "Syntax check passed", records, details)


def parse_tags(record: str) -> dict[str, str]:
    """A DMARC/DKIM "tag=value; tag=value" record as a dict."""
    tags: dict[str, str] = {}
    for part in record.split(";"):
        if "=" in part:
            name, value = part.split("=", 1)
            tags.setdefault(name.strip().lower(), value.strip())
    return tags


def check_dmarc(domain: str, resolver: Resolver) -> CheckResult:
    name = f"_dmarc.{domain}"
    try:
        records = [t for t in resolver.txt(name) if t.lower().replace(" ", "").startswith("v=dmarc1")]
    except DnsError as error:
        return _failed_lookup("dmarc", error)
    if not records:
        return CheckResult("dmarc", FAIL, "No DMARC record",
                           details=[f"Add a TXT record at {name}, e.g. "
                                    "\"v=DMARC1; p=none; rua=mailto:…\" to start monitoring."])
    if len(records) > 1:
        return CheckResult("dmarc", FAIL, "Multiple DMARC records", records,
                           ["Receivers ignore DMARC when there's more than one record."])
    tags = parse_tags(records[0])
    policy = tags.get("p", "").lower()
    if policy not in ("none", "quarantine", "reject"):
        return CheckResult("dmarc", FAIL, "Missing or invalid p= policy", records,
                           ["p= must be none, quarantine or reject."])
    details = []
    if "rua" not in tags:
        details.append("No rua= address: you won't get aggregate reports.")
    pct = tags.get("pct", "100")
    if pct != "100":
        details.append(f"pct={pct}: the policy applies to only {pct}% of failing mail.")
    if tags.get("sp"):
        details.append(f"Subdomain policy sp={tags['sp']}.")
    if policy == "none":
        return CheckResult("dmarc", NOTICE, "Monitoring only · p=none", records,
                           ["Monitoring mode is enabled: failing mail is still delivered."]
                           + details)
    return CheckResult("dmarc", PASS, f"Enforced · p={policy}", records, details)


def rsa_key_bits(public_key_b64: str) -> int:
    """The modulus size of a base64 RSA SubjectPublicKeyInfo (or bare
    RSAPublicKey), or 0 if it can't be read."""
    try:
        der = base64.b64decode(re.sub(r"\s+", "", public_key_b64), validate=False)
        tag, start, end = ber.read(der)
        kids = list(ber.children(der, start, end))
        if kids and kids[0][0] == ber.SEQUENCE and len(kids) > 1 and kids[1][0] == 0x03:
            _, bit_start, bit_end = kids[1]
            inner = der[bit_start + 1:bit_end]  # skip the unused-bits byte
            tag, start, end = ber.read(inner)
            der, kids = inner, list(ber.children(inner, start, end))
        _, mod_start, mod_end = kids[0]
        return int.from_bytes(der[mod_start:mod_end], "big").bit_length()
    except (ValueError, IndexError, TypeError):
        return 0


def _dkim_key(domain: str, selector: str, resolver: Resolver) -> str | None:
    """None if `selector` has no DKIM record, else its p= value ("" if revoked)."""
    try:
        texts = resolver.txt(f"{selector}._domainkey.{domain}")
    except DnsError:
        return None
    keys = [t for t in texts if "p=" in t.replace(" ", "")]
    return parse_tags(keys[0]).get("p", "") if keys else None


def find_selectors(domain: str, resolver: Resolver) -> tuple[list[str], list[str]]:
    """(selectors with a key, selectors with a revoked key) among
    COMMON_SELECTORS on `domain`."""
    # A wildcard TXT under _domainkey would answer every name; a random one
    # showing a key means the answers say nothing.
    if _dkim_key(domain, f"nx{random.randrange(1 << 30):x}", resolver) is not None:
        return [], []
    with ThreadPoolExecutor(max_workers=12) as pool:
        keys = list(pool.map(lambda s: _dkim_key(domain, s, resolver), COMMON_SELECTORS))
    return ([s for s, key in zip(COMMON_SELECTORS, keys) if key],
            [s for s, key in zip(COMMON_SELECTORS, keys) if key == ""])


def check_dkim(domain: str, resolver: Resolver, selectors: list[str]) -> CheckResult:
    if selectors:
        return _check_selectors(domain, resolver, selectors)
    selectors, revoked = find_selectors(domain, resolver)
    where = (f"DKIM keys live at <selector>._domainkey.{domain}; find the selector in a "
             "sent message's DKIM-Signature header (s=).")
    if not selectors:
        if revoked:
            return CheckResult("dkim", INPUT, "Only revoked keys found",
                               details=[f"Old selector{'s' if len(revoked) > 1 else ''} "
                                        f"{', '.join(revoked)} {'have' if len(revoked) > 1 else 'has'}"
                                        f" an empty key (revoked). {where}"])
        return CheckResult("dkim", INPUT, "Selector required",
                           details=[f"None of {len(COMMON_SELECTORS)} common selectors has a "
                                    f"key. {where}"])
    result = _check_selectors(domain, resolver, selectors)
    result.details.append("Selector found by trying common names; "
                          "Change selector to check another.")
    return result


def _check_selectors(domain: str, resolver: Resolver, selectors: list[str]) -> CheckResult:
    records, details, statuses = [], [], []
    for selector in selectors:
        name = f"{selector}._domainkey.{domain}"
        try:
            texts = resolver.txt(name)
        except DnsError as error:
            statuses.append(ERROR)
            details.append(f"{selector}: {error}")
            continue
        keys = [t for t in texts if "p=" in t.replace(" ", "")]
        if not keys:
            statuses.append(FAIL)
            details.append(f"{selector}: no DKIM key at {name}")
            continue
        records.append(f"{selector}: {keys[0]}")
        tags = parse_tags(keys[0])
        key = tags.get("p", "")
        if not key:
            statuses.append(FAIL)
            details.append(f"{selector}: the key is revoked (empty p=)")
            continue
        if tags.get("k", "rsa").lower() == "rsa":
            bits = rsa_key_bits(key)
            if bits and bits < 1024:
                statuses.append(FAIL)
                details.append(f"{selector}: {bits}-bit RSA key is too weak")
                continue
            if bits and bits < 2048:
                statuses.append(NOTICE)
                details.append(f"{selector}: {bits}-bit RSA key; 2048-bit is recommended")
                continue
            details.append(f"{selector}: {bits}-bit RSA key" if bits else f"{selector}: key found")
        else:
            details.append(f"{selector}: {tags['k']} key")
        if tags.get("t", "").lower().startswith("y"):
            statuses.append(NOTICE)
            details.append(f"{selector}: testing mode (t=y)")
            continue
        statuses.append(PASS)
    label = ", ".join(selectors)
    for status, summary in ((ERROR, "Lookup failed"), (FAIL, f"Problem with {label}"),
                            (NOTICE, f"Key found ({label}) with notes")):
        if status in statuses:
            return CheckResult("dkim", status, summary, records, details)
    return CheckResult("dkim", PASS, f"Valid for {label}", records, details)


def check_ptr(resolver: Resolver, ip: str) -> CheckResult:
    if not ip:
        return CheckResult("ptr", INPUT, "Sending IP required",
                           details=["Reverse DNS is checked for the address your mail "
                                    "server sends from."])
    try:
        address = ipaddress.ip_address(ip)
    except ValueError:
        return CheckResult("ptr", FAIL, f"\"{ip}\" is not an IP address")
    try:
        names = resolver.values(address.reverse_pointer, "PTR")
    except DnsError as error:
        return _failed_lookup("ptr", error)
    if not names:
        return CheckResult("ptr", FAIL, f"No PTR record for {ip}",
                           details=["Many receivers reject or junk mail from an address "
                                    "without reverse DNS; ask whoever owns the IP to set it."])
    records = [f"PTR {ip} → {name}" for name in names]
    if len(names) > 1:
        return CheckResult("ptr", NOTICE, "More than one PTR record", records,
                           ["Use a single PTR name for a mail server."])
    forward = resolver.addresses(names[0])
    if str(address) not in {str(ipaddress.ip_address(a)) for a in forward}:
        return CheckResult("ptr", NOTICE, f"{names[0]} doesn't resolve back", records,
                           [f"{names[0]} resolves to {', '.join(forward) or 'nothing'}, "
                            f"not {ip} (not forward-confirmed)."])
    return CheckResult("ptr", PASS, f"{names[0]} (forward-confirmed)", records)


def _duration(seconds: int) -> str:
    for unit, size in (("week", 604800), ("day", 86400), ("hour", 3600), ("minute", 60)):
        if seconds >= size and seconds % size == 0:
            count = seconds // size
            return f"{count} {unit}{'s' if count != 1 else ''}"
    return f"{seconds} s"


def _ns_serial(nameserver: str, domain: str, resolver: Resolver) -> tuple[str, int | None]:
    for address in resolver.addresses(nameserver):
        try:
            response = query(domain, "SOA", address, resolver.timeout, recursion=False,
                             port=resolver.port)
        except DnsError:
            continue
        soas = response.values(TYPES["SOA"])
        if soas:
            return nameserver, soas[0].serial
    return nameserver, None


def check_soa(domain: str, resolver: Resolver) -> CheckResult:
    try:
        soas = resolver.values(domain, "SOA")
    except DnsError as error:
        return _failed_lookup("soa", error)
    if not soas:
        return CheckResult("soa", INFO, "No SOA: part of its parent's zone",
                           details=[f"{domain} isn't a zone of its own."])
    soa = soas[0]
    records = [f"SOA {soa.mname} {soa.rname} {soa.serial} {soa.refresh} {soa.retry} "
               f"{soa.expire} {soa.minimum}"]
    details = [f"Primary nameserver: {soa.mname}", f"Admin: {soa.email}",
               f"Serial {soa.serial} · refresh {_duration(soa.refresh)} · retry "
               f"{_duration(soa.retry)} · expire {_duration(soa.expire)} · negative TTL "
               f"{_duration(soa.minimum)}"]
    # RFC 1912 §2.2's suggested ranges.
    notes = []
    if not 1200 <= soa.refresh <= 43200:
        notes.append("Refresh is usually 20 minutes to 12 hours.")
    if soa.retry >= soa.refresh:
        notes.append("Retry should be shorter than refresh.")
    if not 1209600 <= soa.expire <= 2419200:
        notes.append("Expire is usually 2 to 4 weeks.")
    if soa.minimum > 86400:
        notes.append("A negative TTL over a day keeps a new name unreachable for long.")
    try:
        nameservers = sorted(set(resolver.values(domain, "NS")))
    except DnsError:
        nameservers = []
    serials: dict[str, int | None] = {}
    if nameservers:
        with ThreadPoolExecutor(max_workers=min(8, len(nameservers))) as pool:
            serials = dict(pool.map(lambda ns: _ns_serial(ns, domain, resolver), nameservers))
    seen = {serial for serial in serials.values() if serial is not None}
    if len(seen) > 1:
        return CheckResult("soa", NOTICE, "Nameservers have different serials", records,
                           [f"{ns}: {serial if serial is not None else 'no answer'}"
                            for ns, serial in serials.items()]
                           + ["A secondary hasn't picked up the latest zone yet."] + details)
    if seen:
        details.insert(0, f"All {len(serials)} nameservers serve serial {seen.pop()}.")
    details += notes  # big providers use their own timers: noted, not graded
    return CheckResult("soa", PASS, "Serials match" if serials else "SOA found", records, details)


#: Mail services recognised by their MX host names.
MX_PROVIDERS = (
    ("google.com", "Google Workspace"), ("googlemail.com", "Google Workspace"),
    ("mail.protection.outlook.com", "Microsoft 365"), ("olc.protection.outlook.com", "Microsoft Outlook.com"),
    ("zoho.", "Zoho Mail"), ("pphosted.com", "Proofpoint"), ("ppe-hosted.com", "Proofpoint"),
    ("mimecast", "Mimecast"), ("barracudanetworks.com", "Barracuda"),
    ("messagelabs.com", "Broadcom Email Security"), ("iphmx.com", "Cisco Secure Email"),
    ("fireeyecloud.com", "Trellix Email Security"), ("trendmicro", "Trend Micro"),
    ("secureserver.net", "GoDaddy"), ("protonmail.ch", "Proton Mail"),
    ("icloud.com", "iCloud Mail"), ("yahoodns.net", "Yahoo"), ("mailgun.org", "Mailgun"),
    ("amazonaws.com", "Amazon SES / WorkMail"), ("emailsrvr.com", "Rackspace"),
    ("messagingengine.com", "Fastmail"), ("yandex", "Yandex Mail"), ("ovh.net", "OVHcloud"),
    ("kundenserver.de", "IONOS"), ("ionos.", "IONOS"), ("privateemail.com", "Namecheap"),
    ("titan.email", "Titan"), ("hostinger.", "Hostinger"), ("mxroute.com", "MXroute"),
    ("larksuite.com", "Lark"), ("qq.com", "Tencent Exmail"), ("mailhostbox.com", "Mailhostbox"),
)
#: Services that send for the domain, by their SPF include.
SPF_SENDERS = (
    ("_spf.google.com", "Google"), ("spf.protection.outlook.com", "Microsoft 365"),
    ("sendgrid.net", "SendGrid"), ("mailgun.org", "Mailgun"), ("amazonses.com", "Amazon SES"),
    ("mcsv.net", "Mailchimp"), ("mandrillapp.com", "Mailchimp Transactional"),
    ("zoho.", "Zoho"), ("salesforce.com", "Salesforce"), ("sparkpostmail.com", "SparkPost"),
    ("brevo.com", "Brevo"), ("sendinblue.com", "Brevo"), ("hubspotemail.net", "HubSpot"),
    ("zendesk.com", "Zendesk"), ("freshdesk.com", "Freshdesk"), ("mtasv.net", "Postmark"),
    ("pphosted.com", "Proofpoint"), ("mimecast", "Mimecast"), ("secureserver.net", "GoDaddy"),
    ("protonmail.ch", "Proton Mail"), ("icloud.com", "iCloud Mail"),
    ("messagingengine.com", "Fastmail"),
)
#: Services whose domain-verification TXT record is at the apex.
TXT_SERVICES = (
    ("google-site-verification=", "Google"), ("ms=", "Microsoft 365"),
    ("facebook-domain-verification=", "Meta"), ("apple-domain-verification=", "Apple"),
    ("atlassian-domain-verification=", "Atlassian"), ("docusign=", "DocuSign"),
    ("zoom_verify_", "Zoom"), ("adobe-idp-site-verification=", "Adobe"),
    ("stripe-verification=", "Stripe"), ("globalsign-domain-verification=", "GlobalSign"),
    ("openai-domain-verification=", "OpenAI"), ("slack-domain-verification=", "Slack"),
    ("dropbox-domain-verification=", "Dropbox"), ("zoho-verification=", "Zoho"),
    ("teamviewer-sso-verification=", "TeamViewer"), ("miro-verification=", "Miro"),
    ("canva-site-verification=", "Canva"), ("cisco-ci-domain-verification=", "Cisco Webex"),
    ("hubspot-developer-verification=", "HubSpot"), ("notion-domain-verification=", "Notion"),
    ("postman-domain-verification=", "Postman"), ("amazonses:", "Amazon SES"),
    ("yandex-verification", "Yandex"), ("have-i-been-pwned-verification=", "Have I Been Pwned"),
)


def _match(text: str, table) -> list[str]:
    found: list[str] = []
    for needle, name in table:
        if needle in text and name not in found:
            found.append(name)
    return found


def check_provider(domain: str, resolver: Resolver) -> CheckResult:
    """Who handles the domain's mail, from MX, SPF and verification TXTs."""
    try:
        exchanges = [host for _, host in sorted(resolver.values(domain, "MX")) if host]
        texts = resolver.txt(domain)
    except DnsError as error:
        return _failed_lookup("provider", error)
    providers: list[str] = []
    for host in exchanges:
        providers += [p for p in _match(host, MX_PROVIDERS) if p not in providers]
    senders = _match(" ".join(t.lower() for t in _spf_records(texts)), SPF_SENDERS)
    services = _match(" ".join(t.lower() for t in texts), TXT_SERVICES)
    details = []
    if len(providers) > 1:
        filters = {"Proofpoint", "Mimecast", "Barracuda", "Cisco Secure Email",
                   "Broadcom Email Security", "Trellix Email Security", "Trend Micro"}
        details.append("Mail passes a filtering service before reaching the mailbox."
                       if filters & set(providers) else "MX hosts belong to more than one service.")
    if senders:
        details.append(f"Sends through (SPF): {', '.join(senders)}")
    if services:
        details.append(f"Verified with: {', '.join(services)}")
    if providers:
        summary = " + ".join(providers)
    elif exchanges:
        summary = f"Self-hosted or unrecognised ({exchanges[0]})"
    else:
        summary = "No mail servers"
    return CheckResult("provider", INFO, summary, details=details)


def _dnsbl(name: str, resolver: Resolver) -> tuple[list[str], bool]:
    """(answers, refused?) for a DNSBL lookup: no answers means not listed;
    127.255.255.x (Spamhaus) and 127.0.0.1 from SURBL mean the list won't
    answer this resolver (public DNS is blocked)."""
    try:
        answers = resolver.values(name, "A")
    except DnsError:
        return [], True
    refused = [a for a in answers if a.startswith("127.255.255.") or a == "127.0.1.255"]
    if name.endswith("multi.surbl.org"):
        refused += [a for a in answers if a == "127.0.0.1"]
    if refused:
        return [], True
    return [a for a in answers if a.startswith("127.")], False


def check_blacklist(domain: str, resolver: Resolver, ip: str = "") -> CheckResult:
    """The mail servers' IPv4 addresses (and the sending IP) on IP DNSBLs,
    and the domain on domain blacklists."""
    addresses: list[str] = []
    try:
        hosts = [host for _, host in sorted(resolver.values(domain, "MX")) if host] or [domain]
    except DnsError as error:
        return _failed_lookup("blacklist", error)
    for host in hosts[:4]:
        try:
            addresses += [a for a in resolver.values(host, "A") if a not in addresses][:2]
        except DnsError:
            pass
    try:
        if ip and ipaddress.ip_address(ip).version == 4 and ip not in addresses:
            addresses.append(ip)
    except ValueError:
        pass
    addresses = [a for a in addresses if ipaddress.ip_address(a).is_global]
    jobs = [(address, name, ".".join(reversed(address.split("."))) + "." + zone)
            for address in addresses for name, zone in IP_BLACKLISTS]
    jobs += [(domain, name, f"{domain}.{zone}") for name, zone in DOMAIN_BLACKLISTS]
    with ThreadPoolExecutor(max_workers=16) as pool:
        answers = list(pool.map(lambda job: _dnsbl(job[2], resolver), jobs))
    listed = [f"{target} on {name} ({', '.join(found)})"
              for (target, name, _), (found, _) in zip(jobs, answers) if found]
    refused = sorted({name for (_, name, _), (_, no) in zip(jobs, answers) if no})
    checked = len(IP_BLACKLISTS) + len(DOMAIN_BLACKLISTS) - len(refused)
    records = [f"Checked {', '.join(addresses + [domain])}"]
    details = []
    for kind, lists in (("IP", IP_BLACKLISTS), ("domain", DOMAIN_BLACKLISTS)):
        for name, _ in lists:
            results = [(target, found, no) for (target, list_name, _), (found, no)
                       in zip(jobs, answers) if list_name == name]
            hits = [f"{target} ({', '.join(found)})" for target, found, _ in results if found]
            if hits:
                mark, status = "✗", f"Listed {', '.join(hits)}"
            elif not results:
                mark, status = "–", "Not checked (no IP)"
            elif any(no for _, _, no in results):
                mark, status = "!", "No answer"
            else:
                mark, status = "✓", "Passed"
            details.append(f"{mark} {name} ({kind}): {status}")
    if refused:
        details.append(f"No answer from {', '.join(refused)} (some lists refuse queries "
                       "from public DNS such as 8.8.8.8).")
    if listed:
        return CheckResult("blacklist", FAIL, f"Listed on {len(listed)} blocklist"
                           f"{'s' if len(listed) != 1 else ''}", records, details)
    if not addresses:
        return CheckResult("blacklist", NOTICE, "No mail server IP to check", records,
                           details + ["Only the domain was checked."])
    return CheckResult("blacklist", NOTICE if refused else PASS,
                       f"Not listed in {checked} checked lists", records, details)


def run_check(key: str, domain: str, resolver: Resolver, selectors: list[str] | None = None,
              ip: str = "") -> CheckResult:
    from . import domain_info

    try:
        if key == "ns":
            return check_ns(domain, resolver)
        if key == "soa":
            return check_soa(domain, resolver)
        if key == "provider":
            return check_provider(domain, resolver)
        if key == "blacklist":
            return check_blacklist(domain, resolver, ip)
        if key == "ssl":
            return domain_info.check_ssl(domain, resolver)
        if key == "whois":
            return domain_info.check_registration(domain)
        if key == "address":
            return check_address(domain, resolver)
        if key == "mx":
            return check_mx(domain, resolver)
        if key == "spf":
            return check_spf(domain, resolver)
        if key == "dmarc":
            return check_dmarc(domain, resolver)
        if key == "dkim":
            return check_dkim(domain, resolver, selectors or [])
        if key == "ptr":
            return check_ptr(resolver, ip)
    except DnsError as error:
        return _failed_lookup(key, error)
    raise KeyError(key)


def parse_selectors(text: str) -> list[str]:
    return [s for s in re.split(r"[\s,;]+", text.strip()) if s]


def check_domain(domain: str, server: str = "", selectors: list[str] | None = None,
                 ip: str = "", timeout: float = DEFAULT_TIMEOUT, port: int = DNS_PORT) -> Report:
    """Every check for `domain`, run side by side."""
    resolver = Resolver([server] if server else None, timeout, port)
    with ThreadPoolExecutor(max_workers=len(CHECKS)) as pool:  # slowest: whois, blacklists
        results = list(pool.map(
            lambda key: run_check(key, domain, resolver, selectors, ip), CHECKS))
    return Report(domain=domain, results=results, server=server)
