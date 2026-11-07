"""Who connects this Mac to the Internet: the public address as Cloudflare
sees it (speed.cloudflare.com/cdn-cgi/trace), and the organisation that
holds that address, from the regional Internet registry over RDAP (the
registries' public lookup protocol; rdap.org sends the query on to the
right one). Well-known Thai providers get the brand people call them by
instead of their registered names ("ADVANCED WIRELESS NETWORK COMPANY
LIMITED" is AIS). Qt-free."""

from __future__ import annotations

import json
import re
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, replace

from ..https import urlopen

TRACE_URL = "https://speed.cloudflare.com/cdn-cgi/trace"
#: The same trace from Cloudflare's resolver addresses, so each answers over
#: one IP version only: the public IPv4 and IPv6 address apart.
TRACE_V4_URL = "https://1.1.1.1/cdn-cgi/trace"
TRACE_V6_URL = "https://[2606:4700:4700::1111]/cdn-cgi/trace"
RDAP_URLS = ("https://rdap.org/ip/{ip}", "https://rdap.apnic.net/ip/{ip}")
USER_AGENT = "NetInfoView-SpeedTest"

#: (words in the registered name, brand people know it by).
BRANDS = (
    (("advanced wireless", "advanced info", "awn-"), "AIS"),
    (("true internet", "true move", "truemove", "true online", "true corporation",
      "true universal"), "True Online"),
    (("triple t", "3bb", "jasmine"), "3BB"),
    (("national telecom", "tot public", "cat telecom"), "NT"),
    (("total access", "dtac"), "DTAC"),
    (("singapore telecom", "singtel"), "Singtel"),
)

_SUFFIXES = re.compile(
    r"[,.\s]*\b(public company limited|company limited|co\.?,? ?ltd\.?|limited|ltd\.?|"
    r"inc\.?|corporation|corp\.?|llc|plc|pte\.?|gmbh|s\.?a\.?)\s*$",
    re.IGNORECASE,
)


@dataclass(frozen=True)
class Provider:
    name: str           # what to show: "AIS", or the tidied registered name
    organisation: str   # the registered name, as given
    ip: str = ""        # the address looked up (IPv4 when there is one)
    network: str = ""   # the registry's name for the block, e.g. AWN-CO-LTD-TH
    country: str = ""
    ipv4: str = ""
    ipv6: str = ""


def brand_name(organisation: str) -> str:
    """"ADVANCED WIRELESS NETWORK COMPANY LIMITED" → "AIS"; otherwise the
    name tidied (tidy_name)."""
    lowered = f"{organisation.casefold()} "
    for words, brand in BRANDS:
        if any(word in lowered for word in words):
            return brand
    return tidy_name(organisation)


def tidy_name(organisation: str) -> str:
    """The name without its company-type suffixes ("ReadyIDC Co., Ltd." →
    "ReadyIDC"), and in title case if it was all capitals."""
    name = organisation.strip()
    while True:
        tidied = _SUFFIXES.sub("", name).strip(" ,.")
        if tidied == name or not tidied:
            break
        name = tidied
    if name.isupper():
        name = " ".join(w if len(w) <= 3 else w.capitalize() for w in name.split())
    return name


def _vcard(entity: dict, field: str) -> str:
    try:
        rows = entity["vcardArray"][1]
    except (KeyError, IndexError, TypeError):
        return ""
    return next((str(r[3]) for r in rows if isinstance(r, list) and len(r) > 3 and r[0] == field), "")


def parse_rdap(data: object) -> tuple[str, str, str]:
    """(organisation, network name, country) from an RDAP IP network: the
    registrant's name, else the block's description, else its name."""
    if not isinstance(data, dict):
        return "", "", ""
    organisation = ""
    for entity in data.get("entities") or []:
        if isinstance(entity, dict) and "registrant" in (entity.get("roles") or []):
            organisation = _vcard(entity, "fn")
            if organisation:
                break
    if not organisation:
        for remark in data.get("remarks") or []:
            if isinstance(remark, dict) and remark.get("title") == "description":
                lines = remark.get("description") or []
                if lines:
                    organisation = str(lines[0])
                    break
    network = str(data.get("name") or "")
    return organisation or network, network, str(data.get("country") or "")


def public_ip(timeout: float = 6.0, url: str = TRACE_URL) -> str:
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    with urlopen(request, timeout) as resp:
        text = resp.read().decode("utf-8", "replace")
    return next((line[3:].strip() for line in text.splitlines() if line.startswith("ip=")), "")


def public_ips(timeout: float = 6.0) -> tuple[str, str]:
    """(IPv4, IPv6) public addresses; "" for a version this connection lacks."""
    def ask(url: str) -> str:
        try:
            return public_ip(timeout, url)
        except OSError:
            return ""
    with ThreadPoolExecutor(max_workers=2) as pool:
        v4, v6 = pool.map(ask, (TRACE_V4_URL, TRACE_V6_URL))
    if not v4 and not v6:  # the resolver addresses may be blocked: try the usual way
        either = ask(TRACE_URL)
        v4, v6 = (either, "") if ":" not in either else ("", either)
    return v4, v6


def lookup(ip: str, timeout: float = 8.0) -> Provider | None:
    """The registry's record for `ip`, or None if no registry answers."""
    for template in RDAP_URLS:
        url = template.format(ip=urllib.parse.quote(ip, safe=":."))
        request = urllib.request.Request(
            url, headers={"User-Agent": USER_AGENT, "Accept": "application/rdap+json"})
        try:
            with urlopen(request, timeout) as resp:
                organisation, network, country = parse_rdap(json.load(resp))
        except (OSError, ValueError):
            continue
        if organisation:
            return Provider(brand_name(organisation), organisation, ip, network, country)
    return None


def fetch_provider(timeout: float = 8.0) -> tuple[bool, Provider | None]:
    """(online, provider): online is whether the Internet could be reached
    at all; the provider is None when the registry couldn't say."""
    v4, v6 = public_ips(timeout)
    if not v4 and not v6:
        return False, None
    found = lookup(v4 or v6, timeout)
    if found is None:
        return True, Provider("", "", v4 or v6, ipv4=v4, ipv6=v6)
    return True, replace(found, ipv4=v4, ipv6=v6)


def initials(name: str) -> str:
    """A badge's letters: "AIS" → "AIS", "True Online" → "TO",
    "Clouvider" → "CL", "3BB" → "3BB"."""
    words = [w for w in re.split(r"[\s\-_.,()]+", name) if w]
    if not words:
        return "?"
    first = words[0]
    if len(first) <= 4 and (first.isupper() or first[0].isdigit()):
        return first
    capitals = [c for c in first if c.isupper()]
    if len(capitals) >= 2 and not first.isupper():  # TrueMove → TM, CodeStudio → CS
        return "".join(capitals[:3])
    if len(words) >= 2:
        return (words[0][0] + words[1][0]).upper()
    return first[:2].upper()


#: Badge colours, picked by name so a provider always gets the same one.
BADGE_COLORS = ("#0b7a3b", "#c2410c", "#1d4ed8", "#7c3aed", "#be123c", "#0e7490",
                "#a16207", "#4338ca", "#15803d", "#b91c1c")


def badge_color(name: str) -> str:
    return BADGE_COLORS[sum(ord(c) for c in name.casefold()) % len(BADGE_COLORS)]
