"""Where a speed test server is: country, city, airport code, region and
flag, read from a LibreSpeed server's name ("Tokyo, Japan (A573)",
"Los Angeles, United States (1) (Clouvider)", "Grand Rapids, Michigan
(RackGenius)"). Qt-free, for the Speed Test window's server picker."""

from __future__ import annotations

import re
from dataclasses import dataclass

from .provider import tidy_name
from .speedtest import ServerSpec

REGIONS = ("Asia", "Europe", "Americas", "Oceania", "Africa")

#: Country name → (ISO 3166 code, region).
COUNTRIES = {
    "Australia": ("AU", "Oceania"), "Austria": ("AT", "Europe"), "Belgium": ("BE", "Europe"),
    "Brazil": ("BR", "Americas"), "Bulgaria": ("BG", "Europe"), "Canada": ("CA", "Americas"),
    "Chile": ("CL", "Americas"), "China": ("CN", "Asia"), "Croatia": ("HR", "Europe"),
    "Czech Republic": ("CZ", "Europe"), "Denmark": ("DK", "Europe"), "Finland": ("FI", "Europe"),
    "France": ("FR", "Europe"), "Germany": ("DE", "Europe"), "Greece": ("GR", "Europe"),
    "Hong Kong": ("HK", "Asia"), "Hungary": ("HU", "Europe"), "India": ("IN", "Asia"),
    "Indonesia": ("ID", "Asia"), "Ireland": ("IE", "Europe"), "Israel": ("IL", "Asia"),
    "Italy": ("IT", "Europe"), "Japan": ("JP", "Asia"), "Malaysia": ("MY", "Asia"),
    "Mexico": ("MX", "Americas"), "Netherlands": ("NL", "Europe"),
    "New Zealand": ("NZ", "Oceania"), "Norway": ("NO", "Europe"),
    "Philippines": ("PH", "Asia"), "Poland": ("PL", "Europe"), "Portugal": ("PT", "Europe"),
    "Romania": ("RO", "Europe"), "Serbia": ("RS", "Europe"), "Singapore": ("SG", "Asia"),
    "Slovakia": ("SK", "Europe"), "Slovenia": ("SI", "Europe"),
    "South Africa": ("ZA", "Africa"), "South Korea": ("KR", "Asia"), "Spain": ("ES", "Europe"),
    "Sweden": ("SE", "Europe"), "Switzerland": ("CH", "Europe"), "Taiwan": ("TW", "Asia"),
    "Thailand": ("TH", "Asia"), "Turkey": ("TR", "Europe"), "Ukraine": ("UA", "Europe"),
    "United Arab Emirates": ("AE", "Asia"), "United Kingdom": ("GB", "Europe"),
    "United States": ("US", "Americas"), "Vietnam": ("VN", "Asia"),
}

ALIASES = {
    "USA": "United States", "US": "United States", "United States of America": "United States",
    "UK": "United Kingdom", "England": "United Kingdom", "Scotland": "United Kingdom",
    "Wales": "United Kingdom", "Great Britain": "United Kingdom", "Czechia": "Czech Republic",
    "Korea": "South Korea", "The Netherlands": "Netherlands", "Holland": "Netherlands",
    "Deutschland": "Germany", "UAE": "United Arab Emirates",
}

US_STATES = {
    "Alabama", "Arizona", "California", "Colorado", "Florida", "Georgia", "Illinois",
    "Indiana", "Michigan", "Minnesota", "Missouri", "Nevada", "New Jersey", "New York",
    "North Carolina", "Ohio", "Oregon", "Pennsylvania", "Texas", "Utah", "Virginia",
    "Washington",
}

#: City → its main airport's IATA code, the short name the picker shows.
CITY_CODES = {
    "Amsterdam": "AMS", "Atlanta": "ATL", "Belgrade": "BEG", "Chicago": "ORD",
    "Dallas": "DFW", "Denver": "DEN", "Frankfurt": "FRA", "Grand Rapids": "GRR",
    "Helsinki": "HEL", "Hong Kong": "HKG", "Las Vegas": "LAS", "London": "LHR",
    "Los Angeles": "LAX", "Madrid": "MAD", "Miami": "MIA", "Milan": "MXP",
    "New York": "JFK", "Paris": "CDG", "Poznan": "POZ", "Prague": "PRG", "Roma": "FCO",
    "Rome": "FCO", "San Jose": "SJC", "Seattle": "SEA", "Singapore": "SIN",
    "Stockholm": "ARN", "Sydney": "SYD", "Tokyo": "NRT", "Toronto": "YYZ",
    "Vienna": "VIE", "Warsaw": "WAW", "Zurich": "ZRH",
    # Thailand
    "Bangkok": "BKK", "Chiang Mai": "CNX", "Chiangmai": "CNX", "Chiang Rai": "CEI",
    "Hat Yai": "HDY", "Songkhla": "HDY", "Khon Kaen": "KKC", "Phuket": "HKT",
    "Surat Thani": "URT", "Udon Thani": "UTH", "Ubon Ratchathani": "UBP",
    "Nakhon Ratchasima": "NAK", "Phitsanulok": "PHS", "Nakhon Si Thammarat": "NST",
    "Pattaya": "UTP", "Rayong": "UTP", "Krabi": "KBV", "Trang": "TST",
}

#: Countries with their own filter chip in the picker, before the regions.
COUNTRY_CHIPS = ("Thailand",)


@dataclass(frozen=True)
class Location:
    country: str
    city: str
    code: str = ""      # IATA code of the city, if known
    iso: str = ""       # ISO 3166 country code, if known
    region: str = "Other"
    sponsor: str = ""

    @property
    def subtitle(self) -> str:
        """"Tokyo · NRT · A573"."""
        return " · ".join(p for p in (self.city, self.code, self.sponsor) if p)

    @property
    def local(self) -> bool:
        """A server in a country with its own chip: many share the country,
        so the city leads instead."""
        return self.country in COUNTRY_CHIPS

    @property
    def title(self) -> str:
        return (self.city or self.country) if self.local else self.country

    @property
    def place(self) -> str:
        """The line under the title: "Tokyo · NRT", or for a local server
        (whose title is already its city) "Thailand · BKK"."""
        if self.local:
            return " · ".join(p for p in (self.country, self.code) if p)
        return " · ".join(p for p in (self.city, self.code) if p)

    @property
    def short(self) -> str:
        """For the Server field and "Selected:": "Tokyo · A573"."""
        return " · ".join(p for p in (self.city or self.country, self.sponsor) if p)

    @property
    def detail(self) -> str:
        """The line under the title: "Tokyo · NRT · A573", or for a local
        server "BKK · True Online"."""
        if self.local:
            return " · ".join(p for p in (self.code, self.sponsor) if p) or self.country
        return self.subtitle

    def matches(self, query: str) -> bool:
        query = query.strip().casefold()
        return not query or any(query in p.casefold() for p in (
            self.country, self.city, self.code, self.iso, self.sponsor, self.region))


def flag(iso: str) -> str:
    """The flag emoji for a two-letter country code ("" if there isn't one)."""
    if len(iso) != 2 or not iso.isalpha():
        return ""
    return "".join(chr(0x1F1E6 + ord(c) - ord("A")) for c in iso.upper())


def country_info(name: str) -> tuple[str, str, str]:
    """(country, ISO code, region) for a country, alias or US state."""
    name = name.strip()
    name = ALIASES.get(name, name)
    if name in US_STATES:
        name = "United States"
    iso, region = COUNTRIES.get(name, ("", "Other"))
    return name, iso, region


def locate(spec: ServerSpec) -> Location:
    sponsor = tidy_name(spec.sponsor) if spec.sponsor else ""
    plain = re.sub(r"\s*\([^)]*\)", "", spec.name).strip()
    parts = [p.strip() for p in plain.split(",") if p.strip()]
    if not parts:
        return Location(country=spec.name, city="", sponsor=sponsor)
    city = parts[0]
    country, iso, region = country_info(parts[-1] if len(parts) > 1 else parts[0])
    return Location(country=country, city=city if len(parts) > 1 else "",
                    code=CITY_CODES.get(city, ""), iso=iso, region=region, sponsor=sponsor)
