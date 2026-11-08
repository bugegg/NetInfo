"""Providers' logos for Speed Test: the icon each provider's own website
offers (its <link rel="icon"> / apple-touch-icon, else /favicon.ico),
fetched when first needed and kept in a cache folder, so no brand's artwork
ships with the app. Which website: LibreSpeed's list names each sponsor's;
for Thai ISPs and Ookla servers a small table, else the server's own
domain. Qt-free; the window decodes the bytes.
"""

from __future__ import annotations

import html.parser
import re
import time
import urllib.parse
import urllib.request
from pathlib import Path

from ..fileio.vendor_db import _app_data_dir
from ..https import urlopen

USER_AGENT = "NetInfoView-SpeedTest"
TIMEOUT_S = 6.0
MAX_PAGE = 1_000_000
MAX_ICON = 512_000
#: A logo found is kept this long; a site without one is asked again after.
KEEP_S = 30 * 86400
RETRY_S = 7 * 86400

#: Provider (brand or Ookla sponsor) → its website, where the name alone
#: doesn't lead there.
DOMAINS = {
    "ais": "ais.th", "ais fibre": "ais.th", "awn": "ais.th", "mimotech": "ais.th",
    "true online": "true.th", "truemove h": "true.th", "true": "true.th",
    "3bb": "3bb.co.th", "nt": "ntplc.co.th", "nt corporate": "ntplc.co.th",
    "nt bangrak": "ntplc.co.th", "cat telecom": "ntplc.co.th", "tot": "ntplc.co.th",
    "dtac": "dtac.co.th", "byteark": "byteark.com", "bangmod enterprise": "bangmod.cloud",
    "siamcolo": "siamcolo.net", "readyidc": "readyidc.com", "tcc technology": "tcc-technology.com",
    "singtel": "singtel.com", "cloudflare": "cloudflare.com",
}

_SECOND_LEVEL = {"co", "ac", "or", "go", "in", "net", "com", "org", "mi", "edu", "gov"}
_OOKLA_SUFFIX = ".prod.hosts.ooklaserver.net"


def registrable_domain(host: str) -> str:
    """"speedtest-sp1.3bb.co.th.prod.hosts.ooklaserver.net" → "3bb.co.th"."""
    host = host.lower().strip(".").split(":")[0]
    if host.endswith(_OOKLA_SUFFIX):
        host = host[: -len(_OOKLA_SUFFIX)]
    labels = [label for label in host.split(".") if label]
    if len(labels) < 2 or all(label.isdigit() for label in labels):
        return ""
    if len(labels) >= 3 and len(labels[-1]) == 2 and labels[-2] in _SECOND_LEVEL:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


def domain_for(name: str = "", url: str = "", server_url: str = "") -> str:
    """The website for a provider: the table, else a URL it gave (a
    sponsor URL), else the domain of the server it runs."""
    key = re.sub(r"[^a-z0-9 ]+", "", name.casefold()).strip()
    if key in DOMAINS:
        return DOMAINS[key]
    for candidate in (url, server_url):
        host = urllib.parse.urlsplit(candidate.strip()).hostname if candidate else None
        if host:
            domain = registrable_domain(host)
            if domain:
                return domain
    return ""


class _IconLinks(html.parser.HTMLParser):
    """<link rel="icon" ...> and friends, with their declared sizes."""

    def __init__(self) -> None:
        super().__init__()
        self.links: list[tuple[int, str]] = []

    def handle_starttag(self, tag, attrs):
        if tag != "link":
            return
        a = {k.lower(): (v or "") for k, v in attrs}
        rel = a.get("rel", "").lower().split()
        href = a.get("href", "").strip()
        if not href or not ({"icon", "apple-touch-icon", "apple-touch-icon-precomposed"} & set(rel)):
            return
        size = 0
        for token in a.get("sizes", "").lower().split():
            if "x" in token and token.split("x")[0].isdigit():
                size = max(size, int(token.split("x")[0]))
            elif token == "any":
                size = max(size, 512)
        if "apple-touch-icon" in rel or "apple-touch-icon-precomposed" in rel:
            size = max(size, 180)
        if href.lower().split("?")[0].endswith(".svg"):
            size = max(size, 256)
        self.links.append((size, href))


def icon_links(page: str, base: str) -> list[str]:
    """Icon URLs a page declares, biggest first."""
    parser = _IconLinks()
    try:
        parser.feed(page)
    except Exception:  # a broken page just has no icons
        return []
    ranked = sorted(parser.links, key=lambda sl: -sl[0])
    return [urllib.parse.urljoin(base, href) for _, href in ranked]


def looks_like_image(data: bytes) -> bool:
    head = data[:16].lstrip()
    return (head.startswith(b"\x89PNG") or head.startswith(b"\x00\x00\x01\x00")
            or head.startswith(b"\xff\xd8") or head.startswith(b"GIF8")
            or head.startswith(b"RIFF") or head.startswith(b"<svg")
            or (head.startswith(b"<?xml") and b"<svg" in data[:2000]))


def _get(url: str, limit: int) -> tuple[bytes, str]:
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    with urlopen(request, TIMEOUT_S) as resp:
        return resp.read(limit + 1), resp.geturl()


def fetch_logo(domain: str) -> bytes | None:
    """The best icon the site offers, or None."""
    candidates: list[str] = []
    for root in (f"https://{domain}/", f"https://www.{domain}/"):
        try:
            page, final = _get(root, MAX_PAGE)
        except (OSError, ValueError):
            continue
        candidates = icon_links(page.decode("utf-8", "replace"), final)
        candidates.append(urllib.parse.urljoin(final, "/favicon.ico"))
        break
    if not candidates:
        candidates = [f"https://{domain}/favicon.ico"]
    for url in candidates:
        if not url.startswith(("https://", "http://")):
            continue
        try:
            data, _ = _get(url, MAX_ICON)
        except (OSError, ValueError):
            continue
        if len(data) <= MAX_ICON and looks_like_image(data):
            return data
    return None


def cache_dir() -> Path:
    return _app_data_dir() / "NetInfoView" / "logos"


def _safe(domain: str) -> str:
    return re.sub(r"[^a-z0-9.\-]", "_", domain.lower())


def cached(domain: str, folder: Path | None = None) -> tuple[bool, bytes | None]:
    """(known, logo): known is False when the site should be asked (never
    asked, or long enough ago); logo is None for a site known to have none."""
    folder = folder or cache_dir()
    now = time.time()
    hit, miss = folder / f"{_safe(domain)}.img", folder / f"{_safe(domain)}.none"
    try:
        if hit.is_file() and now - hit.stat().st_mtime < KEEP_S:
            return True, hit.read_bytes()
        if miss.is_file() and now - miss.stat().st_mtime < RETRY_S:
            return True, None
    except OSError:
        pass
    return False, None


def remember(domain: str, data: bytes | None, folder: Path | None = None) -> None:
    folder = folder or cache_dir()
    try:
        folder.mkdir(parents=True, exist_ok=True)
        hit, miss = folder / f"{_safe(domain)}.img", folder / f"{_safe(domain)}.none"
        if data:
            hit.write_bytes(data)
            miss.unlink(missing_ok=True)
        else:
            miss.write_bytes(b"")
    except OSError:
        pass  # no cache this time; the logo still shows


def logo_for(domain: str, folder: Path | None = None) -> bytes | None:
    """Cached or fetched (and then cached)."""
    known, data = cached(domain, folder)
    if known:
        return data
    data = fetch_logo(domain)
    remember(domain, data, folder)
    return data
