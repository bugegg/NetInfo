"""The <title> of a device's web page — the last resort for naming a host,
since a printer, camera or router's admin page is often titled with its
model or the name it was given. Titles that only say what the page is
("Login", "Welcome to nginx!") are not names and are skipped.
"""

from __future__ import annotations

import html
import re
import socket
import ssl
from functools import partial

from .parallel import first_answer
from .tls_cert import open_tls

HTTP_PORTS = ((80, False), (443, True))
DEFAULT_TIMEOUT = 2.0
MAX_RESPONSE_BYTES = 64 * 1024
MAX_TITLE_LENGTH = 63

_TITLE = re.compile(rb"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)
_STATUS_TITLE = re.compile(r"^\d{3}\b")
_GENERIC_TITLES = {
    "", "index", "index.html", "home", "home page", "homepage", "welcome", "login", "log in",
    "logon", "sign in", "signin", "redirect", "redirecting", "redirecting...", "loading",
    "loading...", "untitled", "document", "error", "not found", "forbidden", "unauthorized",
    "access denied", "web server", "web interface", "management", "it works!",
    "welcome to nginx!", "nginx", "apache2 ubuntu default page: it works",
    "apache2 debian default page: it works", "iis windows server", "iis windows",
    "test page for the apache http server", "default page", "web ui", "webui",
}


def title_from_html(body: bytes) -> str:
    """The page title if it's a usable name, else ""."""
    match = _TITLE.search(body)
    if not match:
        return ""
    title = " ".join(html.unescape(match.group(1).decode("utf-8", "replace")).split())
    if (
        title.lower() in _GENERIC_TITLES
        or _STATUS_TITLE.match(title)
        or len(title) > MAX_TITLE_LENGTH
    ):
        return ""
    return title


def _fetch(ip: str, port: int, use_tls: bool, timeout: float) -> bytes:
    request = (
        f"GET / HTTP/1.0\r\nHost: {ip}\r\nUser-Agent: NetInfo\r\n"
        "Accept: text/html\r\nConnection: close\r\n\r\n"
    ).encode("ascii")
    with socket.create_connection((ip, port), timeout=timeout) as raw:
        sock = open_tls(raw) if use_tls else raw
        with sock:
            sock.sendall(request)
            data = b""
            while len(data) < MAX_RESPONSE_BYTES and b"</title>" not in data.lower():
                chunk = sock.recv(8192)
                if not chunk:
                    break
                data += chunk
    return data


def lookup(ip: str, timeout: float = DEFAULT_TIMEOUT) -> str:
    """The title of the first web page at `ip` that has a usable one. The
    ports are tried at once, like tls_cert.lookup."""
    return first_answer([partial(_title_on_port, ip, port, use_tls, timeout)
                         for port, use_tls in HTTP_PORTS])


def _title_on_port(ip: str, port: int, use_tls: bool, timeout: float) -> str:
    try:
        return title_from_html(_fetch(ip, port, use_tls, timeout))
    except (OSError, ssl.SSLError):
        return ""
