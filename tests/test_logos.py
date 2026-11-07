import os
import time

from NetInfoView.ping import logos
from NetInfoView.ping.logos import domain_for, icon_links, looks_like_image, registrable_domain


def test_registrable_domain():
    assert registrable_domain("speedtest-sp1.3bb.co.th.prod.hosts.ooklaserver.net:8080") == "3bb.co.th"
    assert registrable_domain("ams.speedtest.clouvider.net") == "clouvider.net"
    assert registrable_domain("speedtest.rmutp.ac.th") == "rmutp.ac.th"
    assert registrable_domain("localhost") == ""
    assert registrable_domain("127.0.0.1") == ""


def test_domain_for_prefers_the_table_then_sponsor_url_then_server():
    assert domain_for("AIS Fibre") == "ais.th"
    assert domain_for("TrueMove H", server_url="https://truemoveookla-cbr.trueinternet.co.th:8080") == "true.th"
    assert domain_for("Clouvider", "https://www.clouvider.co.uk/") == "clouvider.co.uk"
    assert domain_for("Someone", server_url="https://speedtest.example.org:8080") == "example.org"
    assert domain_for("Someone") == ""


def test_icon_links_biggest_first():
    page = """<html><head>
      <link rel="icon" href="/favicon-16.png" sizes="16x16">
      <link rel="apple-touch-icon" href="/apple.png">
      <link rel="icon" type="image/png" href="https://cdn.example/icon-96.png" sizes="96x96">
      <link rel="stylesheet" href="/x.css">
    </head></html>"""
    assert icon_links(page, "https://example.org/home") == [
        "https://example.org/apple.png", "https://cdn.example/icon-96.png",
        "https://example.org/favicon-16.png"]


def test_looks_like_image():
    assert looks_like_image(b"\x89PNG\r\n\x1a\n....")
    assert looks_like_image(b"\x00\x00\x01\x00\x02\x00")
    assert looks_like_image(b"<svg xmlns='...'></svg>")
    assert not looks_like_image(b"<!doctype html><html>")


def test_cache_keeps_hits_and_misses(tmp_path):
    assert logos.cached("a.example", tmp_path) == (False, None)
    logos.remember("a.example", b"\x89PNGdata", tmp_path)
    assert logos.cached("a.example", tmp_path) == (True, b"\x89PNGdata")
    logos.remember("b.example", None, tmp_path)
    assert logos.cached("b.example", tmp_path) == (True, None)
    # A site without a logo is asked again after a week.
    old = time.time() - logos.RETRY_S - 10
    os.utime(tmp_path / "b.example.none", (old, old))
    assert logos.cached("b.example", tmp_path) == (False, None)


def test_logo_for_fetches_once(tmp_path, monkeypatch):
    calls = []
    monkeypatch.setattr(logos, "fetch_logo", lambda d: calls.append(d) or b"\x89PNGx")
    assert logos.logo_for("c.example", tmp_path) == b"\x89PNGx"
    assert logos.logo_for("c.example", tmp_path) == b"\x89PNGx"
    assert calls == ["c.example"]


def test_fetch_logo_falls_back_to_favicon(monkeypatch):
    def fake_get(url, limit):
        if url.endswith("/favicon.ico"):
            return b"\x00\x00\x01\x00icon", url
        if url.endswith("/"):
            return b"<html><link rel=icon href=/broken.png></html>", url
        return b"<html>not an image</html>", url
    monkeypatch.setattr(logos, "_get", fake_get)
    assert logos.fetch_logo("d.example") == b"\x00\x00\x01\x00icon"
