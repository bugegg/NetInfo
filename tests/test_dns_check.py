"""DNS Check (ping/dns_check.py and its window, ui/dns_check_window.py),
against a fake DNS server on localhost."""

import base64
import socket
import ssl
import struct
import subprocess
import threading
import time
from datetime import datetime, timezone

import pytest
from PyQt6.QtWidgets import QApplication, QInputDialog

from NetInfoView.ping import ber, dns_check, domain_info
from NetInfoView.ui import dns_check_window
from NetInfoView.ui.dns_check_window import DnsCheckWindow
from test_main_window import qapp, window  # noqa: F401

T = dns_check.TYPES


def _name(name: str) -> bytes:
    return b"".join(bytes([len(p)]) + p.encode() for p in name.split(".") if p) + b"\0"


def _txt(text: str) -> bytes:
    raw = text.encode()
    return b"".join(bytes([len(raw[i:i + 255])]) + raw[i:i + 255] for i in range(0, len(raw), 255))


def _spki(bits: int) -> str:
    modulus = (1 << (bits - 1)) | 1
    rsa = ber.encode(ber.SEQUENCE, ber.encode_int(modulus) + ber.encode_int(65537))
    alg = ber.encode(ber.SEQUENCE, ber.encode(ber.OID, bytes.fromhex("2a864886f70d010101"))
                     + ber.encode(ber.NULL, b""))
    return base64.b64encode(ber.encode(ber.SEQUENCE, alg + ber.encode(0x03, b"\0" + rsa))).decode()


ZONE = {
    ("good.test", T["NS"]): [_name("ns1.good.test"), _name("ns2.good.test")],
    ("ns1.good.test", T["A"]): [socket.inet_aton("127.0.0.1")],
    ("ns2.good.test", T["A"]): [socket.inet_aton("127.0.0.1")],
    ("good.test", T["SOA"]): [_name("ns1.good.test") + _name("hostmaster.good.test")
                              + struct.pack("!IIIII", 2026111701, 7200, 900, 1209600, 3600)],
    ("good.test", T["A"]): [socket.inet_aton("192.0.2.10")],
    ("good.test", T["MX"]): [struct.pack("!H", 10) + _name("mail.good.test")],
    ("_mta-sts.good.test", T["TXT"]): [_txt("v=STSv1; id=20261120")],
    ("_smtp._tls.good.test", T["TXT"]): [_txt("v=TLSRPTv1; rua=mailto:tls@good.test")],
    ("mail.good.test", T["A"]): [socket.inet_aton("192.0.2.25")],
    ("good.test", T["TXT"]): [_txt("v=spf1 ip4:192.0.2.0/24 include:_spf.good.test "
                                   "include:sendgrid.net -all"),
                              _txt("google-site-verification=abc")],
    ("sendgrid.net", T["TXT"]): [_txt("v=spf1 ip4:198.51.100.0/24 -all")],
    ("_spf.good.test", T["TXT"]): [_txt("v=spf1 a mx ~all")],
    ("_dmarc.good.test", T["TXT"]): [_txt("v=DMARC1; p=none; rua=mailto:d@good.test")],
    ("custom1._domainkey.good.test", T["TXT"]): [_txt(f"v=DKIM1; k=rsa; p={_spki(2048)}")],
    ("old._domainkey.good.test", T["TXT"]): [_txt("v=DKIM1; k=rsa; p=")],
    ("25.2.0.192.in-addr.arpa", T["PTR"]): [_name("mail.good.test")],
}


@pytest.fixture(autouse=True)
def offline_web_checks(monkeypatch):
    """SSL and registration go to the Internet; tests of them call the real
    functions directly."""
    monkeypatch.setattr(domain_info, "check_ssl",
                        lambda domain, resolver: dns_check.CheckResult("ssl", "pass", "stub"))
    monkeypatch.setattr(domain_info, "check_registration",
                        lambda domain: dns_check.CheckResult("whois", "pass", "stub"))
    monkeypatch.setattr(domain_info, "fetch_sts_policy", lambda domain: STS_POLICY)


STS_POLICY = "version: STSv1\nmode: enforce\nmx: *.good.test\nmax_age: 604800\n"


_REAL_SSL = domain_info.check_ssl
_REAL_REGISTRATION = domain_info.check_registration


@pytest.fixture
def dns_server():
    """A fake recursive + authoritative DNS server for ZONE on UDP and TCP."""
    udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp.bind(("127.0.0.1", 0))
    port = udp.getsockname()[1]
    tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    tcp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    tcp.bind(("127.0.0.1", port))
    tcp.listen()

    def answer(query: bytes) -> bytes:
        ident = query[:2]
        name, offset = dns_check._read_name(query, 12)
        qtype, _ = struct.unpack_from("!HH", query, offset)
        question = query[12:offset + 4]
        records = ZONE.get((name.lower(), qtype), [])
        known = any(key[0] == name.lower() for key in ZONE)
        rcode = 0 if known or records else 3
        flags = 0x8000 | 0x0400 | 0x0080 | rcode
        body = b"".join(b"\xc0\x0c" + struct.pack("!HHIH", qtype, 1, 300, len(r)) + r
                        for r in records)
        return ident + struct.pack("!HHHHH", flags, 1, len(records), 0, 0) + question + body

    def serve_udp():
        while True:
            try:
                message, peer = udp.recvfrom(4096)
            except OSError:
                return
            udp.sendto(answer(message), peer)

    def serve_tcp():
        while True:
            try:
                conn, _ = tcp.accept()
            except OSError:
                return
            with conn:
                size = struct.unpack("!H", conn.recv(2))[0]
                reply = answer(conn.recv(size))
                conn.sendall(struct.pack("!H", len(reply)) + reply)

    for target in (serve_udp, serve_tcp):
        threading.Thread(target=target, daemon=True).start()
    yield port
    udp.close()
    tcp.close()


def _check(port, domain="good.test", selectors=None, ip=""):
    return dns_check.check_domain(domain, "127.0.0.1", selectors or [], ip, timeout=1, port=port)


def test_normalise_domain():
    assert dns_check.normalise_domain(" Example.COM ") == "example.com"
    assert dns_check.normalise_domain("https://www.example.com/path?q=1") == "example.com"
    assert dns_check.normalise_domain("www.google.com") == "google.com"
    assert dns_check.normalise_domain("internal.penso.co.th") == "penso.co.th"
    assert dns_check.normalise_domain("a.b.example.com.au") == "example.com.au"
    assert dns_check.normalise_domain("ccthailand.co.th") == "ccthailand.co.th"
    assert dns_check.normalise_domain("someone@example.com") == "example.com"
    assert dns_check.normalise_domain("bücher.de") == "xn--bcher-kva.de"
    for bad in ("", "localhost", "exa mple.com", "-bad.com", "a..com"):
        assert dns_check.normalise_domain(bad) == ""


def test_parse_spf():
    good = dns_check.parse_spf("v=spf1 ip4:192.0.2.0/24 ip6:2001:db8::/32 include:x.test mx -all")
    assert not good.errors and good.lookups == 2 and good.all_qualifier == "-"
    bad = dns_check.parse_spf("v=spf1 ip4:300.1.1.1 include: bogus ~all")
    assert len(bad.errors) == 3
    assert any("+all" in w for w in dns_check.parse_spf("v=spf1 +all").warnings)
    assert dns_check.parse_spf("v=spf1 redirect=_spf.x.test").redirect == "_spf.x.test"


def test_rsa_key_bits():
    assert dns_check.rsa_key_bits(_spki(2048)) == 2048
    assert dns_check.rsa_key_bits(_spki(1024)) == 1024
    assert dns_check.rsa_key_bits("not base64!") == 0


def test_full_check(dns_server):
    report = _check(dns_server, selectors=["custom1"], ip="192.0.2.25")
    status = {r.key: r.status for r in report.results}
    assert status == {"ns": "pass", "soa": "pass", "address": "pass", "mx": "pass",
                      "provider": "info", "spf": "pass", "dmarc": "notice", "dkim": "pass",
                      "ptr": "pass", "blacklist": "notice", "ssl": "pass", "whois": "pass",
                      "mta_sts": "pass", "tlsrpt": "pass"}
    spf = report.result("spf")
    assert spf.records == ["v=spf1 ip4:192.0.2.0/24 include:_spf.good.test "
                           "include:sendgrid.net -all"]
    assert "4 of 10 DNS lookups used." in spf.details
    assert report.result("dmarc").summary == "Monitoring only · p=none"
    assert "2048-bit" in report.result("dkim").details[0]
    assert dns_check.counts_text(report) == "11 passed | 2 notices"
    assert report.result("mta_sts").summary == "Enforced"
    assert report.result("tlsrpt").summary == "Reports to tls@good.test"
    soa = report.result("soa")
    assert soa.summary == "Serials match"
    assert "All 2 nameservers serve serial 2026111701." in soa.details
    assert "Admin: hostmaster@good.test" in soa.details
    assert "refresh 2 hours" in soa.details[3] and "expire 2 weeks" in soa.details[3]
    provider = report.result("provider")
    assert provider.summary == "Self-hosted or unrecognised (mail.good.test)"
    assert provider.details == ["Sends through (SPF): SendGrid", "Verified with: Google"]
    # 192.0.2.x is documentation space: no public IP to look up on DNSBLs.
    assert report.result("blacklist").summary == "No mail server IP to check"


def test_dkim_auto_detects_common_selectors(dns_server, monkeypatch):
    report = _check(dns_server)
    assert report.result("dkim").status == dns_check.INPUT
    assert report.result("dkim").summary == "Selector required"
    monkeypatch.setattr(dns_check, "COMMON_SELECTORS", ("google", "old"))
    assert _check(dns_server).result("dkim").summary == "Only revoked keys found"
    monkeypatch.setattr(dns_check, "COMMON_SELECTORS", ("google", "old", "custom1"))
    dkim = _check(dns_server).result("dkim")
    assert dkim.status == dns_check.PASS and dkim.summary == "Valid for custom1"
    assert "trying common names" in dkim.details[-1]


def test_needs_input_and_missing_records(dns_server):
    report = _check(dns_server)
    assert report.result("dkim").status == dns_check.INPUT
    assert report.result("ptr").status == dns_check.INPUT
    assert "2 need input" in dns_check.counts_text(report)
    report = _check(dns_server, selectors=["nope"], ip="192.0.2.99")
    assert report.result("dkim").status == dns_check.FAIL
    assert report.result("ptr").summary == "No PTR record for 192.0.2.99"


def test_unknown_domain(dns_server):
    report = _check(dns_server, domain="missing.test")
    assert not report.exists
    assert [r.key for r in report.results] == ["ns"]
    assert report.result("ns").summary == "Domain doesn't exist (NXDOMAIN)"
    assert _check(dns_server).exists


def test_no_server_answering():
    report = dns_check.check_domain("good.test", "127.0.0.1", timeout=0.2, port=9)
    assert all(r.status == dns_check.ERROR for r in report.results
               if r.key not in ("dkim", "ptr", "ssl", "whois"))


def test_summary_and_json(dns_server):
    report = _check(dns_server)
    text = dns_check.summary_text(report)
    assert text.startswith("DNS check: good.test")
    assert "DMARC          Notice       Monitoring only · p=none" in text
    assert '"domain": "good.test"' in dns_check.report_json(report)


def test_history():
    history = dns_check_window.remember("a.test\nb.test", "b.test")
    assert history == "b.test\na.test"
    many = "\n".join(f"d{i}.test" for i in range(20))
    assert len(dns_check_window.history_list(dns_check_window.remember(many, "x.test"))) == 12


def _wait(cond, timeout=10.0):
    end = time.monotonic() + timeout
    while not cond() and time.monotonic() < end:
        QApplication.processEvents()
        time.sleep(0.01)
    assert cond()


def test_window_runs_a_check(window, dns_server, monkeypatch):  # noqa: F811
    monkeypatch.setattr(window.settings, "save", lambda: None)
    w = window.dns_check()
    assert window.dns_check() is w
    w.dns_port = dns_server
    w.server = "127.0.0.1"
    w.domain.setText("https://Good.test/")
    w.start()
    _wait(lambda: w.report is not None)
    assert w.domain.text() == "good.test"
    assert w.tree.topLevelItemCount() == len(dns_check.CHECKS)
    assert w.tree.topLevelItem(dns_check.CHECKS.index("dmarc")).text(1) == "Notice"
    assert w.tree.topLevelItem(dns_check.CHECKS.index("provider")).text(1) == "Info"
    assert w.chip_texts() == ["9 Passed", "2 Notices", "2 Needs input", "1 Info"]
    # Needs attention hides the passed and info rows.
    w.show_attention.click()
    shown = [w.tree.topLevelItem(i).text(0) for i in range(w.tree.topLevelItemCount())
             if not w.tree.topLevelItem(i).isHidden()]
    assert shown == ["DMARC", "DKIM", "PTR", "Blocklist"]
    assert w.show_attention.text() == "Needs attention (4)"
    w.show_all.click()
    # Expand all opens every row with details; pressed again it closes them.
    rows = [w.tree.topLevelItem(i) for i in range(w.tree.topLevelItemCount())
            if w.tree.topLevelItem(i).childCount()]
    assert rows and w.expand_button.text().startswith("Expand all")
    w.expand_button.click()
    assert all(row.isExpanded() for row in rows) and w.all_expanded()
    assert w.expand_button.text().startswith("Collapse all")
    w.expand_button.click()
    assert not any(row.isExpanded() for row in rows)
    assert window.settings.dns_check_history.splitlines()[0] == "good.test"
    assert w.copy_button.isEnabled()
    w.copy_summary()
    assert QApplication.clipboard().text().startswith("DNS check: good.test")

    # Adding the sending IP re-runs only PTR.
    w.sending_ip = "192.0.2.25"
    w.rerun("ptr")
    _wait(lambda: w.report.result("ptr").status == dns_check.PASS)
    assert w.tree.topLevelItem(dns_check.CHECKS.index("ptr")).text(1) == "Passed"
    w.close()


def test_window_rejects_bad_input(window):  # noqa: F811
    w = DnsCheckWindow(None, window)
    w.domain.setText("not a domain")
    w.start()
    assert w.report is None and "is not a domain" in w.placeholder.text()
    w.close()


def test_dns_server_menu(window, monkeypatch):  # noqa: F811
    monkeypatch.setattr(window.settings, "save", lambda: None)
    w = DnsCheckWindow(window.settings, window)
    w._fill_dns_menu()
    labels = [a.text() for a in w.dns_menu.actions() if not a.isSeparator()]
    assert labels[0] == "System default" and labels[-1] == "Custom…"
    assert "Cloudflare (1.1.1.1)" in labels
    w.dns_menu.actions()[2].trigger()  # Cloudflare
    assert w.server == "1.1.1.1" and window.settings.dns_check_server == "1.1.1.1"
    assert w.dns_label.text().startswith("DNS: 1.1.1.1 (Cloudflare)")
    monkeypatch.setattr(QInputDialog, "getText", lambda *a, **k: ("10.1.1.53", True))
    w._ask_server()
    assert w.server == "10.1.1.53"
    assert DnsCheckWindow(window.settings, window).server == "10.1.1.53"  # remembered
    w.set_server("")
    assert window.settings.dns_check_server == ""
    w.close()


def test_sidebar_button(window):  # noqa: F811
    assert window._dashboard.nav_dns_check.text() == "DNS Check"
    window._dashboard.nav_dns_check.click()
    window._dashboard.nav_dns_check.click()
    assert len(window.findChildren(DnsCheckWindow)) == 1


def test_dnsbl_answers(dns_server, monkeypatch):
    resolver = dns_check.Resolver(["127.0.0.1"], 1, dns_server)
    answers = {"2.0.0.127.zen.spamhaus.org": ["127.0.0.2"],
               "3.0.0.127.zen.spamhaus.org": ["127.255.255.254"]}
    monkeypatch.setattr(resolver, "values", lambda name, rtype: answers.get(name, []))
    assert dns_check._dnsbl("2.0.0.127.zen.spamhaus.org", resolver) == (["127.0.0.2"], False)
    assert dns_check._dnsbl("3.0.0.127.zen.spamhaus.org", resolver) == ([], True)
    assert dns_check._dnsbl("1.0.0.127.zen.spamhaus.org", resolver) == ([], False)


def test_blacklist_listed(dns_server, monkeypatch):
    resolver = dns_check.Resolver(["127.0.0.1"], 1, dns_server)
    listed = "8.8.8.8".split(".")[::-1]
    real = resolver.values

    def values(name, rtype):
        if name == ".".join(listed) + ".bl.spamcop.net":
            return ["127.0.0.2"]
        if name.endswith(tuple(zone for _, zone in dns_check.IP_BLACKLISTS
                               + dns_check.DOMAIN_BLACKLISTS)):
            return []
        return real(name, rtype)

    monkeypatch.setattr(resolver, "values", values)
    result = dns_check.check_blacklist("good.test", resolver, "8.8.8.8")
    assert result.status == dns_check.FAIL and result.summary == "Listed on 1 blocklist"
    assert result.details == [
        "✓ Spamhaus ZEN (IP): Passed", "✗ SpamCop (IP): Listed 8.8.8.8 (127.0.0.2)",
        "✓ Barracuda (IP): Passed", "✓ PSBL (IP): Passed", "✓ UCEPROTECT L1 (IP): Passed",
        "✓ Mailspike (IP): Passed", "✓ Spamhaus DBL (domain): Passed",
        "✓ SURBL (domain): Passed"]


def test_provider_tables():
    assert dns_check._match("aspmx.l.google.com", dns_check.MX_PROVIDERS) == ["Google Workspace"]
    assert dns_check._match("x-com.mail.protection.outlook.com",
                            dns_check.MX_PROVIDERS) == ["Microsoft 365"]


# -- registration and SSL (ping/domain_info.py) --------------------------------

NOW = datetime(2026, 11, 17, tzinfo=timezone.utc)


def test_parse_whois_formats():
    verisign = ("Registrar: Network Solutions, LLC\nCreation Date: 1998-08-21T04:00:00Z\n"
                "Registry Expiry Date: 2030-08-20T04:00:00Z\n")
    data = domain_info.parse_whois(verisign)
    assert data["registrar"] == "Network Solutions, LLC"
    assert data["created"] == datetime(1998, 8, 21, tzinfo=timezone.utc)
    assert data["expires"] == datetime(2030, 8, 20, tzinfo=timezone.utc)
    thnic = "Domain Name: EXAMPLE.CO.TH\nCreated date: 12 Feb 2004\nExp date: 11 Feb 2027\n"
    data = domain_info.parse_whois(thnic)
    assert data["expires"] == datetime(2027, 2, 11, tzinfo=timezone.utc)
    assert domain_info.parse_whois("nothing here")["expires"] is None


def test_parse_rdap():
    data = domain_info.parse_rdap({
        "events": [{"eventAction": "registration", "eventDate": "1995-08-13T04:00:00Z"},
                   {"eventAction": "expiration", "eventDate": "2027-08-12T04:00:00Z"}],
        "entities": [{"roles": ["registrar"],
                      "vcardArray": ["vcard", [["version", {}, "text", "4.0"],
                                               ["fn", {}, "text", "MarkMonitor Inc."]]]}],
        "status": ["client transfer prohibited"],
    })
    assert data["registrar"] == "MarkMonitor Inc."
    assert data["expires"] == datetime(2027, 8, 12, tzinfo=timezone.utc)


@pytest.mark.parametrize("expires, status, summary", [
    (datetime(2030, 8, 20, tzinfo=timezone.utc), "pass", "Expires 20 Aug 2030"),
    (datetime(2026, 12, 1, tzinfo=timezone.utc), "notice", "Expires in 14 days"),
    (datetime(2026, 1, 1, tzinfo=timezone.utc), "fail", "Expired 2026-01-01"),
])
def test_registration_grades(monkeypatch, expires, status, summary):
    monkeypatch.setattr(domain_info, "lookup_registration", lambda domain: (domain, {
        "registrar": "Example Registrar", "created": None, "expires": expires, "status": []}))
    result = _REAL_REGISTRATION("good.test", now=NOW)
    assert (result.status, result.summary) == (status, summary)
    assert "Registrar: Example Registrar" in result.details


def test_registration_walks_up_to_the_registered_domain(monkeypatch):
    asked = []
    monkeypatch.setattr(domain_info, "_rdap", lambda name: asked.append(name) or (
        {"registrar": "R", "created": None, "expires": None, "status": []}
        if name == "example.co.th" else None))
    assert domain_info.lookup_registration("mail.example.co.th")[0] == "example.co.th"
    assert asked == ["mail.example.co.th", "example.co.th"]


@pytest.fixture(scope="module")
def certificate(tmp_path_factory):
    folder = tmp_path_factory.mktemp("cert")
    key, cert = folder / "key.pem", folder / "cert.pem"
    try:
        subprocess.run(
            ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "30",
             "-keyout", str(key), "-out", str(cert), "-subj", "/O=Acme/CN=good.test",
             "-addext", "subjectAltName=DNS:good.test,DNS:www.good.test"],
            check=True, capture_output=True,
        )
    except (OSError, subprocess.CalledProcessError):
        pytest.skip("openssl not available")
    return key, cert


def test_certificate_info(certificate):
    _, cert = certificate
    issuer, not_before, not_after, names = domain_info.certificate_info(
        ssl.PEM_cert_to_DER_cert(cert.read_text()))
    assert issuer == "Acme (good.test)"
    assert names == ["good.test", "www.good.test"]
    assert 29 <= (not_after - not_before).days <= 30


def test_ssl_untrusted_certificate(certificate, monkeypatch):
    key, cert = certificate
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(cert, key)
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen()
    monkeypatch.setattr(domain_info, "HTTPS_PORT", listener.getsockname()[1])

    def serve():
        for _ in range(2):  # the verified try, then the one that reads the certificate
            try:
                conn, _ = listener.accept()
                with context.wrap_socket(conn, server_side=True) as tls:
                    tls.recv(1)
            except (OSError, ssl.SSLError):
                pass

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()

    class Resolver:
        def addresses(self, name):
            return ["127.0.0.1"] if name == "good.test" else []

    try:
        result = _REAL_SSL("good.test", Resolver())
    finally:
        thread.join(3)
        listener.close()
    assert result.status == dns_check.FAIL and result.summary.startswith("Not trusted")
    assert result.records == ["Names: good.test, www.good.test"]
    assert "Issuer: Acme (good.test)" in result.details


def test_ssl_without_website():
    class Resolver:
        def addresses(self, name):
            return []

    assert _REAL_SSL("good.test", Resolver()).status == dns_check.INFO


def test_mta_sts_policy_problems(dns_server, monkeypatch):
    monkeypatch.setattr(domain_info, "fetch_sts_policy",
                        lambda domain: STS_POLICY.replace("*.good.test", "mx.other.test"))
    result = _check(dns_server).result("mta_sts")
    assert result.status == dns_check.FAIL and result.summary == "Policy doesn't cover every MX"
    monkeypatch.setattr(domain_info, "fetch_sts_policy",
                        lambda domain: STS_POLICY.replace("enforce", "testing"))
    assert _check(dns_server).result("mta_sts").summary == "Testing mode only"

    def unreachable(domain):
        raise OSError("connection refused")
    monkeypatch.setattr(domain_info, "fetch_sts_policy", unreachable)
    assert _check(dns_server).result("mta_sts").summary == "Policy file unreachable"


def test_mx_matches():
    assert domain_info.mx_matches("mx1.a.test", ["*.a.test"])
    assert not domain_info.mx_matches("x.mx1.a.test", ["*.a.test"])
    assert domain_info.mx_matches("MX.A.TEST.", ["mx.a.test"])


def test_window_says_a_missing_domain_does_not_exist(window, dns_server, monkeypatch):  # noqa: F811
    monkeypatch.setattr(window.settings, "save", lambda: None)
    w = window.dns_check()
    w.dns_port = dns_server
    w.server = "127.0.0.1"
    w.domain.setText("missing.test")
    w.start()
    _wait(lambda: w.report is not None and w._thread is None)
    assert not w.results.isVisibleTo(w)
    assert w.placeholder.text().startswith("missing.test doesn't exist.")
    assert not w.copy_button.isEnabled()


def test_results_arrive_one_by_one(dns_server):
    seen = []
    report = dns_check.check_domain("good.test", "127.0.0.1", [], "", timeout=1,
                                    port=dns_server, on_result=seen.append)
    assert sorted(r.key for r in seen) == sorted(dns_check.CHECKS)
    assert [r.key for r in report.results] == list(dns_check.CHECKS)


def test_a_crashing_check_becomes_an_error_row(dns_server, monkeypatch):
    import http.client

    def broken(domain):
        raise http.client.IncompleteRead(b"")
    monkeypatch.setattr(domain_info, "fetch_sts_policy", broken)
    assert _check(dns_server).result("mta_sts").summary == "Policy file unreachable"

    def boom(domain, resolver):
        raise RuntimeError("bug")
    monkeypatch.setattr(dns_check, "check_spf", boom)
    spf = _check(dns_server).result("spf")
    assert spf.status == dns_check.ERROR and "RuntimeError: bug" in spf.details[0]


def test_mta_sts_policy_must_be_plain_text(dns_server, monkeypatch):
    def html_page(domain):
        raise ValueError("served as text/html, not text/plain")
    monkeypatch.setattr(domain_info, "fetch_sts_policy", html_page)
    result = _check(dns_server).result("mta_sts")
    assert result.summary == "Policy file is invalid" and "text/html" in result.details[0]


def test_tlsrpt_shows_https_report_urls_whole(monkeypatch):
    resolver = dns_check.Resolver(["127.0.0.1"])
    monkeypatch.setattr(resolver, "txt", lambda name: [
        "v=TLSRPTv1; rua=mailto:tls@a.test,https://reports.a.test/x"])
    assert dns_check.check_tlsrpt("a.test", resolver).summary == (
        "Reports to tls@a.test, https://reports.a.test/x")
