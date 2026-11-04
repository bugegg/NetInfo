"""Parsers and message builders behind the hostname device probes."""

import socket
import ssl
import struct
import subprocess
import threading

import pytest

from pinginfoview.ping import ber, http_title, ntlm, snmp, ssdp, tls_cert


# --- NTLM (SMB / RDP) ---

def _challenge(av_pairs):
    info = b"".join(
        struct.pack("<HH", av_id, len(value.encode("utf-16-le"))) + value.encode("utf-16-le")
        for av_id, value in av_pairs
    ) + b"\0\0\0\0"
    header = (
        b"NTLMSSP\0" + struct.pack("<I", 2) + b"\0" * 8 + struct.pack("<I", 0)
        + b"\0" * 8 + b"\0" * 8 + struct.pack("<HHI", len(info), len(info), 48)
    )
    return header + info


def test_ntlm_prefers_the_dns_computer_name():
    blob = b"spnego junk" + _challenge([(2, "PENSO"), (1, "PENS-SV01"), (3, "PENS-SV01.penso.local")])
    assert ntlm.parse_challenge(blob) == "PENS-SV01.penso.local"


def test_ntlm_falls_back_to_the_netbios_computer_name():
    assert ntlm.parse_challenge(_challenge([(1, "KROTNB")])) == "KROTNB"


def test_ntlm_without_a_challenge_is_empty():
    assert ntlm.parse_challenge(b"\xfeSMB" + b"\0" * 80) == ""


def test_ntlm_negotiate_message_shape():
    message = ntlm.negotiate_message()
    assert message[:8] == b"NTLMSSP\0" and len(message) == 32
    assert struct.unpack_from("<I", message, 8)[0] == 1


def test_x224_request_asks_for_tls_and_nla():
    packet = ntlm._x224_connection_request(3)
    assert packet[:2] == b"\x03\x00" and struct.unpack(">H", packet[2:4])[0] == len(packet)
    assert packet[-8:] == struct.pack("<BBHI", 1, 0, 8, 3)


def test_smb_and_rdp_give_up_quietly(monkeypatch):
    closed = socket.socket()
    closed.bind(("127.0.0.1", 0))
    port = closed.getsockname()[1]
    closed.close()  # nothing listens here now
    monkeypatch.setattr(ntlm, "SMB_PORT", port)
    monkeypatch.setattr(ntlm, "RDP_PORT", port)
    assert ntlm.smb_lookup("127.0.0.1", timeout=0.2) == ""
    assert ntlm.rdp_lookup("127.0.0.1", timeout=0.2) == ""


# --- SNMP ---

def _snmp_response(request_id, value_tag, value, error=0):
    varbind = ber.encode(ber.SEQUENCE, ber.encode(ber.OID, bytes.fromhex("2b06010201010500"))
                         + ber.encode(value_tag, value))
    pdu = ber.encode(0xA2, ber.encode_int(request_id) + ber.encode_int(error) + ber.encode_int(0)
                     + ber.encode(ber.SEQUENCE, varbind))
    return ber.encode(ber.SEQUENCE, ber.encode_int(0) + ber.encode(ber.OCTET_STRING, b"public") + pdu)


def test_snmp_parses_sys_name():
    assert snmp.parse_response(_snmp_response(42, ber.OCTET_STRING, b"iR-ADV C5540"), 42) == "iR-ADV C5540"


def test_snmp_rejects_wrong_id_errors_and_missing_values():
    assert snmp.parse_response(_snmp_response(42, ber.OCTET_STRING, b"x"), 43) == ""
    assert snmp.parse_response(_snmp_response(42, ber.OCTET_STRING, b"x", error=2), 42) == ""
    assert snmp.parse_response(_snmp_response(42, 0x80, b""), 42) == ""  # noSuchObject


def test_snmp_request_round_trips_through_the_ber_walker():
    packet = snmp.build_get(1234)
    _, start, end = ber.read(packet)
    tags = [tag for tag, _, _ in ber.children(packet, start, end)]
    assert tags == [ber.INTEGER, ber.OCTET_STRING, 0xA0]


def test_snmp_lookup_against_a_local_fake_agent(monkeypatch):
    server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server.bind(("127.0.0.1", 0))
    monkeypatch.setattr(snmp, "SNMP_PORT", server.getsockname()[1])

    def answer():
        request, addr = server.recvfrom(1024)
        _, start, end = ber.read(request)
        _, _, (_, pdu_start, pdu_end) = list(ber.children(request, start, end))
        _, id_start, id_end = next(ber.children(request, pdu_start, pdu_end))
        server.sendto(_snmp_response(ber.decode_int(request, id_start, id_end),
                                     ber.OCTET_STRING, b"switch-01"), addr)

    thread = threading.Thread(target=answer, daemon=True)
    thread.start()
    try:
        assert snmp.lookup("127.0.0.1") == "switch-01"
    finally:
        thread.join(2)
        server.close()


# --- TLS certificate ---

@pytest.fixture(scope="module")
def certificate(tmp_path_factory):
    folder = tmp_path_factory.mktemp("cert")
    key, cert = folder / "key.pem", folder / "cert.pem"
    try:
        subprocess.run(
            ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
             "-keyout", str(key), "-out", str(cert), "-subj", "/O=Acme/CN=nas01.home.arpa",
             "-addext", "subjectAltName=DNS:nas01.lan,IP:192.168.1.20"],
            check=True, capture_output=True,
        )
    except (OSError, subprocess.CalledProcessError):
        pytest.skip("openssl not available")
    return key, cert


def test_certificate_names_reads_cn_and_san(certificate):
    _, cert = certificate
    der = ssl.PEM_cert_to_DER_cert(cert.read_text())
    assert tls_cert.certificate_names(der) == ("nas01.home.arpa", ["nas01.lan"])
    assert tls_cert.name_from_certificate(der, "192.168.1.20") == "nas01.lan"


def test_tls_lookup_against_a_local_server(certificate, monkeypatch):
    key, cert = certificate
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(cert, key)
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen()
    monkeypatch.setattr(tls_cert, "TLS_PORTS", (listener.getsockname()[1],))

    def serve():
        conn, _ = listener.accept()
        try:
            with context.wrap_socket(conn, server_side=True):
                pass
        except (OSError, ssl.SSLError):
            pass

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    try:
        assert tls_cert.lookup("127.0.0.1") == "nas01.lan"
    finally:
        thread.join(2)
        listener.close()


@pytest.mark.parametrize("name, ok", [
    ("nas01.lan", True), ("PENS-SV01", True), ("*.example.com", False),
    ("localhost", False), ("192.168.1.20", False), ("Acme Inc", False), ("", False),
])
def test_plausible_host_name(name, ok):
    assert tls_cert.plausible_host_name(name, "192.168.1.20") is ok


# --- HTTP title ---

@pytest.mark.parametrize("body, title", [
    (b"<html><head><title> Canon\n iR-ADV C5540 </title>", "Canon iR-ADV C5540"),
    (b"<TITLE lang=en>Synology &amp; DiskStation</TITLE>", "Synology & DiskStation"),
    (b"<title>Login</title>", ""),
    (b"<title>404 Not Found</title>", ""),
    (b"<title>Welcome to nginx!</title>", ""),
    (b"<p>no title</p>", ""),
])
def test_title_from_html(body, title):
    assert http_title.title_from_html(body) == title


def test_http_lookup_against_a_local_server(monkeypatch):
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen()
    monkeypatch.setattr(http_title, "HTTP_PORTS", ((listener.getsockname()[1], False),))

    def serve():
        conn, _ = listener.accept()
        with conn:
            conn.recv(4096)
            conn.sendall(b"HTTP/1.0 200 OK\r\n\r\n<title>Camera-Lobby</title>")

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    try:
        assert http_title.lookup("127.0.0.1") == "Camera-Lobby"
    finally:
        thread.join(2)
        listener.close()


# --- SSDP / UPnP ---

def test_friendly_name_from_device_description():
    xml = "<root><device><friendlyName>\n Samsung Q60BA 65 TV &amp; more</friendlyName></device></root>"
    assert ssdp.friendly_name(xml) == "Samsung Q60BA 65 TV & more"


def test_ssdp_only_fetches_descriptions_from_the_device_itself(monkeypatch):
    fetched = []
    monkeypatch.setattr(ssdp, "discovered", lambda: {
        "192.168.1.30": ["http://10.9.9.9/desc.xml", "https://192.168.1.30/d.xml",
                         "http://192.168.1.30:49152/desc.xml"],
    })
    monkeypatch.setattr(ssdp, "_fetch_description",
                        lambda url: fetched.append(url) or "<friendlyName>TV</friendlyName>")
    assert ssdp.lookup("192.168.1.30") == "TV"
    assert fetched == ["http://192.168.1.30:49152/desc.xml"]
