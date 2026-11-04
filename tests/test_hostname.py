import socket
import subprocess

import pytest

from pinginfoview.ping import hostname
from pinginfoview.ping.hostname import resolve

DSCACHEUTIL_OUTPUT = (
    "name: device.local\n"
    "name: device.lan\n"
    "ip_address: 192.168.1.50\n"
)


@pytest.fixture(autouse=True)
def no_device_queries(monkeypatch):
    """Keep the device probes off the network; tests opt back in."""
    monkeypatch.setattr(hostname, "DEVICE_PROBES", ())


def _fake_run(returncode_stdout):
    def run(*args, **kwargs):
        return subprocess.CompletedProcess(args, 0, stdout=returncode_stdout, stderr="")
    return run


def test_empty_ip_short_circuits_without_calling_anything(monkeypatch):
    def fail(*a, **k):
        raise AssertionError("should not be called for an empty ip")
    monkeypatch.setattr(subprocess, "run", fail)
    monkeypatch.setattr(socket, "gethostbyaddr", fail)
    assert resolve("") == ""


def test_dscacheutil_hit_is_used_and_dns_fallback_not_called(monkeypatch):
    monkeypatch.setattr(subprocess, "run", _fake_run(DSCACHEUTIL_OUTPUT))

    def fail(*a, **k):
        raise AssertionError("gethostbyaddr should not run when dscacheutil answers")
    monkeypatch.setattr(socket, "gethostbyaddr", fail)

    assert resolve("192.168.1.50") == "device.local"


def test_falls_back_to_reverse_dns_when_dscacheutil_is_empty(monkeypatch):
    monkeypatch.setattr(subprocess, "run", _fake_run(""))
    monkeypatch.setattr(
        socket, "gethostbyaddr", lambda ip: ("dns.google", [], [ip])
    )
    assert resolve("8.8.8.8") == "dns.google"


def test_empty_string_when_neither_source_answers(monkeypatch):
    monkeypatch.setattr(subprocess, "run", _fake_run(""))

    def raise_herror(ip):
        raise socket.herror("unknown host")
    monkeypatch.setattr(socket, "gethostbyaddr", raise_herror)
    assert resolve("203.0.113.5") == ""


def test_subprocess_failure_falls_through_to_dns(monkeypatch):
    def raise_oserror(*a, **k):
        raise OSError("dscacheutil missing")
    monkeypatch.setattr(subprocess, "run", raise_oserror)
    monkeypatch.setattr(socket, "gethostbyaddr", lambda ip: ("fallback.name", [], [ip]))
    assert resolve("10.0.0.1") == "fallback.name"


def test_trailing_dot_from_reverse_dns_is_stripped(monkeypatch):
    """gethostbyaddr often returns an FQDN with a trailing root dot."""
    monkeypatch.setattr(subprocess, "run", _fake_run(""))
    monkeypatch.setattr(
        socket, "gethostbyaddr", lambda ip: ("dns.google.", [], [ip])
    )
    assert resolve("8.8.8.8") == "dns.google"



def _no_system_answer(monkeypatch):
    monkeypatch.setattr(subprocess, "run", _fake_run(""))

    def raise_herror(ip):
        raise socket.herror("unknown host")
    monkeypatch.setattr(socket, "gethostbyaddr", raise_herror)


def test_asks_the_device_when_the_system_resolver_has_nothing(monkeypatch):
    _no_system_answer(monkeypatch)
    monkeypatch.setattr(hostname, "DEVICE_PROBES", (lambda ip: "", lambda ip: "macbook.local."))
    assert resolve("172.16.10.25") == "macbook.local"


def test_earlier_probe_wins_even_when_it_answers_last(monkeypatch):
    import time

    _no_system_answer(monkeypatch)

    def slow_but_trusted(ip):
        time.sleep(0.2)
        return "PENS-SV01.penso.local"

    monkeypatch.setattr(hostname, "DEVICE_PROBES", (slow_but_trusted, lambda ip: "Model 123"))
    assert resolve("172.16.10.1") == "PENS-SV01.penso.local"


def test_placeholders_and_failing_probes_are_skipped(monkeypatch):
    _no_system_answer(monkeypatch)

    def broken(ip):
        raise RuntimeError("boom")

    monkeypatch.setattr(hostname, "DEVICE_PROBES", (
        lambda ip: "localhost.local", lambda ip: "-", broken, lambda ip: "Samsung Q60BA 65 TV",
    ))
    assert resolve("172.16.10.167") == "Samsung Q60BA 65 TV"


def test_public_addresses_are_never_probed(monkeypatch):
    _no_system_answer(monkeypatch)

    def fail(ip):
        raise AssertionError("a public address must not be probed")

    monkeypatch.setattr(hostname, "DEVICE_PROBES", (fail,))
    assert resolve("8.8.8.8") == ""
