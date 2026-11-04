"""Tests for the `python -m NetInfoView` entry point's startup helpers."""

import pytest

resource = pytest.importorskip("resource")  # POSIX only; Windows has no fd limit to raise

from NetInfoView.__main__ import FILE_DESCRIPTOR_LIMIT, _raise_file_descriptor_limit


def test_raises_the_soft_limit_toward_the_target(monkeypatch):
    monkeypatch.setattr(resource, "getrlimit", lambda which: (256, 999999))
    calls = []
    monkeypatch.setattr(
        resource, "setrlimit", lambda which, limits: calls.append(limits)
    )

    _raise_file_descriptor_limit()

    assert calls == [(FILE_DESCRIPTOR_LIMIT, 999999)]


def test_never_lowers_an_already_higher_soft_limit(monkeypatch):
    monkeypatch.setattr(resource, "getrlimit", lambda which: (999999, 999999))
    calls = []
    monkeypatch.setattr(
        resource, "setrlimit", lambda which, limits: calls.append(limits)
    )

    _raise_file_descriptor_limit()

    assert calls == []


def test_is_capped_by_an_effectively_unlimited_hard_limit(monkeypatch):
    """hard == RLIM_INFINITY (a huge sentinel) must not make the target
    huge too — it should still cap at FILE_DESCRIPTOR_LIMIT."""
    monkeypatch.setattr(
        resource, "getrlimit", lambda which: (256, resource.RLIM_INFINITY)
    )
    calls = []
    monkeypatch.setattr(
        resource, "setrlimit", lambda which, limits: calls.append(limits)
    )

    _raise_file_descriptor_limit()

    assert calls == [(FILE_DESCRIPTOR_LIMIT, resource.RLIM_INFINITY)]


def test_is_capped_by_a_low_hard_limit(monkeypatch):
    monkeypatch.setattr(resource, "getrlimit", lambda which: (64, 512))
    calls = []
    monkeypatch.setattr(
        resource, "setrlimit", lambda which, limits: calls.append(limits)
    )

    _raise_file_descriptor_limit()

    assert calls == [(512, 512)]


def test_a_setrlimit_failure_is_swallowed_rather_than_raised(monkeypatch):
    monkeypatch.setattr(resource, "getrlimit", lambda which: (256, 999999))

    def fail(which, limits):
        raise OSError("not permitted")

    monkeypatch.setattr(resource, "setrlimit", fail)

    _raise_file_descriptor_limit()  # must not raise
