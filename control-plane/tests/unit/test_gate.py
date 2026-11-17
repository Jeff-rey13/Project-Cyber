"""Example-based gate tests: one per deny reason, plus the parse edge cases."""

import pytest

from app.scope import gate
from app.scope.gate import authorize_request, parse_target

from ..property.test_gate_properties import INSIDE, KEY, SNAP, make_snapshot


@pytest.mark.parametrize("method,url,reason", [
    ("GET", "http://evil.com/bookings", "host not verified"),
    ("DELETE", "http://127.0.0.1/bookings", "method not permitted"),
    ("BREW", "http://127.0.0.1/bookings", "method not permitted"),
    ("GET", "http://127.0.0.1/bookings/admin/x", "path on exclusion list"),
    ("GET", "http://127.0.0.1/secret", "path not in allow-list"),
    ("GET", "http://127.0.0.1/bookingsadmin", "path not in allow-list"),
    ("GET", "http://127.0.0.1@evil.com/", "unparseable or unsafe url"),
])
def test_each_deny_reason(method, url, reason):
    d = authorize_request(method, url, SNAP, KEY, now=INSIDE)
    assert not d and d.reason.startswith(reason)


def test_ipv6_hosts():
    snap = make_snapshot(verified_hosts=("::1",))
    assert authorize_request("GET", "http://[::1]/bookings", snap, KEY, now=INSIDE)
    assert authorize_request("GET", "http://[::1]:8080/bookings", snap, KEY, now=INSIDE)
    assert not authorize_request("GET", "http://[::1/bookings", snap, KEY, now=INSIDE)
    assert not authorize_request("GET", "http://[::1]x/bookings", snap, KEY, now=INSIDE)


@pytest.mark.parametrize("url", [
    "", "http://", "http:///bookings", "http://127.0.0.1:0/", "http://127.0.0.1:99999/", "http://127.0.0.1:８０/",
    "http://127.0.0.1/%25252525252e%25252525252e", "http://127.0.0.1/%ff", "http://127.0.0.1/a%00b",
])
def test_parse_rejects(url):
    with pytest.raises(ValueError):
        parse_target(url)


def test_parse_canonicalises():
    t = parse_target("HTTPS://Nimbus.Test.:8443/Bookings/%41BC")
    assert (t.scheme, t.host, t.port, t.path) == ("https", "nimbus.test", 8443, "/Bookings/ABC")
    assert parse_target("http://nimbus.test").path == "/" and parse_target("http://nimbus.test").port == 80


def test_non_snapshot_and_non_string_inputs_deny():
    assert not authorize_request("GET", "http://127.0.0.1/bookings", None, KEY, now=INSIDE)  # type: ignore[arg-type]
    assert not authorize_request(None, "http://127.0.0.1/bookings", SNAP, KEY, now=INSIDE)  # type: ignore[arg-type]
    assert not authorize_request("GET", b"http://127.0.0.1/", SNAP, KEY, now=INSIDE)  # type: ignore[arg-type]


def test_unexpected_exception_is_a_deny(monkeypatch):
    def boom(*a, **k):
        raise RuntimeError("bug")

    monkeypatch.setattr(gate, "_authorize", boom)
    d = authorize_request("GET", "http://127.0.0.1/bookings", SNAP, KEY, now=INSIDE)
    assert not d and d.reason == "gate error: RuntimeError"


def test_default_clock_used_when_now_omitted():
    # real "now" is well outside the 2027 test window
    assert not authorize_request("GET", "http://127.0.0.1/bookings", SNAP, KEY)
