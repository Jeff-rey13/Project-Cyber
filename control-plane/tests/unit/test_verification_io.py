"""The real dns/http lookups, with the network stubbed out."""

import dns.resolver
import httpx

from app.scope import verification


class _Rec:
    def __init__(self, *parts):
        self.strings = [p.encode() for p in parts]


def test_dns_txt_joins_split_strings(monkeypatch):
    seen = {}

    def fake_resolve(name, rtype, lifetime):
        seen["q"] = (name, rtype)
        return [_Rec("abc", "def"), _Rec("xyz")]

    monkeypatch.setattr(dns.resolver, "resolve", fake_resolve)
    assert verification.dns_txt_lookup("_aeroscan-challenge.nimbus.test") == ["abcdef", "xyz"]
    assert seen["q"] == ("_aeroscan-challenge.nimbus.test", "TXT")


def test_dns_failure_is_empty(monkeypatch):
    def boom(*a, **k):
        raise dns.resolver.NXDOMAIN()

    monkeypatch.setattr(dns.resolver, "resolve", boom)
    assert verification.dns_txt_lookup("nope.test") == []


def test_http_fetch_ok_and_truncated(monkeypatch):
    calls = {}

    def fake_get(url, timeout, follow_redirects):
        calls["redirects"] = follow_redirects
        return httpx.Response(200, text="t" * 1000)

    monkeypatch.setattr(httpx, "get", fake_get)
    assert verification.http_file_fetch("http://x.test/.well-known/aeroscan-challenge.txt") == "t" * 256
    assert calls["redirects"] is False


def test_http_fetch_non_200_and_error(monkeypatch):
    monkeypatch.setattr(httpx, "get", lambda *a, **k: httpx.Response(302, headers={"location": "http://evil"}))
    assert verification.http_file_fetch("http://x.test/") is None

    def boom(*a, **k):
        raise httpx.ConnectError("down")

    monkeypatch.setattr(httpx, "get", boom)
    assert verification.http_file_fetch("http://x.test/") is None


