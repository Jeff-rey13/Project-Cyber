import pytest

from app.scope.domains import InvalidDomain, canonical_domain, is_loopback


@pytest.mark.parametrize(
    "raw,expected",
    [
        ("nimbus.test", "nimbus.test"),
        ("NIMBUS.Test", "nimbus.test"),
        ("nimbus.test.", "nimbus.test"),
        ("bücher.example", "xn--bcher-kva.example"),
        ("xn--bcher-kva.example", "xn--bcher-kva.example"),
        ("127.0.0.1", "127.0.0.1"),
        ("[::1]", "::1"),
        ("[0:0:0:0:0:0:0:1]", "::1"),
        ("::1", "::1"),
        ("localhost", "localhost"),
    ],
)
def test_canonicalises(raw, expected):
    assert canonical_domain(raw) == expected


@pytest.mark.parametrize(
    "raw",
    [
        "", " ", " nimbus.test", "nimbus.test ", "nimbus.test:443", "http://nimbus.test", "nimbus.test/path",
        "user@nimbus.test", "nimbus..test", "-nimbus.test", "nimbus-.test", "nimbus_test.com",
        "2130706433.0", "0x7f.1", "127.1", "a" * 64 + ".test", "[not-ip]", "nimbus.test%00", "nim\tbus.test",
        "evil.com\\@nimbus.test", "nimbus.test#frag", "nimbus.test?q",
    ],
)
def test_rejects(raw):
    with pytest.raises(InvalidDomain):
        canonical_domain(raw)


def test_rejects_non_string():
    with pytest.raises(InvalidDomain):
        canonical_domain(None)  # type: ignore[arg-type]


@pytest.mark.parametrize("host,expected", [
    ("127.0.0.1", True), ("127.8.9.10", True), ("::1", True), ("localhost", True),
    ("10.0.0.1", False), ("nimbus.test", False), ("localhost.evil.com", False), ("0.0.0.0", False),
])
def test_loopback(host, expected):
    assert is_loopback(host) is expected
