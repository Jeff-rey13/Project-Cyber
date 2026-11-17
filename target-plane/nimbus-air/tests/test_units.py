import pytest

from app import tokens
from app.ratelimit import FixedWindowLimiter


def test_token_roundtrip():
    t = tokens.issue(7, "s", 60)
    assert tokens.decode(t, "s")["sub"] == 7


def test_token_tamper_detected():
    t = tokens.issue(7, "s", 60)
    body, sig = t.split(".")
    forged_body = tokens._b64(b'{"sub":1,"exp":9999999999}')
    with pytest.raises(tokens.TokenError):
        tokens.decode(f"{forged_body}.{sig}", "s")


def test_token_expiry():
    t = tokens.issue(7, "s", 10, now=1000)
    assert tokens.decode(t, "s", now=1005)["sub"] == 7
    with pytest.raises(tokens.TokenError):
        tokens.decode(t, "s", now=1011)


@pytest.mark.parametrize("junk", ["", "abc", "a.b", "!!!.sig", tokens._b64(b'{"sub":"x"}') + ".sig"])
def test_token_junk(junk):
    with pytest.raises(tokens.TokenError):
        tokens.decode(junk, "s")


def test_limiter_window_resets():
    now = [0.0]
    lim = FixedWindowLimiter(2, 10, clock=lambda: now[0])
    assert [lim.allow("k") for _ in range(3)] == [True, True, False]
    assert lim.allow("other")
    now[0] = 10.0
    assert lim.allow("k")
