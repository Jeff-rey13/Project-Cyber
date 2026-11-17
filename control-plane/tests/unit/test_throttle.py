"""Throttle maths on a simulated clock, so the tests are exact and instant."""

import httpx
import pytest

from app.orchestrator.throttle import (
    HARD_MAX_CONCURRENCY,
    HARD_MAX_RPS,
    HARD_MIN_RPS,
    AdaptiveThrottle,
    ThrottleAbort,
    ThrottleConfig,
    ThrottleTransport,
)


class FakeTime:
    def __init__(self):
        self.t = 0.0

    def clock(self):
        return self.t

    def sleep(self, s):
        self.t += s


def throttle(**cfg):
    ft = FakeTime()
    return AdaptiveThrottle(ThrottleConfig(**cfg), clock=ft.clock, sleep=ft.sleep), ft


def feed(t, n, latency, error=False):
    for _ in range(n):
        t.record(latency, error)


def test_config_is_clamped_to_hard_ceilings():
    c = ThrottleConfig(initial_rps=1000, max_rps=1000, min_rps=-5, concurrency=99, window=0, ramp_after=0, abort_after=0).clamped()
    assert c.max_rps == HARD_MAX_RPS and c.initial_rps == HARD_MAX_RPS and c.min_rps == HARD_MIN_RPS
    assert c.concurrency == HARD_MAX_CONCURRENCY and c.window == 1 and c.ramp_after == 1 and c.abort_after == 1


def test_pacing_matches_rate():
    t, ft = throttle(initial_rps=4, max_rps=4)
    for _ in range(9):
        t.acquire()
    # first request is free, then one every 0.25s
    assert ft.t == pytest.approx(2.0)


def test_backs_off_hard_on_latency():
    t, _ = throttle(initial_rps=8, min_rps=0.5, window=5, latency_max_s=0.5)
    feed(t, 5, latency=2.0)
    assert t.rate == 4.0
    feed(t, 5, latency=2.0)
    assert t.rate == 2.0
    assert [h.healthy for h in t.history] == [False, False]


def test_backs_off_on_errors():
    t, _ = throttle(initial_rps=8, window=10, error_rate_max=0.2)
    feed(t, 7, 0.01)
    feed(t, 3, 0.01, error=True)
    assert t.rate == 4.0 and t.history[-1].error_rate == 0.3


def test_never_below_floor():
    t, _ = throttle(initial_rps=1, min_rps=0.5, window=1, abort_after=100)
    feed(t, 20, latency=9)
    assert t.rate == 0.5


def test_ramps_gently_after_sustained_health():
    t, _ = throttle(initial_rps=5, max_rps=10, window=2, ramp_after=3)
    feed(t, 4, 0.01)
    assert t.rate == 5
    feed(t, 2, 0.01)
    assert t.rate == pytest.approx(6.0)
    feed(t, 100, 0.01)
    assert t.rate == 10


def test_unhealthy_window_resets_healthy_streak():
    t, _ = throttle(initial_rps=5, window=1, ramp_after=3, latency_max_s=1)
    feed(t, 2, 0.01)
    feed(t, 1, 5)
    feed(t, 2, 0.01)
    assert t.rate == 2.5


def test_sustained_stress_aborts_and_blocks_further_sends():
    t, _ = throttle(window=2, abort_after=3, latency_max_s=0.1)
    feed(t, 4, 1.0)
    assert t.abort_reason is None
    feed(t, 2, 1.0)
    assert "unhealthy for 3 windows" in t.abort_reason
    with pytest.raises(ThrottleAbort):
        t.acquire()
    snap = t.snapshot()
    assert snap["aborted"] and len(snap["history"]) == 3


def test_recovery_between_bad_windows_does_not_abort():
    t, _ = throttle(window=1, abort_after=3, latency_max_s=0.1)
    for _ in range(10):
        feed(t, 2, 1.0)
        feed(t, 1, 0.01)
    assert t.abort_reason is None


def test_transport_records_status_and_timeouts():
    t, _ = throttle(window=1, initial_rps=20, max_rps=20, abort_after=100)
    codes = iter([200, 503, 429])

    def h(req):
        return httpx.Response(next(codes))

    tr = ThrottleTransport(httpx.MockTransport(h), t)
    for _ in range(3):
        tr.handle_request(httpx.Request("GET", "http://x/"))
    assert [w.error_rate for w in t.history] == [0.0, 1.0, 1.0]

    def slow(req):
        raise httpx.ReadTimeout("slow", request=req)

    tr = ThrottleTransport(httpx.MockTransport(slow), t)
    with pytest.raises(httpx.ReadTimeout):
        tr.handle_request(httpx.Request("GET", "http://x/"))
    assert t.history[-1].error_rate == 1.0
    tr.close()


def test_abort_is_a_request_error():
    assert issubclass(ThrottleAbort, httpx.RequestError)
