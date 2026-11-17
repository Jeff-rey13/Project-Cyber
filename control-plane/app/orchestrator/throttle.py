"""Adaptive do-no-harm throttle (PRD 5.5).

Token bucket whose refill rate reacts to the target's health. Evaluated over
fixed-size windows of responses rather than wall-clock intervals so behaviour
is the same on a fast laptop and a slow ci box.

  unhealthy window (avg latency > L_MAX or error rate > E_MAX): rate halves
  N healthy windows in a row:                                  rate x1.2
  K unhealthy windows in a row:                                scan aborts

The ceilings below are module constants on purpose. Callers can ask for less,
never for more.
"""

import threading
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Optional

import httpx

HARD_MAX_RPS = 20.0
HARD_MAX_CONCURRENCY = 4
HARD_MIN_RPS = 0.2


class ThrottleAbort(httpx.RequestError):
    """Target looks stressed; stop sending. Subclasses RequestError so engines unwind normally."""


@dataclass
class ThrottleConfig:
    initial_rps: float = 5.0
    min_rps: float = 0.5
    max_rps: float = 10.0
    window: int = 10               # responses per evaluation window
    latency_max_s: float = 1.5     # L_MAX
    error_rate_max: float = 0.2    # E_MAX
    ramp_after: int = 3            # N healthy windows before speeding up
    abort_after: int = 5           # K unhealthy windows in a row
    concurrency: int = 2

    def clamped(self) -> "ThrottleConfig":
        mx = min(max(self.max_rps, HARD_MIN_RPS), HARD_MAX_RPS)
        mn = min(max(self.min_rps, HARD_MIN_RPS), mx)
        return ThrottleConfig(
            initial_rps=min(max(self.initial_rps, mn), mx), min_rps=mn, max_rps=mx,
            window=max(self.window, 1), latency_max_s=self.latency_max_s, error_rate_max=self.error_rate_max,
            ramp_after=max(self.ramp_after, 1), abort_after=max(self.abort_after, 1),
            concurrency=min(max(self.concurrency, 1), HARD_MAX_CONCURRENCY),
        )


@dataclass
class WindowStat:
    at: float
    rate: float
    avg_latency: float
    error_rate: float
    healthy: bool


@dataclass
class AdaptiveThrottle:
    config: ThrottleConfig = field(default_factory=ThrottleConfig)
    clock: Callable[[], float] = time.monotonic
    sleep: Callable[[float], None] = time.sleep

    def __post_init__(self):
        self.config = self.config.clamped()
        self.rate = self.config.initial_rps
        self._tokens = 1.0
        self._last = self.clock()
        self._lock = threading.Lock()
        self._slots = threading.BoundedSemaphore(self.config.concurrency)
        self._samples: list[tuple[float, bool]] = []
        self._healthy_streak = 0
        self._unhealthy_streak = 0
        self.history: list[WindowStat] = []
        self.sent_at: list[float] = []
        self.abort_reason: Optional[str] = None

    # --- sending side ---

    def acquire(self) -> None:
        while True:
            with self._lock:
                if self.abort_reason:
                    raise ThrottleAbort(self.abort_reason)
                now = self.clock()
                # bucket capacity of one token: no bursts, steady pacing at `rate`
                self._tokens = min(1.0, self._tokens + (now - self._last) * self.rate)
                self._last = now
                if self._tokens >= 1.0:
                    self._tokens -= 1.0
                    self.sent_at.append(now)
                    return
                wait = (1.0 - self._tokens) / self.rate
            self.sleep(wait)

    # --- feedback side ---

    def record(self, latency_s: float, error: bool) -> None:
        with self._lock:
            self._samples.append((latency_s, error))
            if len(self._samples) < self.config.window:
                return
            samples, self._samples = self._samples, []
            avg = sum(s[0] for s in samples) / len(samples)
            err = sum(1 for s in samples if s[1]) / len(samples)
            healthy = avg <= self.config.latency_max_s and err <= self.config.error_rate_max
            if healthy:
                self._unhealthy_streak = 0
                self._healthy_streak += 1
                if self._healthy_streak >= self.config.ramp_after:
                    self.rate = min(self.config.max_rps, self.rate * 1.2)
                    self._healthy_streak = 0
            else:
                self._healthy_streak = 0
                self._unhealthy_streak += 1
                self.rate = max(self.config.min_rps, self.rate * 0.5)
                if self._unhealthy_streak >= self.config.abort_after:
                    self.abort_reason = (f"target unhealthy for {self._unhealthy_streak} windows "
                                         f"(avg latency {avg:.2f}s, error rate {err:.0%}); stopping to avoid harm")
            self.history.append(WindowStat(self.clock(), round(self.rate, 3), round(avg, 4), round(err, 3), healthy))

    def snapshot(self) -> dict:
        with self._lock:
            return {
                "rate": round(self.rate, 3),
                "aborted": self.abort_reason,
                "requests": len(self.sent_at),
                "history": [vars(h) for h in self.history],
            }


class ThrottleTransport(httpx.BaseTransport):
    """Paces and measures real sends. Sits *after* the gate so denied requests cost nothing."""

    def __init__(self, inner: httpx.BaseTransport, throttle: AdaptiveThrottle):
        self._inner = inner
        self.throttle = throttle

    def handle_request(self, request: httpx.Request) -> httpx.Response:
        self.throttle.acquire()
        with self.throttle._slots:
            start = time.perf_counter()
            try:
                response = self._inner.handle_request(request)
            except httpx.TimeoutException:
                self.throttle.record(time.perf_counter() - start, error=True)
                raise
            # read the body inside the timing so slow streaming responses count as slow
            response.read()
            self.throttle.record(time.perf_counter() - start, error=response.status_code >= 500 or response.status_code == 429)
            return response

    def close(self) -> None:
        self._inner.close()
