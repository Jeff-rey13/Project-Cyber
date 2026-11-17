"""The only http client engines are given (PRD 4.2).

The gate sits in the transport, not in a wrapper around .get()/.post(), so
it sees every request httpx actually sends, including redirect hops and
anything built with client.build_request(). Env proxies are ignored so
HTTP(S)_PROXY can't quietly route traffic somewhere else.
"""

import threading
from collections import Counter
from collections.abc import Callable
from datetime import datetime
from typing import Optional

import httpx

from ..scope.gate import Decision, authorize_request
from ..scope.snapshot import ScopeSnapshot
from .throttle import AdaptiveThrottle, ThrottleTransport


class ScopeViolation(httpx.RequestError):
    """Raised instead of sending. Subclasses RequestError so engines handle it like any failed request."""

    def __init__(self, decision: Decision, request: httpx.Request):
        super().__init__(f"blocked by scope gate: {decision.reason}", request=request)
        self.decision = decision


class GateStats:
    """Thread-safe allow/deny tally; feeds the dashboard's gate-denials panel later."""

    def __init__(self):
        self._lock = threading.Lock()
        self.allowed = 0
        self.denied = 0
        self.deny_reasons: Counter[str] = Counter()

    def record(self, decision: Decision) -> None:
        with self._lock:
            if decision.allowed:
                self.allowed += 1
            else:
                self.denied += 1
                # strip the exception detail so reasons bucket nicely
                self.deny_reasons[decision.reason.split(":")[0]] += 1

    def as_dict(self) -> dict:
        with self._lock:
            return {"allowed": self.allowed, "denied": self.denied, "deny_reasons": dict(self.deny_reasons)}


DecisionHook = Callable[[Decision, httpx.Request], None]


class GateTransport(httpx.BaseTransport):
    def __init__(
        self,
        inner: httpx.BaseTransport,
        snapshot: ScopeSnapshot,
        key: bytes,
        stats: GateStats,
        on_decision: Optional[DecisionHook] = None,
        clock: Optional[Callable[[], datetime]] = None,
    ):
        self._inner = inner
        self._snapshot = snapshot
        self._key = key
        self._stats = stats
        self._on_decision = on_decision
        self._clock = clock

    def handle_request(self, request: httpx.Request) -> httpx.Response:
        now = self._clock() if self._clock else None
        decision = authorize_request(request.method, str(request.url), self._snapshot, self._key, now=now)
        self._stats.record(decision)
        if self._on_decision:
            self._on_decision(decision, request)
        if not decision.allowed:
            raise ScopeViolation(decision, request)
        return self._inner.handle_request(request)

    def close(self) -> None:
        self._inner.close()


def guarded_client(
    snapshot: ScopeSnapshot,
    key: bytes,
    *,
    stats: Optional[GateStats] = None,
    on_decision: Optional[DecisionHook] = None,
    inner_transport: Optional[httpx.BaseTransport] = None,
    clock: Optional[Callable[[], datetime]] = None,
    timeout: float = 10.0,
    follow_redirects: bool = False,
    throttle: Optional[AdaptiveThrottle] = None,
) -> httpx.Client:
    # refuse up front rather than build a client that will deny every request anyway
    if not snapshot.is_sealed_with(key):
        raise ValueError("refusing to build a client from an unsealed scope snapshot")
    # gate -> throttle -> wire. the throttle is not optional; callers can only pick a gentler one.
    paced = ThrottleTransport(inner_transport or httpx.HTTPTransport(retries=0), throttle or AdaptiveThrottle())
    transport = GateTransport(
        paced,
        snapshot,
        key,
        stats or GateStats(),
        on_decision,
        clock,
    )
    return httpx.Client(
        transport=transport,
        trust_env=False,
        follow_redirects=follow_redirects,
        timeout=timeout,
        headers={"User-Agent": "AeroScan/1.0 (authorized security test)"},
    )
