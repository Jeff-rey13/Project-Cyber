"""The guarded client must never let a denied request reach the wire."""

import hashlib
import hmac
from datetime import datetime, timedelta, timezone

import httpx
import pytest

from app.orchestrator.guarded_client import GateStats, ScopeViolation, guarded_client
from app.scope.snapshot import ScopeSnapshot

KEY = b"integration-key-0123456789"
T0 = datetime(2027, 1, 1, tzinfo=timezone.utc)


def sealed(**kw):
    base = dict(
        job_id="job-int",
        verified_hosts=("127.0.0.1",),
        allow_paths=("/",),
        deny_paths=("/admin",),
        window_start=T0,
        window_end=T0 + timedelta(hours=1),
        forbidden_methods=frozenset({"DELETE"}),
        proof_ref=(1,),
        captured_at=T0,
    )
    base.update(kw)
    s = ScopeSnapshot(**base)
    return s.model_copy(update={"seal": hmac.new(KEY, s.canonical_bytes(), hashlib.sha256).hexdigest()})


class Wire:
    """Mock transport that records what actually got 'sent'."""

    def __init__(self, handler=None):
        self.sent: list[httpx.Request] = []
        self._handler = handler or (lambda r: httpx.Response(200, text="ok"))

    def transport(self):
        def h(request):
            self.sent.append(request)
            return self._handler(request)
        return httpx.MockTransport(h)


def client_for(wire, snap=None, **kw):
    return guarded_client(snap or sealed(), KEY, inner_transport=wire.transport(), clock=lambda: T0 + timedelta(minutes=5), **kw)


def test_in_scope_request_goes_through():
    wire = Wire()
    with client_for(wire) as c:
        assert c.get("http://127.0.0.1/bookings/ABC123").status_code == 200
    assert len(wire.sent) == 1


@pytest.mark.parametrize("method,url", [
    ("GET", "http://evil.com/"),
    ("GET", "http://127.0.0.1/admin/users"),
    ("DELETE", "http://127.0.0.1/bookings/ABC123"),
    ("GET", "http://127.0.0.1/bookings/%2e%2e/admin"),
    ("GET", "http://169.254.169.254/latest/meta-data/"),
])
def test_denied_requests_never_hit_the_wire(method, url):
    wire = Wire()
    stats = GateStats()
    with client_for(wire, stats=stats) as c:
        with pytest.raises(ScopeViolation) as exc:
            c.request(method, url)
    assert wire.sent == []
    assert stats.denied == 1 and stats.allowed == 0
    assert not exc.value.decision.allowed


def test_redirect_off_scope_is_blocked_mid_chain():
    def handler(req):
        if req.url.host == "127.0.0.1":
            return httpx.Response(302, headers={"location": "http://evil.com/steal"})
        return httpx.Response(200)

    wire = Wire(handler)
    with client_for(wire, follow_redirects=True) as c:
        with pytest.raises(ScopeViolation):
            c.get("http://127.0.0.1/bookings")
    assert [str(r.url) for r in wire.sent] == ["http://127.0.0.1/bookings"]


def test_redirects_off_by_default():
    wire = Wire(lambda r: httpx.Response(302, headers={"location": "http://127.0.0.1/other"}))
    with client_for(wire) as c:
        assert c.get("http://127.0.0.1/a").status_code == 302
    assert len(wire.sent) == 1


def test_build_request_path_is_also_gated():
    wire = Wire()
    with client_for(wire) as c:
        req = c.build_request("GET", "http://evil.com/")
        with pytest.raises(ScopeViolation):
            c.send(req)
    assert wire.sent == []


def test_env_proxy_ignored(monkeypatch):
    monkeypatch.setenv("HTTP_PROXY", "http://evil-proxy:8080")
    monkeypatch.setenv("HTTPS_PROXY", "http://evil-proxy:8080")
    wire = Wire()
    with client_for(wire) as c:
        c.get("http://127.0.0.1/x")
    assert wire.sent[0].url.host == "127.0.0.1"


def test_unsealed_snapshot_refused_at_construction():
    bad = sealed().model_copy(update={"seal": "0" * 64})
    with pytest.raises(ValueError):
        guarded_client(bad, KEY, inner_transport=Wire().transport())


def test_outside_window_blocked():
    wire = Wire()
    c = guarded_client(sealed(), KEY, inner_transport=wire.transport(), clock=lambda: T0 + timedelta(hours=2))
    with pytest.raises(ScopeViolation):
        c.get("http://127.0.0.1/")
    assert wire.sent == []


def test_decision_hook_sees_everything_and_stats_bucket_reasons():
    wire = Wire()
    seen = []
    stats = GateStats()
    with client_for(wire, stats=stats, on_decision=lambda d, r: seen.append((d.allowed, str(r.url)))) as c:
        c.get("http://127.0.0.1/ok")
        for url in ("http://evil.com/", "http://evil2.com/", "ftp://127.0.0.1/"):
            with pytest.raises(ScopeViolation):
                c.get(url) if not url.startswith("ftp") else c.send(httpx.Request("GET", url))
    assert seen[0] == (True, "http://127.0.0.1/ok") and len(seen) == 4
    d = stats.as_dict()
    assert d["allowed"] == 1 and d["denied"] == 3
    assert d["deny_reasons"]["host not verified"] == 2


def test_violation_is_a_request_error():
    # engines already catch RequestError for flaky targets; a block must not crash them differently
    assert issubclass(ScopeViolation, httpx.RequestError)
