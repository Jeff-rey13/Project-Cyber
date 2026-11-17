"""api_checks edge cases against a scripted target."""

import hashlib
import hmac
from datetime import datetime, timedelta, timezone

import httpx

from app.engines.api_checks import BURST, ApiChecksEngine, _sensitive_keys
from app.engines.base import ScanContext
from app.orchestrator.guarded_client import guarded_client
from app.orchestrator.throttle import AdaptiveThrottle, ThrottleConfig
from app.scope.snapshot import ScopeSnapshot

KEY = b"apichecks-key-0123456789"
NOW = datetime.now(timezone.utc)
BASE = "http://127.0.0.1"
IDS = [{"label": "a", "token": "tA", "objects": ["P1"], "markers": ["Alice"]}]


def sealed():
    s = ScopeSnapshot(job_id="x", verified_hosts=("127.0.0.1",), allow_paths=("/",), deny_paths=(),
                      window_start=NOW - timedelta(minutes=1), window_end=NOW + timedelta(hours=1),
                      forbidden_methods=frozenset({"DELETE"}), proof_ref=(1,), captured_at=NOW)
    return s.model_copy(update={"seal": hmac.new(KEY, s.canonical_bytes(), hashlib.sha256).hexdigest()})


def client(handler):
    fast = AdaptiveThrottle(ThrottleConfig(initial_rps=20, max_rps=20))
    return guarded_client(sealed(), KEY, inner_transport=httpx.MockTransport(handler), throttle=fast)


def test_sensitive_key_walk():
    assert _sensitive_keys({"a": {"passport_no": 1}, "b": [{"card_masked": 1}], "ok": 1}) == ["a.passport_no", "b.card_masked"]


def test_no_openapi_no_identities_only_hygiene():
    def h(req):
        return httpx.Response(404) if "api" in req.url.path or "swagger" in req.url.path else \
            httpx.Response(200, headers={"x-content-type-options": "nosniff", "cache-control": "no-store"})

    with client(h) as c:
        assert ApiChecksEngine().run(c, sealed(), ScanContext(job_id="j", base_url=BASE)) == []


def test_rate_limit_headers_count_as_limited():
    calls = []

    def h(req):
        calls.append(req.url.path)
        return httpx.Response(200, json={}, headers={"X-RateLimit-Remaining": "10"})

    with client(h) as c:
        assert ApiChecksEngine().check_rate_limit(c, BASE + "/o/P1", "/o/{id}", {}) == []
    assert len(calls) == 1


def test_rate_limit_finding_after_full_burst():
    n = []

    def h(req):
        n.append(1)
        return httpx.Response(200, json={})

    with client(h) as c:
        (f,) = ApiChecksEngine().check_rate_limit(c, BASE + "/o/P1", "/o/{id}", {})
    assert len(n) == BURST and f.vuln_class == "missing_rate_limit"


def test_mass_assignment_skipped_when_profile_unreadable_or_field_sticks_not():
    with client(lambda r: httpx.Response(401)) as c:
        assert ApiChecksEngine().check_mass_assignment(c, BASE, {}) == []

    def h(req):
        return httpx.Response(200, json={"role": "customer"})

    with client(h) as c:
        assert ApiChecksEngine().check_mass_assignment(c, BASE, {}) == []


def test_login_paths():
    eng = ApiChecksEngine()
    from app.engines.authz_engine import Identity

    with client(lambda r: httpx.Response(200, text="nope")) as c:
        assert eng._token(c, BASE, Identity("a", ["x"], ["m"], email="e", password="p")) is None
        assert eng._token(c, BASE, Identity("a", ["x"], ["m"])) is None
        assert eng._token(c, BASE, Identity("a", ["x"], ["m"], token="t")) == "t"


def test_identity_without_working_login_stops_after_hygiene():
    def h(req):
        if req.url.path == "/openapi.json":
            return httpx.Response(200, json={"paths": {"/o/{id}": {"get": {}}}})
        return httpx.Response(401)

    ids = [{"label": "a", "email": "e", "password": "p", "objects": ["P1"], "markers": ["m"]}]
    with client(h) as c:
        found = ApiChecksEngine().run(c, sealed(), ScanContext(job_id="j", base_url=BASE, identities=ids))
    assert {f.vuln_class for f in found} == {"api_inventory_exposure", "missing_security_header"}


def test_static_token_used():
    seen = []

    def h(req):
        seen.append(req.headers.get("authorization"))
        if req.url.path == "/openapi.json":
            return httpx.Response(200, json={"paths": {}})
        return httpx.Response(200, json={}, headers={"x-content-type-options": "n", "cache-control": "n"})

    with client(h) as c:
        ApiChecksEngine().run(c, sealed(), ScanContext(job_id="j", base_url=BASE, identities=IDS))
    assert "Bearer tA" in seen
