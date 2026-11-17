"""AuthZ engine: unit-level helpers, then the real thing against a live Nimbus Air."""

import hashlib
import hmac
from datetime import datetime, timedelta, timezone

import httpx
import pytest

from app.engines.authz_engine import (
    AuthzEngine,
    Endpoint,
    Identity,
    leaks_foreign_data,
    looks_predictable,
    object_endpoints,
    redact,
)
from app.engines.base import ScanContext
from app.orchestrator.guarded_client import GateStats, guarded_client
from app.scope.snapshot import ScopeSnapshot

from ..lab import identities_from_db, nimbus

KEY = b"authz-test-key-0123456789"
NOW = datetime.now(timezone.utc)


def sealed():
    s = ScopeSnapshot(job_id="job-authz", verified_hosts=("127.0.0.1",), allow_paths=("/",), deny_paths=(),
                      window_start=NOW - timedelta(minutes=5), window_end=NOW + timedelta(hours=1),
                      forbidden_methods=frozenset({"DELETE", "TRACE", "CONNECT"}), proof_ref=(1,), captured_at=NOW)
    return s.model_copy(update={"seal": hmac.new(KEY, s.canonical_bytes(), hashlib.sha256).hexdigest()})


# --- helpers ---

def test_object_endpoints_only_safe_single_param():
    doc = {"paths": {
        "/bookings/{pnr}": {"get": {}, "post": {}},
        "/bookings/{pnr}/checkin": {"post": {}},
        "/a/{x}/b/{y}": {"get": {}},
        "/me": {"get": {}},
    }}
    assert [(e.method, e.template) for e in object_endpoints(doc)] == [("GET", "/bookings/{pnr}")]


def test_endpoint_url_escapes_object_id():
    assert Endpoint("GET", "/b/{id}", "id").url("http://h/", "../x?y") == "http://h/b/..%2Fx%3Fy"


def test_identity_requires_objects_and_markers():
    with pytest.raises(ValueError):
        Identity.from_dict({"label": "a", "objects": [], "markers": ["x"]})


def test_leak_detection_needs_markers():
    v = Identity("bob", ["P1"], ["Bob Lim", "X1234567"])
    assert leaks_foreign_data('{"name":"bob lim"}', v) == ["Bob Lim"]
    assert leaks_foreign_data('{"pnr":"P1","status":"ok"}', v) == []


def test_redaction_strips_markers_and_pii_shapes():
    ids = [Identity("bob", ["P1"], ["Bob Lim", "X1234567"])]
    out = redact('{"n":"Bob Lim","p":"X1234567","dob":"1990-02-03","e":"bob@nimbus.test","c":"4000 **** **** 1234","t":"+65 91234567"}', ids)
    for leaked in ("Bob Lim", "X1234567", "1990-02-03", "bob@nimbus.test", "1234", "91234567"):
        assert leaked not in out
    assert "[bob:marker0]" in out


@pytest.mark.parametrize("a,b,expected", [
    ("1001", "1002", True), ("1", "999999", False), ("AB", "CD", True),
    ("NM000123", "NM000124", True), ("Q7X2KD", "M3PA9Z", False),
])
def test_predictability(a, b, expected):
    assert looks_predictable(a, b) is expected


def test_needs_two_identities():
    r = AuthzEngine().assess(None, ScanContext(job_id="j", base_url="http://x", identities=[]))
    assert r.skipped == {"*": "need at least two test identities"} and r.findings == []


# --- live lab ---

def run_engine(base, db, stats=None):
    ctx = ScanContext(job_id="j", base_url=base, identities=identities_from_db(db))
    engine = AuthzEngine()
    with guarded_client(sealed(), KEY, stats=stats) as c:
        findings = engine.run(c, sealed(), ctx)
    return engine.last, findings


def test_finds_bola_and_anon_access_on_insecure_lab(tmp_path):
    with nimbus(tmp_path, secure=False) as (base, db):
        stats = GateStats()
        result, findings = run_engine(base, db, stats)

    by = {(f.vuln_class, f.extra["attacker"], f.extra["victim"]) for f in findings}
    assert ("bola", "alice", "bob") in by and ("bola", "bob", "alice") in by
    assert ("broken_auth", "anonymous", "alice") in by and ("broken_auth", "anonymous", "bob") in by

    assert result.matrix["/bookings/{pnr}"] == {"alice->bob": True, "bob->alice": True, "anon->alice": True, "anon->bob": True}
    bola = next(f for f in findings if f.vuln_class == "bola")
    assert bola.severity == "high" and bola.cwe == 639 and bola.extra["reachability"] == result.matrix["/bookings/{pnr}"]
    assert next(f for f in findings if f.vuln_class == "broken_auth").severity == "critical"
    # random 6-char pnrs, so no predictability flag
    assert result.predictable["/bookings/{pnr}"] is False
    # nothing raw made it into evidence
    idents = identities_from_db(db)
    for f in findings:
        for ident in idents:
            for m in ident["markers"]:
                assert m.lower() not in f.evidence.lower()
    assert stats.denied == 0 and stats.allowed > 0


def test_clean_on_secure_lab(tmp_path):
    with nimbus(tmp_path, secure=True) as (base, db):
        result, findings = run_engine(base, db)
    assert findings == []
    assert result.matrix["/bookings/{pnr}"] == {"alice->bob": False, "bob->alice": False, "anon->alice": False, "anon->bob": False}


def test_bad_credentials_mean_baseline_skip(tmp_path):
    with nimbus(tmp_path, secure=True) as (base, db):
        ids = identities_from_db(db)
        for i in ids:
            i["password"] = "wrong"
        ctx = ScanContext(job_id="j", base_url=base, identities=ids)
        with guarded_client(sealed(), KEY) as c:
            result = AuthzEngine().assess(c, ctx)
    assert result.findings == [] and "/bookings/{pnr}" in result.skipped


def test_static_token_and_explicit_endpoints():
    seen = []

    def h(req):
        seen.append(req.headers.get("authorization"))
        body = {"P-A": "alice data", "P-B": "bob data"}[req.url.path.rsplit("/", 1)[1]]
        return httpx.Response(200, text=body)

    ids = [{"label": "a", "token": "tA", "objects": ["P-A"], "markers": ["alice data"]},
           {"label": "b", "token": "tB", "objects": ["P-B"], "markers": ["bob data"]}]
    eng = AuthzEngine(endpoints=[Endpoint("GET", "/o/{id}", "id")])
    with guarded_client(sealed(), KEY, inner_transport=httpx.MockTransport(h)) as c:
        res = eng.assess(c, ScanContext(job_id="j", base_url="http://127.0.0.1", identities=ids))
    assert "Bearer tA" in seen and None in seen
    assert {f.vuln_class for f in res.findings} == {"bola", "broken_auth"}


def test_login_failure_modes():
    def h(req):
        return httpx.Response(200, text="not json") if req.url.path == "/auth/token" else httpx.Response(401)

    with guarded_client(sealed(), KEY, inner_transport=httpx.MockTransport(h)) as c:
        eng = AuthzEngine()
        assert eng._login(c, "http://127.0.0.1", Identity("a", ["x"], ["m"], email="e", password="p")) is None
        assert eng._login(c, "http://127.0.0.1", Identity("a", ["x"], ["m"])) is None
