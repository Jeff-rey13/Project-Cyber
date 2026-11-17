"""Control API: auth, verification, lifecycle and metrics, with a real scan against the lab."""

from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient
from sqlmodel import Session

from app.api.metrics import posture_score
from app.api.routes import create_api
from app.config import Settings
from app.db import make_engine
from app.orchestrator import service

from ..conftest import SNAPSHOT_KEY
from ..lab import identities_from_db, nimbus

TOKEN = "operator-token-0123456789"
H = {"Authorization": f"Bearer {TOKEN}"}
NOW = datetime.now(timezone.utc)


def scope(hosts=("127.0.0.1",)):
    return {"hosts": list(hosts), "window_start": (NOW - timedelta(minutes=5)).isoformat(),
            "window_end": (NOW + timedelta(hours=1)).isoformat()}


@pytest.fixture
def api():
    engine = make_engine("sqlite://")
    settings = Settings(database_url="sqlite://", redis_url="", snapshot_key=SNAPSHOT_KEY, operator_token=TOKEN)

    def run_inline(job_id):
        with Session(engine) as s:
            service.execute_scan(s, job_id, SNAPSHOT_KEY)

    return TestClient(create_api(settings, engine, run_inline))


def test_health_is_open_everything_else_needs_token(api):
    assert api.get("/health").status_code == 200
    for path in ("/targets", "/scans", "/metrics", "/audit/verify"):
        assert api.get(path).status_code == 401
        assert api.get(path, headers={"Authorization": "Bearer wrong"}).status_code == 401
        assert api.get(path, headers=H).status_code == 200


def test_verification_endpoints(api):
    r = api.post("/targets/nimbus.test/verification", json={"method": "dns_txt"}, headers=H)
    assert r.status_code == 200 and r.json()["instruction"].startswith("_aeroscan-challenge.nimbus.test TXT = ")
    assert api.post("/targets/http:%2F%2Fx/verification", json={}, headers=H).status_code in (400, 404)
    assert api.post("/targets/127.0.0.1/verification", json={"method": "loopback"}, headers=H).status_code == 400
    assert api.post("/targets/10.0.0.1/self-verify", headers=H).status_code == 400
    assert api.post("/targets/127.0.0.1/self-verify", headers=H).json()["verified"] is True
    assert [t["domain"] for t in api.get("/targets", headers=H).json()] == ["127.0.0.1"]


def test_check_verification_endpoint(api, monkeypatch):
    from app.scope import verification

    token = api.post("/targets/nimbus.test/verification", json={}, headers=H).json()["instruction"].split(" = ")[1]
    monkeypatch.setattr(verification, "dns_txt_lookup", lambda name: [token])
    assert api.post("/targets/nimbus.test/verification/check", headers=H).json()["verified"] is True
    assert api.post("/targets/bad..name/verification/check", headers=H).status_code == 400


def test_unverified_scan_is_refused_at_queue(api):
    r = api.post("/scans", json={"base_url": "http://nimbus.test", "scope": scope(["nimbus.test"]), "engines": ["authz"]}, headers=H)
    assert r.status_code == 201 and r.json()["state"] == "PENDING_VERIFICATION"
    job_id = r.json()["id"]
    q = api.post(f"/scans/{job_id}/queue", headers=H)
    assert q.status_code == 409 and "VERIFIED" in q.json()["detail"]
    assert api.get("/metrics", headers=H).json()["gate"]["pre_scan_refusals"] >= 1
    assert api.post(f"/scans/{job_id}/refresh", headers=H).json()["state"] == "PENDING_VERIFICATION"


@pytest.mark.parametrize("body,code", [
    ({"base_url": "http://evil.com", "scope": scope(), "engines": ["authz"]}, 400),
    ({"base_url": "http://127.0.0.1", "scope": scope(), "engines": ["nope"]}, 400),
    ({"base_url": "http://127.0.0.1", "scope": {"hosts": []}, "engines": ["authz"]}, 422),
    ({"base_url": "http://127.0.0.1", "scope": scope(), "engines": []}, 422),
])
def test_bad_scan_requests(api, body, code):
    assert api.post("/scans", json=body, headers=H).status_code == code


def test_unknown_scan_and_illegal_abort(api):
    assert api.get("/scans/nope", headers=H).status_code == 404
    assert api.get("/scans/nope/findings", headers=H).status_code == 404
    api.post("/targets/127.0.0.1/self-verify", headers=H)
    job = api.post("/scans", json={"base_url": "http://127.0.0.1", "scope": scope(), "engines": ["authz"]}, headers=H).json()
    assert api.post(f"/scans/{job['id']}/abort", headers=H).json()["state"] == "ABORTED"
    assert api.post(f"/scans/{job['id']}/abort", headers=H).status_code == 409


def test_full_scan_through_api(api, tmp_path):
    with nimbus(tmp_path, secure=False) as (base, db):
        assert api.post("/targets/127.0.0.1/self-verify", headers=H).status_code == 200
        body = {"base_url": base, "scope": scope(), "engines": ["authz"],
                "options": {"identities": identities_from_db(db)}}
        job = api.post("/scans", json=body, headers=H).json()
        assert job["state"] == "VERIFIED"
        assert all("password" not in i for i in job["options"]["identities"])
        done = api.post(f"/scans/{job['id']}/queue", headers=H)
        assert done.status_code == 200

    final = api.get(f"/scans/{job['id']}", headers=H).json()
    assert final["state"] == "COMPLETED" and final["scope_snapshot"]["seal"]

    findings = api.get(f"/scans/{job['id']}/findings", headers=H).json()
    classes = [f["vuln_class"] for f in findings]
    assert classes[0] == "broken_auth" and "bola" in classes
    for f in findings:
        assert f["frameworks"]["owasp"] and f["frameworks"]["pci_dss_v4"] and f["frameworks"]["mas_trm"]

    m = api.get("/metrics", headers=H).json()
    assert m["scan"]["id"] == job["id"] and m["findings"]["total"] == len(findings)
    assert m["findings"]["by_severity"]["critical"] >= 1 and m["findings"]["by_severity"]["high"] >= 1
    assert 0 <= m["posture_score"] < 100
    assert m["throttle"]["requests"] > 0 and m["gate"]["allowed"] > 0
    assert m["compliance"]["owasp"]["API1:2023 Broken Object Level Authorization"] >= 1
    assert api.get(f"/metrics?job_id={job['id']}", headers=H).json()["scan"]["id"] == job["id"]
    assert api.get("/audit/verify", headers=H).json() == {"intact": True, "first_bad_entry": None}


def test_metrics_empty_state(api):
    m = api.get("/metrics", headers=H).json()
    assert m["scan"] is None and m["posture_score"] is None and m["findings"]["total"] == 0


def test_posture_score_bounds():
    class F:
        def __init__(self, r):
            self.risk_score = r

    assert posture_score([]) == 100
    assert posture_score([F(30)]) == 70
    assert posture_score([F(10)] * 20) == 0


def test_dashboard_is_served(api):
    r = api.get("/dashboard/")
    assert r.status_code == 200 and "AeroScan" in r.text
    assert api.get("/", follow_redirects=False).headers["location"] == "/dashboard/"
