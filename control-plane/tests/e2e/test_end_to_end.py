"""End to end (PRD 9.1): bring up lab -> verify -> scan -> assert findings; and refuse unverified targets.

Runs the real control api, real lab process over a real socket, and the
in-process engines (authz + api_checks). zap and nuclei need their own
containers and are exercised in the compose stack, not here.
"""

import sqlite3
from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient
from sqlmodel import Session

from app.api.routes import create_api
from app.config import Settings
from app.db import make_engine
from app.orchestrator import service

from ..conftest import SNAPSHOT_KEY
from ..lab import identities_from_db, nimbus

TOKEN = "e2e-operator-token-0123456789"
H = {"Authorization": f"Bearer {TOKEN}"}
ENGINES = ["authz", "api_checks"]


def scope(hosts, deny=()):
    now = datetime.now(timezone.utc)
    return {"hosts": hosts, "deny_paths": list(deny), "window_start": (now - timedelta(minutes=1)).isoformat(),
            "window_end": (now + timedelta(hours=1)).isoformat()}


@pytest.fixture
def api():
    engine = make_engine("sqlite://")
    settings = Settings(database_url="sqlite://", redis_url="", snapshot_key=SNAPSHOT_KEY, operator_token=TOKEN)

    def run_inline(job_id):
        with Session(engine) as s:
            service.execute_scan(s, job_id, SNAPSHOT_KEY)

    return TestClient(create_api(settings, engine, run_inline))


def scan(api, base, db, hosts=("127.0.0.1",), deny=()):
    body = {"base_url": base, "scope": scope(list(hosts), deny), "engines": ENGINES,
            "options": {"identities": identities_from_db(db)}}
    job = api.post("/scans", json=body, headers=H).json()
    q = api.post(f"/scans/{job['id']}/queue", headers=H)
    return job, q


# --- refusal ---------------------------------------------------------------

def test_refuses_unverified_targets_and_sends_nothing(api, tmp_path):
    with nimbus(tmp_path, secure=False) as (base, db):
        port = base.rsplit(":", 1)[1]
        # same lab, reached by a name that was never verified
        for host in ("localhost", "nimbus.test", "127.0.0.2"):
            job, q = scan(api, f"http://{host}:{port}", db, hosts=(host,))
            assert job["state"] == "PENDING_VERIFICATION"
            assert q.status_code == 409
            assert api.get(f"/scans/{job['id']}", headers=H).json()["state"] == "PENDING_VERIFICATION"

        # loopback self-verify can't be stretched to cover a real-looking host
        assert api.post("/targets/nimbus.test/self-verify", headers=H).status_code == 400
        assert api.post("/targets/169.254.169.254/self-verify", headers=H).status_code == 400

    m = api.get("/metrics", headers=H).json()
    assert m["gate"]["allowed"] == 0 and m["scan"] is None
    assert m["gate"]["pre_scan_refusals"] >= 3


def test_base_url_outside_scope_is_rejected(api, tmp_path):
    api.post("/targets/127.0.0.1/self-verify", headers=H)
    body = {"base_url": "http://evil.example", "scope": scope(["127.0.0.1"]), "engines": ENGINES}
    assert api.post("/scans", json=body, headers=H).status_code == 400


# --- full scan, vulnerable lab -------------------------------------------------

def test_full_scan_insecure_lab(api, tmp_path):
    with nimbus(tmp_path, secure=False) as (base, db):
        assert api.post("/targets/127.0.0.1/self-verify", headers=H).status_code == 200
        before = sqlite3.connect(db).execute("select loyalty_tier from customer where email='alice@nimbus.test'").fetchone()[0]
        job, q = scan(api, base, db)
        assert q.status_code == 200
        after = sqlite3.connect(db).execute("select loyalty_tier from customer where email='alice@nimbus.test'").fetchone()[0]

    final = api.get(f"/scans/{job['id']}", headers=H).json()
    assert final["state"] == "COMPLETED", final["error"]
    assert final["options"]["engine_errors"] == []

    findings = api.get(f"/scans/{job['id']}/findings", headers=H).json()
    classes = {f["vuln_class"] for f in findings}
    # acceptance: at least five distinct classes
    expected = {"bola", "broken_auth", "excessive_data_exposure", "mass_assignment", "missing_rate_limit"}
    assert expected <= classes and len(classes) >= 5

    # de-duplicated: one finding per class/template/param, not one per pnr probed
    keys = [(f["vuln_class"], f["url_template"], f["param"]) for f in findings]
    assert len(keys) == len(set(keys))

    # ranked by context risk, critical unauth access on top
    assert findings[0]["vuln_class"] == "broken_auth" and findings[0]["severity"] == "critical"
    assert [f["risk_score"] for f in findings] == sorted((f["risk_score"] for f in findings), reverse=True)

    bola = next(f for f in findings if f["vuln_class"] == "bola")
    assert bola["extra"]["reachability"]["alice->bob"] is True
    assert "{id}" in bola["url_template"] and bola["risk_factors"]["pii"] == 1.5

    # every finding carries all three frameworks
    for f in findings:
        assert f["frameworks"]["owasp"] and f["frameworks"]["pci_dss_v4"] and f["frameworks"]["mas_trm"], f["vuln_class"]
        assert f["remediation"]

    # the mass assignment probe cleaned up after itself
    assert after == before

    m = api.get("/metrics", headers=H).json()
    assert m["throttle"]["requests"] > 0 and not m["throttle"]["aborted"]
    assert m["gate"]["allowed"] > 0
    assert api.get("/audit/verify", headers=H).json()["intact"] is True


# --- full scan, fixed lab -----------------------------------------------------

def test_full_scan_secure_lab_is_clean_of_app_vulns(api, tmp_path):
    with nimbus(tmp_path, secure=True) as (base, db):
        api.post("/targets/127.0.0.1/self-verify", headers=H)
        job, q = scan(api, base, db)
        assert q.status_code == 200

    findings = api.get(f"/scans/{job['id']}/findings", headers=H).json()
    classes = {f["vuln_class"] for f in findings}
    assert not classes & {"bola", "broken_auth", "excessive_data_exposure", "mass_assignment", "missing_rate_limit"}
    # what's left is hygiene the secure_mode flag doesn't claim to fix
    assert classes <= {"api_inventory_exposure", "missing_security_header"}


def test_deny_list_respected_during_real_scan(api, tmp_path):
    with nimbus(tmp_path, secure=False) as (base, db):
        api.post("/targets/127.0.0.1/self-verify", headers=H)
        job, _ = scan(api, base, db, deny=["/bookings"])

    final = api.get(f"/scans/{job['id']}", headers=H).json()
    findings = api.get(f"/scans/{job['id']}/findings", headers=H).json()
    assert not any("/bookings" in f["url_template"] for f in findings)
    assert final["options"]["gate_stats"]["denied"] > 0
    assert "path on exclusion list" in final["options"]["gate_stats"]["deny_reasons"]
