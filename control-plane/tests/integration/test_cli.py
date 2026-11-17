import json

import pytest
from fastapi.testclient import TestClient
from sqlmodel import Session

from app import cli
from app.api.routes import create_api
from app.config import Settings
from app.db import make_engine
from app.orchestrator import service

from ..conftest import SNAPSHOT_KEY
from ..lab import identities_from_db, nimbus

TOKEN = "cli-operator-token-0123456789"


@pytest.fixture
def api(monkeypatch):
    engine = make_engine("sqlite://")
    settings = Settings(database_url="sqlite://", redis_url="", snapshot_key=SNAPSHOT_KEY, operator_token=TOKEN)

    def run_inline(job_id):
        with Session(engine) as s:
            service.execute_scan(s, job_id, SNAPSHOT_KEY)

    tc = TestClient(create_api(settings, engine, run_inline), headers={"Authorization": f"Bearer {TOKEN}"})
    monkeypatch.setattr(cli, "_client", lambda: tc)
    monkeypatch.setattr(cli.time, "sleep", lambda s: None)
    return tc


def test_try_unverified_is_refused(api, capsys):
    assert cli.main(["try-unverified", "http://example.com"]) == 0
    out = capsys.readouterr().out
    assert "PENDING_VERIFICATION" in out and "409" in out


def test_try_unverified_bad_url_refused_at_create(api, capsys):
    assert cli.main(["try-unverified", "ftp://example.com"]) == 0
    assert "refused at create" in capsys.readouterr().out


def test_scan_and_findings_against_lab(api, tmp_path, capsys):
    with nimbus(tmp_path, secure=False) as (base, db):
        api.post("/targets/127.0.0.1/self-verify")
        ident = tmp_path / "ids.json"
        ident.write_text(json.dumps({"identities": identities_from_db(db)}))
        assert cli.main(["scan", "--base-url", base, "--identities", str(ident)]) == 0
    out = capsys.readouterr().out
    assert "API1:2023" in out and "[critical]" in out

    scan_id = api.get("/scans").json()[0]["id"]
    assert cli.main(["findings", scan_id]) == 0
    assert "/bookings/{id}" in capsys.readouterr().out


def test_scan_refusals(api, capsys):
    assert cli.main(["scan", "--base-url", "http://nimbus.test", "--engines", "authz"]) == 1
    assert "refused to queue" in capsys.readouterr().out
    assert cli.main(["scan", "--base-url", "http://127.0.0.1", "--engines", "nope"]) == 1
    assert "refused:" in capsys.readouterr().out


def test_no_findings_message(capsys):
    cli._print_findings([])
    assert "no findings" in capsys.readouterr().out


def test_missing_token_exits(monkeypatch):
    monkeypatch.delenv("AEROSCAN_OPERATOR_TOKEN", raising=False)
    with pytest.raises(SystemExit):
        cli._client()


def test_partial_scan_is_flagged(api, tmp_path, capsys):
    api.post("/targets/127.0.0.1/self-verify")
    # nothing listening on this port, so every engine request fails
    assert cli.main(["scan", "--base-url", "http://127.0.0.1:9", "--engines", "authz,api_checks"]) == 2
    assert "WARNING engine failed" in capsys.readouterr().out


def test_identities_from_stdin(api, monkeypatch, capsys):
    import io

    monkeypatch.setattr(cli.sys, "stdin", io.StringIO('{"identities": []}'))
    api.post("/targets/127.0.0.1/self-verify")
    cli.main(["scan", "--base-url", "http://127.0.0.1:9", "--identities", "-", "--engines", "authz"])
    assert "created" in capsys.readouterr().out
