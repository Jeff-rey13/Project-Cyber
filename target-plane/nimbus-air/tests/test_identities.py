import json

from app import identities
from app.seed import KNOWN_IDENTITIES


def test_identities_match_seed(session):
    out = identities.identities(session)
    assert [i["email"] for i in out] == [k["email"] for k in KNOWN_IDENTITIES]
    for i in out:
        assert len(i["objects"]) == 2 and len(i["markers"]) == 2 and i["password"]


def test_main_prints_scan_options(monkeypatch, capsys):
    monkeypatch.setenv("NIMBUS_DATABASE_URL", "sqlite://")
    identities.main()
    doc = json.loads(capsys.readouterr().out)
    assert {i["label"] for i in doc["identities"]} == {"alice", "bob"}
