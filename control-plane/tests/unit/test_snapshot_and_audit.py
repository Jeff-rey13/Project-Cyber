from datetime import datetime, timedelta, timezone

import pytest
from pydantic import ValidationError
from sqlmodel import select

from app.scope import audit
from app.scope.models import AuditEntry
from app.scope.snapshot import DEFAULT_FORBIDDEN_METHODS, ScopeDefinition, ScopeError, capture_snapshot
from app.scope.verification import self_verify_loopback

from ..conftest import SNAPSHOT_KEY

OP = "operator"
T0 = datetime(2027, 1, 1, tzinfo=timezone.utc)


def definition(**kw):
    base = dict(hosts=["127.0.0.1"], window_start=T0, window_end=T0 + timedelta(hours=2))
    base.update(kw)
    return ScopeDefinition(**base)


# --- definition validation ---

def test_defaults():
    d = definition()
    assert d.allow_paths == ["/"] and d.deny_paths == []
    assert d.forbidden_methods == set(DEFAULT_FORBIDDEN_METHODS)


@pytest.mark.parametrize("kw", [
    {"hosts": []},
    {"window_end": T0},
    {"window_end": T0 - timedelta(seconds=1)},
    {"window_end": T0 + timedelta(days=8)},
    {"allow_paths": ["bookings"]},
    {"allow_paths": ["/a/../b"]},
    {"deny_paths": ["/x?y"]},
    {"forbidden_methods": {"YEET"}},
])
def test_bad_definitions_rejected(kw):
    with pytest.raises(ValidationError):
        definition(**kw)


def test_naive_window_treated_as_utc():
    d = definition(window_start=datetime(2027, 1, 1), window_end=datetime(2027, 1, 1, 1))
    assert d.window_start.tzinfo is not None


def test_methods_uppercased():
    assert definition(forbidden_methods={"delete", "put"}).forbidden_methods == {"DELETE", "PUT"}


# --- capture ---

def test_capture_requires_verified_hosts(session):
    with pytest.raises(ScopeError):
        capture_snapshot(session, "job-1", definition(), SNAPSHOT_KEY, OP)
    refused = session.exec(select(AuditEntry).where(AuditEntry.action == "scope.refused")).one()
    assert refused.detail["host"] == "127.0.0.1"


def test_capture_refuses_if_any_host_unverified(session):
    self_verify_loopback(session, "127.0.0.1", OP)
    with pytest.raises(ScopeError):
        capture_snapshot(session, "job-1", definition(hosts=["127.0.0.1", "nimbus.test"]), SNAPSHOT_KEY, OP)


def test_capture_produces_sealed_frozen_snapshot(session):
    v = self_verify_loopback(session, "127.0.0.1", OP)
    snap = capture_snapshot(session, "job-1", definition(hosts=["127.0.0.1", "127.0.0.1"]), SNAPSHOT_KEY, OP)
    assert snap.verified_hosts == ("127.0.0.1",)
    assert snap.proof_ref == (v.id,)
    assert snap.is_sealed_with(SNAPSHOT_KEY)
    assert not snap.is_sealed_with(b"some-other-key-0123456789")
    with pytest.raises(ValidationError):
        snap.verified_hosts = ("evil.com",)  # type: ignore[misc]


def test_snapshot_detached_from_definition(session):
    self_verify_loopback(session, "127.0.0.1", OP)
    d = definition()
    snap = capture_snapshot(session, "job-1", d, SNAPSHOT_KEY, OP)
    d.allow_paths.append("/admin")
    d.hosts.append("evil.com")
    assert snap.allow_paths == ("/",) and snap.verified_hosts == ("127.0.0.1",)


def test_tampered_copy_fails_seal(session):
    self_verify_loopback(session, "127.0.0.1", OP)
    snap = capture_snapshot(session, "job-1", definition(), SNAPSHOT_KEY, OP)
    forged = snap.model_copy(update={"verified_hosts": ("127.0.0.1", "evil.com")})
    assert not forged.is_sealed_with(SNAPSHOT_KEY)
    assert not snap.model_copy(update={"seal": ""}).is_sealed_with(SNAPSHOT_KEY)


def test_short_key_refused(session):
    self_verify_loopback(session, "127.0.0.1", OP)
    with pytest.raises(ScopeError):
        capture_snapshot(session, "job-1", definition(), b"short", OP)


# --- audit chain ---

def test_audit_chain_intact_then_detects_tamper(session):
    for i in range(5):
        audit.append(session, OP, "test.event", {"i": i})
    assert audit.verify_chain(session) is None

    third = session.exec(select(AuditEntry).order_by(AuditEntry.id).offset(2)).first()
    third.detail = {"i": 999}
    session.add(third)
    session.commit()
    assert audit.verify_chain(session) == third.id


def test_audit_detects_deleted_row(session):
    for i in range(4):
        audit.append(session, OP, "test.event", {"i": i})
    second = session.exec(select(AuditEntry).order_by(AuditEntry.id).offset(1)).first()
    session.delete(second)
    session.commit()
    assert audit.verify_chain(session) is not None
