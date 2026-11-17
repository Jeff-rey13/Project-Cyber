from datetime import timedelta

import pytest
from sqlmodel import select

from app.scope import audit
from app.scope.models import AuditEntry, Verification, VerificationMethod, VerificationStatus, utcnow
from app.scope.verification import (
    TOKEN_TTL,
    VerificationError,
    begin_verification,
    check_verification,
    is_verified,
    self_verify_loopback,
    verified_record,
)

OP = "operator"


def publish(token_holder):
    """Fake dns that returns whatever is currently in token_holder for the challenge name."""
    def lookup(name):
        return token_holder.get(name, [])
    return lookup


def no_dns(name):
    raise AssertionError("dns should not be queried")


def test_begin_returns_instruction_with_fresh_random_token(session):
    v1, instr = begin_verification(session, "Nimbus.Test", OP)
    v2, _ = begin_verification(session, "nimbus.test", OP)
    assert instr == f"_aeroscan-challenge.nimbus.test TXT = {v1.token}"
    assert len(v1.token) == 64 and v1.token != v2.token
    session.refresh(v1)
    assert v1.status == VerificationStatus.EXPIRED  # retired by the second begin


def test_dns_pass_marks_verified_and_keeps_proof(session):
    v, _ = begin_verification(session, "nimbus.test", OP)
    dns = {"_aeroscan-challenge.nimbus.test": ["unrelated", v.token]}
    assert check_verification(session, "nimbus.test", OP, txt_lookup=publish(dns))
    rec = verified_record(session, "nimbus.test")
    assert rec.proof["observed"] == ["unrelated", v.token]
    assert rec.verified_at is not None
    assert is_verified(session, "NIMBUS.test.")


def test_wrong_token_fails(session):
    begin_verification(session, "nimbus.test", OP)
    dns = {"_aeroscan-challenge.nimbus.test": ["0" * 64]}
    assert not check_verification(session, "nimbus.test", OP, txt_lookup=publish(dns))
    assert not is_verified(session, "nimbus.test")


def test_token_on_wrong_record_name_fails(session):
    v, _ = begin_verification(session, "nimbus.test", OP)
    dns = {"_aeroscan-challenge.other.test": [v.token], "nimbus.test": [v.token]}
    assert not check_verification(session, "nimbus.test", OP, txt_lookup=publish(dns))


def test_token_is_single_use(session):
    v, _ = begin_verification(session, "nimbus.test", OP)
    dns = {"_aeroscan-challenge.nimbus.test": [v.token]}
    assert check_verification(session, "nimbus.test", OP, txt_lookup=publish(dns))
    # no pending challenge left, so a replay fails rather than re-verifying
    assert not check_verification(session, "nimbus.test", OP, txt_lookup=publish(dns))


def test_old_token_dead_after_reissue(session):
    old, _ = begin_verification(session, "nimbus.test", OP)
    begin_verification(session, "nimbus.test", OP)
    dns = {"_aeroscan-challenge.nimbus.test": [old.token]}
    assert not check_verification(session, "nimbus.test", OP, txt_lookup=publish(dns))


def test_expired_challenge_fails(session):
    start = utcnow()
    v, _ = begin_verification(session, "nimbus.test", OP, now=start)
    dns = {"_aeroscan-challenge.nimbus.test": [v.token]}
    later = start + TOKEN_TTL + timedelta(seconds=1)
    assert not check_verification(session, "nimbus.test", OP, txt_lookup=publish(dns), now=later)
    session.refresh(v)
    assert v.status == VerificationStatus.EXPIRED


def test_check_without_begin_fails(session):
    assert not check_verification(session, "nimbus.test", OP, txt_lookup=no_dns)


def test_token_for_one_domain_does_not_verify_another(session):
    a, _ = begin_verification(session, "a.test", OP)
    begin_verification(session, "b.test", OP)
    dns = {"_aeroscan-challenge.b.test": [a.token]}
    assert not check_verification(session, "b.test", OP, txt_lookup=publish(dns))


def test_hosted_file_method(session):
    v, instr = begin_verification(session, "nimbus.test", OP, method=VerificationMethod.HOSTED_FILE)
    assert "/.well-known/aeroscan-challenge.txt" in instr
    seen = []

    def fetch(url):
        seen.append(url)
        return v.token + "\n"

    assert check_verification(session, "nimbus.test", OP, txt_lookup=no_dns, file_fetch=fetch)
    assert seen == ["http://nimbus.test/.well-known/aeroscan-challenge.txt"]


def test_hosted_file_missing(session):
    begin_verification(session, "nimbus.test", OP, method=VerificationMethod.HOSTED_FILE)
    assert not check_verification(session, "nimbus.test", OP, file_fetch=lambda url: None)


def test_begin_refuses_loopback_method(session):
    with pytest.raises(VerificationError):
        begin_verification(session, "127.0.0.1", OP, method=VerificationMethod.LOOPBACK)


@pytest.mark.parametrize("host", ["127.0.0.1", "127.0.0.53", "[::1]", "localhost"])
def test_loopback_self_verify(session, host):
    v = self_verify_loopback(session, host, OP)
    assert v.status == VerificationStatus.VERIFIED and v.proof["method"] == "loopback"
    assert is_verified(session, host)
    # idempotent
    assert self_verify_loopback(session, host, OP).id == v.id


@pytest.mark.parametrize("host", ["nimbus.test", "10.0.0.5", "192.168.1.1", "0.0.0.0", "localhost.evil.com", "169.254.169.254"])
def test_loopback_self_verify_refuses_everything_else(session, host):
    with pytest.raises(VerificationError):
        self_verify_loopback(session, host, OP)
    assert not is_verified(session, host)
    refused = session.exec(select(AuditEntry).where(AuditEntry.action == "verification.loopback_refused")).all()
    assert refused


def test_is_verified_false_on_garbage(session):
    assert not is_verified(session, "http://x")


def test_every_step_is_audited(session):
    v, _ = begin_verification(session, "nimbus.test", OP)
    check_verification(session, "nimbus.test", OP, txt_lookup=lambda n: [])
    check_verification(session, "nimbus.test", OP, txt_lookup=lambda n: [v.token])
    actions = [e.action for e in session.exec(select(AuditEntry).order_by(AuditEntry.id))]
    assert actions == ["verification.begin", "verification.fail", "verification.pass"]
    assert audit.verify_chain(session) is None


def test_no_verification_rows_for_rejected_domains(session):
    with pytest.raises(ValueError):
        begin_verification(session, "http://nimbus.test", OP)
    assert session.exec(select(Verification)).all() == []
