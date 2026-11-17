"""Proof-of-control for scan targets (PRD 5.1).

A domain only ever becomes VERIFIED here. Three ways in:
  - dns txt:      operator publishes a random token at _aeroscan-challenge.<domain>
  - hosted file:  operator serves the token at /.well-known/aeroscan-challenge.txt
  - loopback:     literal loopback hosts only, for the bundled lab
"""

import hmac
import secrets
from collections.abc import Callable
from datetime import datetime, timedelta, timezone
from typing import Optional

from sqlmodel import Session, select

from . import audit
from .domains import canonical_domain, is_loopback
from .models import Verification, VerificationMethod, VerificationStatus, utcnow

CHALLENGE_LABEL = "_aeroscan-challenge"
WELL_KNOWN_PATH = "/.well-known/aeroscan-challenge.txt"
TOKEN_TTL = timedelta(hours=24)

TxtLookup = Callable[[str], list[str]]
FileFetch = Callable[[str], Optional[str]]


class VerificationError(Exception):
    pass


def _aware(dt: datetime) -> datetime:
    # sqlite hands datetimes back naive; everything in here is utc
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def dns_txt_lookup(name: str) -> list[str]:
    import dns.exception
    import dns.resolver

    try:
        answer = dns.resolver.resolve(name, "TXT", lifetime=5.0)
    except dns.exception.DNSException:
        return []
    return [b"".join(r.strings).decode(errors="replace") for r in answer]


def http_file_fetch(url: str) -> Optional[str]:
    import httpx

    # one fixed path, no redirects, tiny timeout. this is the only request aeroscan ever sends to an
    # unverified host, and it's the same thing any acme client does.
    try:
        r = httpx.get(url, timeout=5.0, follow_redirects=False)
    except httpx.HTTPError:
        return None
    return r.text[:256] if r.status_code == 200 else None


def _pending(session: Session, domain: str) -> Optional[Verification]:
    stmt = (
        select(Verification)
        .where(Verification.domain == domain, Verification.status == VerificationStatus.PENDING)
        .order_by(Verification.id.desc())
    )
    return session.exec(stmt).first()


def begin_verification(
    session: Session,
    raw_domain: str,
    actor: str,
    method: VerificationMethod = VerificationMethod.DNS_TXT,
    now: Optional[datetime] = None,
) -> tuple[Verification, str]:
    """Issue a fresh single-use token. Any earlier pending challenge for the domain is retired."""
    if method == VerificationMethod.LOOPBACK:
        raise VerificationError("loopback targets use self_verify_loopback")
    domain = canonical_domain(raw_domain)
    now = now or utcnow()

    for old in session.exec(select(Verification).where(Verification.domain == domain, Verification.status == VerificationStatus.PENDING)):
        old.status = VerificationStatus.EXPIRED
        session.add(old)

    v = Verification(domain=domain, token=secrets.token_hex(32), method=method, expires_at=now + TOKEN_TTL)
    session.add(v)
    session.commit()
    session.refresh(v)
    audit.append(session, actor, "verification.begin", {"domain": domain, "method": method.value, "verification_id": v.id})

    if method == VerificationMethod.DNS_TXT:
        instruction = f"{CHALLENGE_LABEL}.{domain} TXT = {v.token}"
    else:
        instruction = f"serve {v.token} at http://{domain}{WELL_KNOWN_PATH}"
    return v, instruction


def check_verification(
    session: Session,
    raw_domain: str,
    actor: str,
    txt_lookup: Optional[TxtLookup] = None,
    file_fetch: Optional[FileFetch] = None,
    now: Optional[datetime] = None,
) -> bool:
    # resolved per call (not as default args) so the real lookups can be swapped out in one place
    txt_lookup = txt_lookup or dns_txt_lookup
    file_fetch = file_fetch or http_file_fetch
    domain = canonical_domain(raw_domain)
    now = now or utcnow()
    v = _pending(session, domain)
    if v is None:
        audit.append(session, actor, "verification.fail", {"domain": domain, "reason": "no pending challenge"})
        return False
    if _aware(v.expires_at) <= now:
        v.status = VerificationStatus.EXPIRED
        session.add(v)
        session.commit()
        audit.append(session, actor, "verification.fail", {"domain": domain, "reason": "challenge expired"})
        return False

    if v.method == VerificationMethod.DNS_TXT:
        record = f"{CHALLENGE_LABEL}.{domain}"
        observed = txt_lookup(record)
        proof = {"method": "dns_txt", "record": record, "observed": observed}
    else:
        url = f"http://{domain}{WELL_KNOWN_PATH}"
        body = file_fetch(url)
        observed = [body.strip()] if body else []
        proof = {"method": "hosted_file", "url": url, "observed": observed}

    # check every candidate without short-circuiting, so timing doesn't hint at which one matched
    matched = False
    for candidate in observed:
        matched |= hmac.compare_digest(candidate.strip().encode(), v.token.encode())

    if not matched:
        audit.append(session, actor, "verification.fail", {"domain": domain, "reason": "token not found"})
        return False

    v.status = VerificationStatus.VERIFIED
    v.verified_at = now
    v.proof = proof
    session.add(v)
    session.commit()
    audit.append(session, actor, "verification.pass", {"domain": domain, "verification_id": v.id, "proof": proof})
    return True


def self_verify_loopback(session: Session, raw_domain: str, actor: str, now: Optional[datetime] = None) -> Verification:
    """Verify the bundled lab without dns.

    loopback self-verify only; anything outside 127.0.0.0/8, ::1 and `localhost`
    must go through a real proof above.
    """
    domain = canonical_domain(raw_domain)
    if not is_loopback(domain):
        audit.append(session, actor, "verification.loopback_refused", {"domain": domain})
        raise VerificationError(f"{domain} is not a loopback address")
    now = now or utcnow()
    existing = verified_record(session, domain)
    if existing:
        return existing
    proof = {"method": "loopback", "address": domain}
    v = Verification(
        domain=domain,
        token=secrets.token_hex(32),
        method=VerificationMethod.LOOPBACK,
        status=VerificationStatus.VERIFIED,
        expires_at=now,
        verified_at=now,
        proof=proof,
    )
    session.add(v)
    session.commit()
    session.refresh(v)
    audit.append(session, actor, "verification.pass", {"domain": domain, "verification_id": v.id, "proof": proof})
    return v


def verified_record(session: Session, raw_domain: str) -> Optional[Verification]:
    domain = canonical_domain(raw_domain)
    stmt = (
        select(Verification)
        .where(Verification.domain == domain, Verification.status == VerificationStatus.VERIFIED)
        .order_by(Verification.id.desc())
    )
    return session.exec(stmt).first()


def is_verified(session: Session, raw_domain: str) -> bool:
    try:
        return verified_record(session, raw_domain) is not None
    except ValueError:
        return False
