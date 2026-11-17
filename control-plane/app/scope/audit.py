"""Append-only, hash-chained audit log.

Each entry commits to the previous entry's hash, so editing or deleting a
row in the middle breaks every hash after it and `verify_chain` says where.
There is intentionally no update or delete function in this module.
"""

import hashlib
import json
from datetime import datetime
from typing import Optional

from sqlmodel import Session, select

from .models import AuditEntry, utcnow

GENESIS = "0" * 64


def _hash(prev_hash: str, at: datetime, actor: str, action: str, detail: dict) -> str:
    payload = json.dumps(
        {"prev": prev_hash, "at": at.isoformat(), "actor": actor, "action": action, "detail": detail},
        sort_keys=True,
        separators=(",", ":"),
        default=str,
    )
    return hashlib.sha256(payload.encode()).hexdigest()


def _last(session: Session) -> Optional[AuditEntry]:
    return session.exec(select(AuditEntry).order_by(AuditEntry.id.desc())).first()


def append(session: Session, actor: str, action: str, detail: Optional[dict] = None) -> AuditEntry:
    detail = detail or {}
    last = _last(session)
    prev = last.entry_hash if last else GENESIS
    # strip tz before hashing so sqlite's naive round-trip doesn't change the digest
    at = utcnow().replace(tzinfo=None)
    entry = AuditEntry(at=at, actor=actor, action=action, detail=detail, prev_hash=prev,
                       entry_hash=_hash(prev, at, actor, action, detail))
    session.add(entry)
    session.commit()
    session.refresh(entry)
    return entry


def verify_chain(session: Session) -> Optional[int]:
    """Return None if the chain is intact, else the id of the first bad entry."""
    prev = GENESIS
    for e in session.exec(select(AuditEntry).order_by(AuditEntry.id)):
        at = e.at.replace(tzinfo=None)
        if e.prev_hash != prev or e.entry_hash != _hash(prev, at, e.actor, e.action, e.detail):
            return e.id
        prev = e.entry_hash
    return None
