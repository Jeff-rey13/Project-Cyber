"""Immutable, integrity-protected per-job scope (PRD 5.1, 7, 8).

The operator edits a ScopeDefinition. At VERIFIED -> QUEUED the definition is
frozen into a ScopeSnapshot and sealed with an hmac. The gate only ever reads
the snapshot, and refuses one whose seal doesn't check out.
"""

import hashlib
import hmac
import json
from datetime import datetime, timedelta, timezone
from typing import Optional

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator
from sqlmodel import Session

from . import audit
from .domains import canonical_domain
from .models import utcnow
from .verification import verified_record

MAX_WINDOW = timedelta(days=7)
# destructive or proxy-ish verbs are out unless the operator explicitly drops them from this set
DEFAULT_FORBIDDEN_METHODS = frozenset({"DELETE", "TRACE", "CONNECT"})
KNOWN_METHODS = frozenset({"GET", "HEAD", "OPTIONS", "POST", "PUT", "PATCH", "DELETE", "TRACE", "CONNECT"})


class ScopeError(Exception):
    pass


def _utc(dt: datetime) -> datetime:
    return dt.replace(tzinfo=timezone.utc) if dt.tzinfo is None else dt.astimezone(timezone.utc)


def _check_paths(paths: list[str]) -> list[str]:
    for p in paths:
        if not p.startswith("/") or any(ch in p for ch in "?#\\\x00") or "/../" in p + "/" or "/./" in p + "/":
            raise ValueError(f"bad path prefix: {p!r}")
    return paths


class ScopeDefinition(BaseModel):
    """What the operator asks for. Mutable, unverified, never read by the gate."""

    hosts: list[str] = Field(min_length=1)
    allow_paths: list[str] = Field(default_factory=lambda: ["/"])
    deny_paths: list[str] = Field(default_factory=list)
    window_start: datetime
    window_end: datetime
    forbidden_methods: set[str] = Field(default_factory=lambda: set(DEFAULT_FORBIDDEN_METHODS))

    @field_validator("allow_paths", "deny_paths")
    @classmethod
    def _paths(cls, v: list[str]) -> list[str]:
        return _check_paths(v)

    @field_validator("forbidden_methods")
    @classmethod
    def _methods(cls, v: set[str]) -> set[str]:
        upper = {m.upper() for m in v}
        unknown = upper - KNOWN_METHODS
        if unknown:
            raise ValueError(f"unknown methods: {sorted(unknown)}")
        return upper

    @model_validator(mode="after")
    def _window(self) -> "ScopeDefinition":
        start, end = _utc(self.window_start), _utc(self.window_end)
        if end <= start:
            raise ValueError("window_end must be after window_start")
        if end - start > MAX_WINDOW:
            raise ValueError("scan window longer than 7 days")
        self.window_start, self.window_end = start, end
        return self


class ScopeSnapshot(BaseModel):
    model_config = ConfigDict(frozen=True)

    job_id: str
    verified_hosts: tuple[str, ...]
    allow_paths: tuple[str, ...]
    deny_paths: tuple[str, ...]
    window_start: datetime
    window_end: datetime
    forbidden_methods: frozenset[str]
    proof_ref: tuple[int, ...]
    captured_at: datetime
    seal: str = ""

    def canonical_bytes(self) -> bytes:
        body = self.model_dump(exclude={"seal"})
        body["forbidden_methods"] = sorted(body["forbidden_methods"])
        return json.dumps(body, sort_keys=True, separators=(",", ":"), default=str).encode()

    def digest(self) -> str:
        return hashlib.sha256(self.canonical_bytes()).hexdigest()

    def is_sealed_with(self, key: bytes) -> bool:
        expected = hmac.new(key, self.canonical_bytes(), hashlib.sha256).hexdigest()
        return bool(self.seal) and hmac.compare_digest(self.seal, expected)


def _seal(snapshot: ScopeSnapshot, key: bytes) -> ScopeSnapshot:
    sig = hmac.new(key, snapshot.canonical_bytes(), hashlib.sha256).hexdigest()
    return snapshot.model_copy(update={"seal": sig})


def capture_snapshot(
    session: Session,
    job_id: str,
    definition: ScopeDefinition,
    key: bytes,
    actor: str,
    now: Optional[datetime] = None,
) -> ScopeSnapshot:
    """Freeze a definition into a sealed snapshot. Every host must already be VERIFIED."""
    if len(key) < 16:
        raise ScopeError("snapshot key too short")
    hosts: list[str] = []
    proofs: list[int] = []
    for raw in definition.hosts:
        host = canonical_domain(raw)
        record = verified_record(session, host)
        if record is None:
            audit.append(session, actor, "scope.refused", {"job_id": job_id, "host": host, "reason": "not verified"})
            raise ScopeError(f"{host} has not passed ownership verification")
        if host not in hosts:
            hosts.append(host)
            proofs.append(record.id)

    snap = ScopeSnapshot(
        job_id=job_id,
        verified_hosts=tuple(hosts),
        allow_paths=tuple(definition.allow_paths),
        deny_paths=tuple(definition.deny_paths),
        window_start=definition.window_start,
        window_end=definition.window_end,
        forbidden_methods=frozenset(definition.forbidden_methods),
        proof_ref=tuple(proofs),
        captured_at=_utc(now or utcnow()),
    )
    snap = _seal(snap, key)
    audit.append(session, actor, "scope.captured", {"job_id": job_id, "hosts": hosts, "proof_ref": proofs, "digest": snap.digest()})
    return snap
