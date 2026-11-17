"""Persistent records for targets, verification challenges and the audit log."""

from datetime import datetime, timezone
from enum import Enum
from typing import Optional

from sqlmodel import JSON, Column, Field, SQLModel


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class VerificationStatus(str, Enum):
    PENDING = "pending"
    VERIFIED = "verified"
    EXPIRED = "expired"


class VerificationMethod(str, Enum):
    DNS_TXT = "dns_txt"
    HOSTED_FILE = "hosted_file"
    LOOPBACK = "loopback"


class Verification(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    domain: str = Field(index=True)
    token: str
    method: VerificationMethod = VerificationMethod.DNS_TXT
    status: VerificationStatus = VerificationStatus.PENDING
    created_at: datetime = Field(default_factory=utcnow)
    expires_at: datetime
    verified_at: Optional[datetime] = None
    # what we actually observed when the check passed; kept for the audit trail
    proof: Optional[dict] = Field(default=None, sa_column=Column(JSON))


class AuditEntry(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    at: datetime = Field(default_factory=utcnow)
    actor: str
    action: str
    detail: dict = Field(default_factory=dict, sa_column=Column(JSON))
    prev_hash: str
    entry_hash: str = Field(index=True, unique=True)
