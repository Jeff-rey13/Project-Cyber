"""Scan lifecycle state machine (PRD 4.2).

DRAFT -> PENDING_VERIFICATION -> VERIFIED -> QUEUED -> RUNNING -> COMPLETED | FAILED | ABORTED

All state changes go through `transition`, which validates the edge and
writes an audit entry. Nothing else should assign `job.state`.
"""

import uuid
from datetime import datetime
from enum import Enum
from typing import Optional

from sqlmodel import JSON, Column, Field, Session, SQLModel

from ..scope import audit
from ..scope.models import utcnow


class ScanState(str, Enum):
    DRAFT = "DRAFT"
    PENDING_VERIFICATION = "PENDING_VERIFICATION"
    VERIFIED = "VERIFIED"
    QUEUED = "QUEUED"
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    ABORTED = "ABORTED"


TERMINAL = frozenset({ScanState.COMPLETED, ScanState.FAILED, ScanState.ABORTED})

TRANSITIONS: dict[ScanState, frozenset[ScanState]] = {
    ScanState.DRAFT: frozenset({ScanState.PENDING_VERIFICATION, ScanState.VERIFIED, ScanState.ABORTED}),
    ScanState.PENDING_VERIFICATION: frozenset({ScanState.VERIFIED, ScanState.ABORTED}),
    ScanState.VERIFIED: frozenset({ScanState.QUEUED, ScanState.ABORTED}),
    ScanState.QUEUED: frozenset({ScanState.RUNNING, ScanState.ABORTED, ScanState.FAILED}),
    ScanState.RUNNING: frozenset({ScanState.COMPLETED, ScanState.FAILED, ScanState.ABORTED}),
    ScanState.COMPLETED: frozenset(),
    ScanState.FAILED: frozenset(),
    ScanState.ABORTED: frozenset(),
}


class IllegalTransition(Exception):
    pass


class ScanJob(SQLModel, table=True):
    id: str = Field(default_factory=lambda: uuid.uuid4().hex, primary_key=True)
    created_by: str
    base_url: str
    state: ScanState = ScanState.DRAFT
    scope_definition: dict = Field(sa_column=Column(JSON))
    # sealed snapshot, written exactly once at VERIFIED -> QUEUED
    scope_snapshot: Optional[dict] = Field(default=None, sa_column=Column(JSON))
    engines: list = Field(default_factory=list, sa_column=Column(JSON))
    options: dict = Field(default_factory=dict, sa_column=Column(JSON))
    error: Optional[str] = None
    created_at: datetime = Field(default_factory=utcnow)
    started_at: Optional[datetime] = None
    finished_at: Optional[datetime] = None


def transition(session: Session, job: ScanJob, new: ScanState, actor: str, reason: str = "") -> ScanJob:
    old = ScanState(job.state)
    if new not in TRANSITIONS[old]:
        raise IllegalTransition(f"{old.value} -> {new.value} is not allowed")
    job.state = new
    if new == ScanState.RUNNING:
        job.started_at = utcnow()
    if new in TERMINAL:
        job.finished_at = utcnow()
        if reason and new != ScanState.COMPLETED:
            job.error = reason
    session.add(job)
    session.commit()
    session.refresh(job)
    audit.append(session, actor, "scan.transition", {"job_id": job.id, "from": old.value, "to": new.value, "reason": reason})
    return job
