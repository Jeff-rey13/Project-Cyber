"""Raw engine output, stored as-is before normalisation."""

from dataclasses import asdict
from datetime import datetime
from typing import Optional

from sqlmodel import JSON, Column, Field, Session, SQLModel, select

from ..engines.base import RawFinding
from ..scope.models import utcnow


class RawFindingRow(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    job_id: str = Field(index=True)
    engine: str
    data: dict = Field(sa_column=Column(JSON))
    created_at: datetime = Field(default_factory=utcnow)


def save_raw(session: Session, job_id: str, findings: list[RawFinding]) -> None:
    for f in findings:
        session.add(RawFindingRow(job_id=job_id, engine=f.engine, data=asdict(f)))
    session.commit()


def load_raw(session: Session, job_id: str) -> list[RawFinding]:
    rows = session.exec(select(RawFindingRow).where(RawFindingRow.job_id == job_id).order_by(RawFindingRow.id))
    return [RawFinding(**r.data) for r in rows]
