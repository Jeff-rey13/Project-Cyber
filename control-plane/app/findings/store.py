"""Normalized findings table (PRD 7) and the job-level normalize step."""

from datetime import datetime
from typing import Optional

from sqlmodel import JSON, Column, Field, Session, SQLModel, select

from ..scope.models import utcnow
from .normalize import EndpointContext, correlate, rank
from .raw_store import load_raw


class Finding(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    job_id: str = Field(index=True)
    fingerprint: str = Field(index=True)
    vuln_class: str
    title: str
    description: str = ""
    url_template: str
    param: Optional[str] = None
    method: str = "GET"
    severity: str
    cvss_base: float
    risk_score: float
    risk_factors: dict = Field(default_factory=dict, sa_column=Column(JSON))
    confidence: str
    sources: list = Field(default_factory=list, sa_column=Column(JSON))
    cwe: Optional[int] = None
    evidence_redacted: str = ""
    frameworks: dict = Field(default_factory=dict, sa_column=Column(JSON))
    remediation: str = ""
    extra: dict = Field(default_factory=dict, sa_column=Column(JSON))
    rank: int = 0
    first_seen: datetime = Field(default_factory=utcnow)
    last_seen: datetime = Field(default_factory=utcnow)


def normalize_job(session: Session, job_id: str, contexts: Optional[dict[str, EndpointContext]] = None) -> list[Finding]:
    """Rebuild this job's normalized findings from its raw rows. Safe to re-run."""
    for old in session.exec(select(Finding).where(Finding.job_id == job_id)):
        session.delete(old)
    session.commit()

    ranked = rank(correlate(load_raw(session, job_id)), contexts)
    now = utcnow()
    rows = []
    for i, m in enumerate(ranked, start=1):
        earlier = session.exec(
            select(Finding).where(Finding.fingerprint == m.fingerprint, Finding.job_id != job_id).order_by(Finding.first_seen)
        ).first()
        rows.append(Finding(
            job_id=job_id, fingerprint=m.fingerprint, vuln_class=m.vuln_class, title=m.title, description=m.description,
            url_template=m.url_template, param=m.param, method=m.method, severity=m.severity, cvss_base=m.cvss_base,
            risk_score=m.risk_score, risk_factors=m.risk_factors, confidence=m.confidence, sources=m.sources, cwe=m.cwe,
            evidence_redacted=m.evidence, extra=m.extra, rank=i,
            first_seen=earlier.first_seen if earlier else now, last_seen=now,
        ))
    session.add_all(rows)
    session.commit()
    for r in rows:
        session.refresh(r)
    return rows


def findings_for(session: Session, job_id: str) -> list[Finding]:
    return list(session.exec(select(Finding).where(Finding.job_id == job_id).order_by(Finding.rank)))
