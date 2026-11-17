"""Builds the /metrics document the dashboard reads. Everything comes from stored scan data."""

from collections import Counter
from typing import Optional

from sqlmodel import Session, select

from ..compliance import mapper
from ..engines.base import SEVERITIES
from ..findings.store import Finding, findings_for
from ..orchestrator.state import ScanJob, ScanState
from ..scope.models import AuditEntry

# summed risk (each finding 0..20) at which posture reads 0. tuned on the bundled lab: the broken
# build lands around 30, the fixed build in the 90s, so the gauge moves visibly between them.
POSTURE_RISK_BUDGET = 100.0


def posture_score(findings: list[Finding]) -> int:
    total = sum(f.risk_score for f in findings)
    return max(0, round(100 * (1 - min(1.0, total / POSTURE_RISK_BUDGET))))


def _latest_finished(session: Session) -> Optional[ScanJob]:
    stmt = (
        select(ScanJob)
        .where(ScanJob.state.in_([ScanState.COMPLETED, ScanState.ABORTED, ScanState.FAILED]))
        .order_by(ScanJob.finished_at.desc())
    )
    return session.exec(stmt).first()


def build_metrics(session: Session, job_id: Optional[str] = None) -> dict:
    job = session.get(ScanJob, job_id) if job_id else _latest_finished(session)
    jobs = session.exec(select(ScanJob)).all()
    findings = findings_for(session, job.id) if job else []

    by_sev = Counter(f.severity for f in findings)
    by_engine = Counter(src for f in findings for src in f.sources)
    gate_totals = {"allowed": 0, "denied": 0, "deny_reasons": Counter()}
    for j in jobs:
        g = (j.options or {}).get("gate_stats") or {}
        gate_totals["allowed"] += g.get("allowed", 0)
        gate_totals["denied"] += g.get("denied", 0)
        gate_totals["deny_reasons"].update(g.get("deny_reasons", {}))
    # verification/scope refusals happen before any request exists, so count them from the audit log
    refusals = len(session.exec(select(AuditEntry).where(AuditEntry.action.in_(
        ["scope.refused", "verification.loopback_refused", "scan.refused"]))).all())

    return {
        "scan": None if not job else {
            "id": job.id, "state": job.state.value, "base_url": job.base_url, "error": job.error,
            "started_at": job.started_at.isoformat() if job.started_at else None,
            "finished_at": job.finished_at.isoformat() if job.finished_at else None,
            "engines": job.engines, "engine_errors": (job.options or {}).get("engine_errors", []),
        },
        "posture_score": posture_score(findings) if job else None,
        "findings": {
            "total": len(findings),
            "by_severity": {s: by_sev.get(s, 0) for s in reversed(SEVERITIES)},
            "by_engine": dict(by_engine),
            "multi_engine": sum(1 for f in findings if len(f.sources) > 1),
            "top": [
                {"rank": f.rank, "title": f.title, "vuln_class": f.vuln_class, "severity": f.severity,
                 "risk_score": f.risk_score, "url_template": f.url_template, "sources": f.sources,
                 "owasp": (f.frameworks or {}).get("owasp", [])[:1]}
                for f in findings[:10]
            ],
        },
        "compliance": mapper.coverage(findings),
        "throttle": (job.options or {}).get("throttle") if job else None,
        "gate": {
            "allowed": gate_totals["allowed"],
            "denied": gate_totals["denied"],
            "deny_reasons": dict(gate_totals["deny_reasons"]),
            "pre_scan_refusals": refusals,
        },
        "scans": dict(Counter(j.state.value for j in jobs)),
    }
