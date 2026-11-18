"""Control API (PRD 4.2, 6.2, 8). Every route except /health needs the operator token."""

import hmac
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any, Optional

from fastapi import APIRouter, Depends, FastAPI, Header, HTTPException, status
from fastapi.responses import RedirectResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field, ValidationError
from sqlmodel import Session, select

from ..config import Settings
from ..db import init_db
from ..engines.registry import ENGINES
from ..findings.store import findings_for
from ..orchestrator import service
from ..orchestrator.state import IllegalTransition, ScanJob
from ..scope import audit
from ..scope.domains import InvalidDomain
from ..scope.models import Verification, VerificationMethod, VerificationStatus
from ..scope.snapshot import ScopeDefinition, ScopeError
from ..scope import verification as verif
from .metrics import build_metrics

DASHBOARD_DIR = Path(__file__).resolve().parents[3] / "dashboard"


class BeginVerification(BaseModel):
    method: VerificationMethod = VerificationMethod.DNS_TXT


class ScanRequest(BaseModel):
    base_url: str
    scope: dict[str, Any]
    engines: list[str] = Field(min_length=1)
    options: dict[str, Any] = Field(default_factory=dict)


def _job_view(job: ScanJob) -> dict:
    opts = dict(job.options or {})
    # credentials for test identities go in, never come back out
    if "identities" in opts:
        opts["identities"] = [{k: v for k, v in i.items() if k not in {"password", "token"}} for i in opts["identities"]]
    return {
        "id": job.id, "state": job.state.value, "base_url": job.base_url, "engines": job.engines,
        "created_by": job.created_by, "error": job.error, "scope_definition": job.scope_definition,
        "scope_snapshot": job.scope_snapshot, "options": opts,
        "created_at": job.created_at, "started_at": job.started_at, "finished_at": job.finished_at,
    }


def create_api(settings: Settings, engine, enqueue: Callable[[str], None]) -> FastAPI:
    init_db(engine)
    app = FastAPI(title="Squawk control API", version="1.0.0")

    def get_session() -> Iterator[Session]:
        with Session(engine) as s:
            yield s

    def operator(authorization: Optional[str] = Header(default=None)) -> str:
        presented = (authorization or "").removeprefix("Bearer ").strip()
        if not presented or not hmac.compare_digest(presented.encode(), settings.operator_token.encode()):
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, "operator token required", headers={"WWW-Authenticate": "Bearer"})
        return "operator"

    r = APIRouter(dependencies=[Depends(operator)])

    @app.get("/health")
    def health():
        return {"status": "ok"}

    # --- targets / verification ---

    @r.post("/targets/{domain}/verification")
    def begin(domain: str, body: BeginVerification, s: Session = Depends(get_session), who: str = Depends(operator)):
        try:
            v, instruction = verif.begin_verification(s, domain, who, body.method)
        except (InvalidDomain, verif.VerificationError) as exc:
            raise HTTPException(400, str(exc)) from exc
        return {"domain": v.domain, "method": v.method.value, "instruction": instruction, "expires_at": v.expires_at}

    @r.post("/targets/{domain}/verification/check")
    def check(domain: str, s: Session = Depends(get_session), who: str = Depends(operator)):
        try:
            ok = verif.check_verification(s, domain, who)
        except InvalidDomain as exc:
            raise HTTPException(400, str(exc)) from exc
        return {"domain": domain, "verified": ok}

    @r.post("/targets/{host}/self-verify")
    def self_verify(host: str, s: Session = Depends(get_session), who: str = Depends(operator)):
        try:
            v = verif.self_verify_loopback(s, host, who)
        except (InvalidDomain, verif.VerificationError) as exc:
            raise HTTPException(400, str(exc)) from exc
        return {"domain": v.domain, "verified": True, "proof": v.proof}

    @r.get("/targets")
    def targets(s: Session = Depends(get_session)):
        rows = s.exec(select(Verification).where(Verification.status == VerificationStatus.VERIFIED))
        return [{"domain": v.domain, "method": v.method.value, "verified_at": v.verified_at, "proof": v.proof} for v in rows]

    # --- scans ---

    @r.post("/scans", status_code=201)
    def create(body: ScanRequest, s: Session = Depends(get_session), who: str = Depends(operator)):
        try:
            definition = ScopeDefinition.model_validate(body.scope)
            job = service.create_scan(s, who, body.base_url, definition, body.engines, body.options, registry=ENGINES)
        except ValidationError as exc:
            raise HTTPException(422, exc.errors(include_url=False, include_context=False)) from exc
        except (service.ScanRefused, InvalidDomain) as exc:
            audit.append(s, who, "scan.refused", {"base_url": body.base_url, "reason": str(exc)})
            raise HTTPException(400, str(exc)) from exc
        return _job_view(job)

    def _job(s: Session, job_id: str) -> ScanJob:
        job = s.get(ScanJob, job_id)
        if not job:
            raise HTTPException(404, "no such scan")
        return job

    @r.get("/scans")
    def list_scans(s: Session = Depends(get_session)):
        return [_job_view(j) for j in s.exec(select(ScanJob).order_by(ScanJob.created_at.desc()))]

    @r.get("/scans/{job_id}")
    def get_scan(job_id: str, s: Session = Depends(get_session)):
        return _job_view(_job(s, job_id))

    @r.post("/scans/{job_id}/refresh")
    def refresh(job_id: str, s: Session = Depends(get_session), who: str = Depends(operator)):
        return _job_view(service.refresh_verification(s, _job(s, job_id), who))

    @r.post("/scans/{job_id}/queue")
    def queue(job_id: str, s: Session = Depends(get_session), who: str = Depends(operator)):
        job = _job(s, job_id)
        try:
            job = service.queue_scan(s, job, who, settings.snapshot_key, enqueue)
        except (service.ScanRefused, ScopeError) as exc:
            audit.append(s, who, "scan.refused", {"job_id": job_id, "reason": str(exc)})
            raise HTTPException(409, str(exc)) from exc
        return _job_view(job)

    @r.post("/scans/{job_id}/abort")
    def abort(job_id: str, s: Session = Depends(get_session), who: str = Depends(operator)):
        try:
            return _job_view(service.abort_scan(s, _job(s, job_id), who))
        except IllegalTransition as exc:
            raise HTTPException(409, str(exc)) from exc

    @r.get("/scans/{job_id}/findings")
    def findings(job_id: str, s: Session = Depends(get_session)):
        _job(s, job_id)
        return [f.model_dump() for f in findings_for(s, job_id)]

    # --- audit / metrics ---

    @r.get("/audit/verify")
    def audit_verify(s: Session = Depends(get_session)):
        bad = audit.verify_chain(s)
        return {"intact": bad is None, "first_bad_entry": bad}

    @r.get("/metrics")
    def metrics(job_id: Optional[str] = None, s: Session = Depends(get_session)):
        return build_metrics(s, job_id)

    app.include_router(r)

    if DASHBOARD_DIR.is_dir():
        # static files only; the page asks for the operator token and calls /metrics itself
        app.mount("/dashboard", StaticFiles(directory=DASHBOARD_DIR, html=True), name="dashboard")

        @app.get("/", include_in_schema=False)
        def root():
            return RedirectResponse("/dashboard/")

    return app
