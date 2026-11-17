"""Scan lifecycle operations. The API and the worker both call these; nothing pokes job state directly."""

from collections.abc import Callable, Mapping
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from typing import Optional

import httpx
from sqlmodel import Session

from ..engines.base import RawFinding, ScanContext
from ..engines.registry import ENGINES, EngineFactory
from ..findings.raw_store import save_raw
from ..scope.domains import canonical_domain
from ..scope.gate import parse_target
from ..scope.snapshot import ScopeDefinition, ScopeSnapshot, capture_snapshot
from ..scope.verification import is_verified
from .guarded_client import GateStats, guarded_client
from .state import ScanJob, ScanState, transition

# hard ceiling, deliberately not configurable (PRD 3.3)
HARD_MAX_ENGINE_CONCURRENCY = 4


class ScanRefused(Exception):
    pass


def _all_verified(session: Session, hosts: list[str]) -> bool:
    return all(is_verified(session, h) for h in hosts)


def create_scan(
    session: Session,
    actor: str,
    base_url: str,
    definition: ScopeDefinition,
    engines: list[str],
    options: Optional[dict] = None,
    registry: Mapping[str, EngineFactory] = ENGINES,
) -> ScanJob:
    try:
        target = parse_target(base_url)
    except ValueError as exc:
        raise ScanRefused(f"bad base url: {exc}") from exc
    hosts = [canonical_domain(h) for h in definition.hosts]
    if target.host not in hosts:
        raise ScanRefused("base url host is not in the requested scope")
    unknown = set(engines) - set(registry)
    if not engines or unknown:
        raise ScanRefused(f"unknown or empty engine list: {sorted(unknown)}")

    job = ScanJob(
        created_by=actor,
        base_url=base_url,
        scope_definition=definition.model_dump(mode="json"),
        engines=list(dict.fromkeys(engines)),
        options=options or {},
    )
    session.add(job)
    session.commit()
    session.refresh(job)
    next_state = ScanState.VERIFIED if _all_verified(session, hosts) else ScanState.PENDING_VERIFICATION
    return transition(session, job, next_state, actor, "created")


def refresh_verification(session: Session, job: ScanJob, actor: str) -> ScanJob:
    if job.state == ScanState.PENDING_VERIFICATION and _all_verified(session, job.scope_definition["hosts"]):
        return transition(session, job, ScanState.VERIFIED, actor, "all hosts verified")
    return job


def queue_scan(session: Session, job: ScanJob, actor: str, key: bytes, enqueue: Callable[[str], None]) -> ScanJob:
    if job.state != ScanState.VERIFIED:
        raise ScanRefused(f"scan is {job.state.value}; only VERIFIED scans can be queued")
    definition = ScopeDefinition.model_validate(job.scope_definition)
    # capture re-checks verification itself, so a revoked host fails here too
    snapshot = capture_snapshot(session, job.id, definition, key, actor)
    job.scope_snapshot = snapshot.model_dump(mode="json")
    job = transition(session, job, ScanState.QUEUED, actor, "snapshot captured")
    enqueue(job.id)
    return job


def abort_scan(session: Session, job: ScanJob, actor: str, reason: str = "aborted by operator") -> ScanJob:
    return transition(session, job, ScanState.ABORTED, actor, reason)


def load_snapshot(job: ScanJob) -> Optional[ScopeSnapshot]:
    if not job.scope_snapshot:
        return None
    return ScopeSnapshot.model_validate(job.scope_snapshot)


def execute_scan(
    session: Session,
    job_id: str,
    key: bytes,
    actor: str = "worker",
    registry: Mapping[str, EngineFactory] = ENGINES,
    inner_transport: Optional[httpx.BaseTransport] = None,
    clock: Optional[Callable[[], datetime]] = None,
    stats: Optional[GateStats] = None,
) -> ScanJob:
    job = session.get(ScanJob, job_id)
    if job is None:
        raise ScanRefused(f"no such job {job_id}")
    if job.state != ScanState.QUEUED:
        # e.g. aborted while waiting in the queue; nothing to do
        return job

    snapshot = load_snapshot(job)
    if snapshot is None or not snapshot.is_sealed_with(key):
        return transition(session, job, ScanState.FAILED, actor, "scope snapshot missing or tampered")

    job = transition(session, job, ScanState.RUNNING, actor, "worker picked up")
    stats = stats or GateStats()
    ctx = ScanContext(job_id=job.id, base_url=job.base_url, identities=job.options.get("identities", []), options=job.options)

    findings: list[RawFinding] = []
    errors: list[str] = []
    try:
        client = guarded_client(snapshot, key, stats=stats, inner_transport=inner_transport, clock=clock)
        with client, ThreadPoolExecutor(max_workers=min(len(job.engines), HARD_MAX_ENGINE_CONCURRENCY)) as pool:
            futures = {pool.submit(registry[name]().run, client, snapshot, ctx): name for name in job.engines}
            for fut in as_completed(futures):
                name = futures[fut]
                try:
                    findings.extend(fut.result())
                except Exception as exc:  # noqa: BLE001 - one engine failing shouldn't sink the others
                    errors.append(f"{name}: {type(exc).__name__}: {exc}")
    except Exception as exc:  # noqa: BLE001
        return transition(session, job, ScanState.FAILED, actor, f"runner error: {type(exc).__name__}: {exc}")

    save_raw(session, job.id, findings)
    job.options = {**job.options, "gate_stats": stats.as_dict(), "engine_errors": errors}
    session.add(job)
    session.commit()

    if errors and len(errors) == len(job.engines):
        return transition(session, job, ScanState.FAILED, actor, "; ".join(errors))
    return transition(session, job, ScanState.COMPLETED, actor, f"{len(findings)} raw findings")

