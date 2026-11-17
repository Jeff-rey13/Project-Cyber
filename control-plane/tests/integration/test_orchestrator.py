"""State machine, lifecycle and queue. Engines here are fakes; real adapters come later."""

import itertools
from datetime import datetime, timedelta, timezone

import httpx
import pytest
from fakeredis import FakeRedis
from sqlmodel import Session, select

from app.engines.base import RawFinding
from app.findings.raw_store import load_raw
from app.orchestrator import service, worker
from app.orchestrator.guarded_client import ScopeViolation
from app.orchestrator.state import TRANSITIONS, IllegalTransition, ScanJob, ScanState, transition
from app.scope import audit
from app.scope.models import AuditEntry
from app.scope.snapshot import ScopeDefinition, ScopeSnapshot
from app.scope.verification import begin_verification, check_verification, self_verify_loopback

from ..conftest import SNAPSHOT_KEY

OP = "operator"
NOW = datetime.now(timezone.utc)
IN_WINDOW = lambda: NOW + timedelta(minutes=1)  # noqa: E731


def definition(hosts=("127.0.0.1",)):
    return ScopeDefinition(hosts=list(hosts), window_start=NOW - timedelta(minutes=5), window_end=NOW + timedelta(hours=1))


class ProbeEngine:
    """Hits one in-scope url and one out-of-scope url, reports what happened."""

    name = "probe"

    def run(self, client, scope, ctx):
        ok = client.get(ctx.base_url + "/bookings/ABC123")
        try:
            client.get("http://evil.com/exfil")
            escaped = True
        except ScopeViolation:
            escaped = False
        return [RawFinding(engine="probe", vuln_class="test", title="probe", url=str(ok.request.url),
                           severity="low", extra={"escaped": escaped})]


class BrokenEngine:
    name = "broken"

    def run(self, client, scope, ctx):
        raise RuntimeError("engine fell over")


REGISTRY = {"probe": ProbeEngine, "broken": BrokenEngine}


class Wire:
    def __init__(self):
        self.sent = []

    def transport(self):
        def h(req):
            self.sent.append(str(req.url))
            return httpx.Response(200, json={"ok": True})
        return httpx.MockTransport(h)


def make_job(session, engines=("probe",), hosts=("127.0.0.1",)):
    return service.create_scan(session, OP, "http://127.0.0.1:8080", definition(hosts), list(engines), registry=REGISTRY)


# --- state machine ---

@pytest.mark.parametrize("src,dst", [(s, d) for s, d in itertools.product(ScanState, ScanState) if d not in TRANSITIONS[s]])
def test_illegal_transitions_raise(session, src, dst):
    job = ScanJob(created_by=OP, base_url="http://127.0.0.1", scope_definition={}, state=src)
    session.add(job)
    session.commit()
    with pytest.raises(IllegalTransition):
        transition(session, job, dst, OP)


def test_terminal_states_have_no_exits():
    for s in (ScanState.COMPLETED, ScanState.FAILED, ScanState.ABORTED):
        assert TRANSITIONS[s] == frozenset()


def test_transitions_are_audited(session):
    self_verify_loopback(session, "127.0.0.1", OP)
    job = make_job(session)
    entries = session.exec(select(AuditEntry).where(AuditEntry.action == "scan.transition")).all()
    assert [(e.detail["from"], e.detail["to"]) for e in entries] == [("DRAFT", "VERIFIED")]
    assert job.state == ScanState.VERIFIED


# --- lifecycle ---

def test_unverified_target_cannot_be_queued(session):
    job = service.create_scan(session, OP, "http://nimbus.test", definition(("nimbus.test",)), ["probe"], registry=REGISTRY)
    assert job.state == ScanState.PENDING_VERIFICATION
    enqueued = []
    with pytest.raises(service.ScanRefused):
        service.queue_scan(session, job, OP, SNAPSHOT_KEY, enqueued.append)
    assert enqueued == [] and job.scope_snapshot is None


def test_pending_becomes_verified_after_proof(session):
    job = service.create_scan(session, OP, "http://nimbus.test", definition(("nimbus.test",)), ["probe"], registry=REGISTRY)
    assert service.refresh_verification(session, job, OP).state == ScanState.PENDING_VERIFICATION
    v, _ = begin_verification(session, "nimbus.test", OP)
    check_verification(session, "nimbus.test", OP, txt_lookup=lambda n: [v.token])
    assert service.refresh_verification(session, job, OP).state == ScanState.VERIFIED


@pytest.mark.parametrize("base_url,engines", [
    ("http://evil.com", ["probe"]),            # base host outside scope
    ("ftp://127.0.0.1", ["probe"]),            # bad scheme
    ("http://127.0.0.1", []),                  # no engines
    ("http://127.0.0.1", ["probe", "nope"]),   # unknown engine
])
def test_create_refuses_bad_requests(session, base_url, engines):
    with pytest.raises(service.ScanRefused):
        service.create_scan(session, OP, base_url, definition(), engines, registry=REGISTRY)


def test_full_run_completes_and_gate_holds(session):
    self_verify_loopback(session, "127.0.0.1", OP)
    job = make_job(session)
    queued = []
    job = service.queue_scan(session, job, OP, SNAPSHOT_KEY, queued.append)
    assert queued == [job.id] and job.state == ScanState.QUEUED
    assert ScopeSnapshot.model_validate(job.scope_snapshot).is_sealed_with(SNAPSHOT_KEY)

    wire = Wire()
    job = service.execute_scan(session, job.id, SNAPSHOT_KEY, registry=REGISTRY, inner_transport=wire.transport(), clock=IN_WINDOW)
    assert job.state == ScanState.COMPLETED
    assert wire.sent == ["http://127.0.0.1:8080/bookings/ABC123"]
    raw = load_raw(session, job.id)
    assert len(raw) == 1 and raw[0].extra["escaped"] is False
    assert job.options["gate_stats"] == {"allowed": 1, "denied": 1, "deny_reasons": {"host not verified": 1}}
    assert audit.verify_chain(session) is None


def test_one_engine_failing_does_not_sink_the_scan(session):
    self_verify_loopback(session, "127.0.0.1", OP)
    job = service.queue_scan(session, make_job(session, engines=("probe", "broken")), OP, SNAPSHOT_KEY, lambda _: None)
    job = service.execute_scan(session, job.id, SNAPSHOT_KEY, registry=REGISTRY, inner_transport=Wire().transport(), clock=IN_WINDOW)
    assert job.state == ScanState.COMPLETED
    assert job.options["engine_errors"] == ["broken: RuntimeError: engine fell over"]


def test_all_engines_failing_fails_the_scan(session):
    self_verify_loopback(session, "127.0.0.1", OP)
    job = service.queue_scan(session, make_job(session, engines=("broken",)), OP, SNAPSHOT_KEY, lambda _: None)
    job = service.execute_scan(session, job.id, SNAPSHOT_KEY, registry=REGISTRY, inner_transport=Wire().transport(), clock=IN_WINDOW)
    assert job.state == ScanState.FAILED and "engine fell over" in job.error


def test_tampered_snapshot_fails_before_any_request(session):
    self_verify_loopback(session, "127.0.0.1", OP)
    job = service.queue_scan(session, make_job(session), OP, SNAPSHOT_KEY, lambda _: None)
    job.scope_snapshot = {**job.scope_snapshot, "verified_hosts": ["127.0.0.1", "evil.com"]}
    session.add(job)
    session.commit()
    wire = Wire()
    job = service.execute_scan(session, job.id, SNAPSHOT_KEY, registry=REGISTRY, inner_transport=wire.transport(), clock=IN_WINDOW)
    assert job.state == ScanState.FAILED and "tampered" in job.error
    assert wire.sent == []


def test_aborted_while_queued_is_skipped(session):
    self_verify_loopback(session, "127.0.0.1", OP)
    job = service.queue_scan(session, make_job(session), OP, SNAPSHOT_KEY, lambda _: None)
    service.abort_scan(session, job, OP)
    wire = Wire()
    job = service.execute_scan(session, job.id, SNAPSHOT_KEY, registry=REGISTRY, inner_transport=wire.transport())
    assert job.state == ScanState.ABORTED and wire.sent == []


def test_execute_unknown_job(session):
    with pytest.raises(service.ScanRefused):
        service.execute_scan(session, "nope", SNAPSHOT_KEY, registry=REGISTRY)


def test_runner_level_error_fails_scan(session, monkeypatch):
    self_verify_loopback(session, "127.0.0.1", OP)
    job = service.queue_scan(session, make_job(session), OP, SNAPSHOT_KEY, lambda _: None)

    def boom(*a, **k):
        raise OSError("no sockets left")

    monkeypatch.setattr(service, "guarded_client", boom)
    job = service.execute_scan(session, job.id, SNAPSHOT_KEY, registry=REGISTRY)
    assert job.state == ScanState.FAILED and "no sockets left" in job.error


def test_engine_concurrency_capped(session):
    import threading
    import time

    live, peak, lock = [0], [0], threading.Lock()

    class Slow:
        name = "slow"

        def run(self, client, scope, ctx):
            with lock:
                live[0] += 1
                peak[0] = max(peak[0], live[0])
            time.sleep(0.05)
            with lock:
                live[0] -= 1
            return []

    reg = {f"slow{i}": Slow for i in range(8)}
    self_verify_loopback(session, "127.0.0.1", OP)
    job = service.create_scan(session, OP, "http://127.0.0.1", definition(), list(reg), registry=reg)
    job = service.queue_scan(session, job, OP, SNAPSHOT_KEY, lambda _: None)
    service.execute_scan(session, job.id, SNAPSHOT_KEY, registry=reg, inner_transport=Wire().transport())
    assert peak[0] <= service.HARD_MAX_ENGINE_CONCURRENCY


# --- rq ---

def test_rq_round_trip(tmp_path, monkeypatch):
    from app import config
    from app.db import init_db, make_engine

    db = tmp_path / "rq.db"
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{db.as_posix()}")
    monkeypatch.setenv("AEROSCAN_SNAPSHOT_KEY", SNAPSHOT_KEY.decode())
    monkeypatch.setenv("AEROSCAN_OPERATOR_TOKEN", "operator-token-0123456789")
    config.get_settings.cache_clear()
    monkeypatch.setitem(service.ENGINES, "probe", ProbeEngine)

    engine = make_engine(f"sqlite:///{db.as_posix()}")
    init_db(engine)
    with Session(engine) as s:
        self_verify_loopback(s, "127.0.0.1", OP)
        job = make_job(s)
        q = worker.make_queue(FakeRedis(), is_async=False)
        # no live target in this test, so the probe's request fails and the engine errors out;
        # what matters is that rq ran our function end to end through the real lifecycle
        service.queue_scan(s, job, OP, SNAPSHOT_KEY, worker.enqueuer(q))
        s.expire_all()
        final = s.get(ScanJob, job.id)
    assert final.state in (ScanState.COMPLETED, ScanState.FAILED)
    assert final.started_at is not None and final.finished_at is not None
    config.get_settings.cache_clear()


def test_config_fails_closed(monkeypatch):
    from app import config

    monkeypatch.setenv("AEROSCAN_SNAPSHOT_KEY", "change-me")
    monkeypatch.setenv("AEROSCAN_OPERATOR_TOKEN", "operator-token-0123456789")
    config.get_settings.cache_clear()
    with pytest.raises(config.ConfigError):
        config.get_settings()
    config.get_settings.cache_clear()


