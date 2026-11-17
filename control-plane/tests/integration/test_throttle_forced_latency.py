"""PRD 9.1 throttle test: inject latency into the real lab and watch the request rate fall."""

import hashlib
import hmac
import time
from datetime import datetime, timedelta, timezone

import httpx

from app.engines.base import RawFinding
from app.orchestrator import service
from app.orchestrator.guarded_client import guarded_client
from app.orchestrator.state import ScanState
from app.orchestrator.throttle import AdaptiveThrottle, ThrottleConfig
from app.scope.snapshot import ScopeDefinition, ScopeSnapshot
from app.scope.verification import self_verify_loopback

from ..conftest import SNAPSHOT_KEY
from ..lab import nimbus

NOW = datetime.now(timezone.utc)


def sealed():
    s = ScopeSnapshot(job_id="job-thr", verified_hosts=("127.0.0.1",), allow_paths=("/",), deny_paths=(),
                      window_start=NOW - timedelta(minutes=5), window_end=NOW + timedelta(hours=1),
                      forbidden_methods=frozenset({"DELETE"}), proof_ref=(1,), captured_at=NOW)
    return s.model_copy(update={"seal": hmac.new(SNAPSHOT_KEY, s.canonical_bytes(), hashlib.sha256).hexdigest()})


CFG = dict(initial_rps=10, max_rps=10, min_rps=0.5, window=4, latency_max_s=0.15, ramp_after=2, abort_after=50)


def hammer(base, n):
    t = AdaptiveThrottle(ThrottleConfig(**CFG))
    with guarded_client(sealed(), SNAPSHOT_KEY, throttle=t) as c:
        for _ in range(n):
            c.get(base + "/health")
    return t


def achieved_rps(sent_at, last_n):
    window = sent_at[-last_n:]
    return (len(window) - 1) / (window[-1] - window[0])


def test_rate_drops_under_injected_latency(tmp_path):
    with nimbus(tmp_path, secure=True) as (base, _):
        healthy = hammer(base, 16)
    with nimbus(tmp_path, secure=True, extra_env={"NIMBUS_INJECT_LATENCY_MS": "400"}) as (base, _):
        stressed = hammer(base, 16)

    assert healthy.rate == 10 and all(h.healthy for h in healthy.history)
    # 4 unhealthy windows: 10 -> 5 -> 2.5 -> 1.25 -> 0.625
    assert stressed.rate < 1.0 and not any(h.healthy for h in stressed.history)
    assert [h.rate for h in stressed.history] == [5.0, 2.5, 1.25, 0.625]
    # measured, not just configured: the stressed tail is sent far slower than the healthy one
    assert achieved_rps(stressed.sent_at, 4) < achieved_rps(healthy.sent_at, 4) / 3


def test_scan_aborts_cleanly_when_target_stays_sick(session, tmp_path):
    class Pinger:
        name = "pinger"

        def run(self, client, scope, ctx):
            out = []
            for _ in range(40):
                try:
                    client.get(ctx.base_url + "/health")
                except httpx.RequestError:
                    break
            out.append(RawFinding(engine="pinger", vuln_class="test", title="t", url=ctx.base_url))
            return out

    with nimbus(tmp_path, secure=True, extra_env={"NIMBUS_INJECT_LATENCY_MS": "300"}) as (base, _):
        self_verify_loopback(session, "127.0.0.1", "op")
        d = ScopeDefinition(hosts=["127.0.0.1"], window_start=NOW - timedelta(minutes=1), window_end=NOW + timedelta(hours=1))
        job = service.create_scan(session, "op", base, d, ["pinger"], registry={"pinger": Pinger},
                                  options={"throttle_config": {"initial_rps": 20, "window": 2, "latency_max_s": 0.1,
                                                               "abort_after": 3, "bogus_key": 1, "max_rps": "x"}})
        job = service.queue_scan(session, job, "op", SNAPSHOT_KEY, lambda _: None)
        started = time.monotonic()
        job = service.execute_scan(session, job.id, SNAPSHOT_KEY, registry={"pinger": Pinger})

    assert job.state == ScanState.ABORTED and "stopping to avoid harm" in job.error
    thr = job.options["throttle"]
    assert thr["aborted"] and thr["requests"] == 6 and len(thr["history"]) == 3
    # it gave up instead of grinding through all 40 requests
    assert time.monotonic() - started < 10
