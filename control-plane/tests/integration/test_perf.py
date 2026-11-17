import hashlib
import hmac
import json
import os
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from sqlmodel import select

from app.orchestrator.throttle import HARD_MAX_CONCURRENCY, HARD_MAX_RPS
from app.perf.k6_runner import (
    MAX_DURATION_S,
    PROFILES,
    PerfRefused,
    Profile,
    format_summary,
    profile_from,
    render_script,
    run_perf,
    subprocess_runner,
)
from app.scope.models import AuditEntry
from app.scope.snapshot import ScopeSnapshot
from app.scope.verification import self_verify_loopback

KEY = b"perf-test-key-0123456789"
NOW = datetime.now(timezone.utc)
BASE = "http://127.0.0.1:8080"

SUMMARY = {"metrics": {
    "http_req_duration": {"avg": 12.34, "med": 10.0, "p(90)": 20.0, "p(95)": 25.55, "max": 80.0},
    "http_req_failed": {"value": 0.0125, "passes": 1, "fails": 79},
    "http_reqs": {"count": 80, "rate": 4.98},
}}


def sealed(**kw):
    base = dict(job_id="perf", verified_hosts=("127.0.0.1",), allow_paths=("/",), deny_paths=("/admin",),
                window_start=NOW - timedelta(minutes=5), window_end=NOW + timedelta(hours=1),
                forbidden_methods=frozenset({"DELETE"}), proof_ref=(1,), captured_at=NOW)
    base.update(kw)
    s = ScopeSnapshot(**base)
    return s.model_copy(update={"seal": hmac.new(KEY, s.canonical_bytes(), hashlib.sha256).hexdigest()})


class FakeK6:
    def __init__(self, code=0, summary=SUMMARY, exc=None):
        self.code, self.summary, self.exc = code, summary, exc
        self.argv = self.env = self.script = None

    def __call__(self, argv, env, timeout):
        if self.exc:
            raise self.exc
        self.argv, self.env = list(argv), env
        self.script = Path(argv[-1]).read_text()
        if self.summary is not None:
            Path(argv[argv.index("--summary-export") + 1]).write_text(json.dumps(self.summary))
        return self.code, "", "boom" if self.code not in (0, 99) else ""


def go(session, runner, **kw):
    args = dict(actor="op", base_url=BASE, paths=["/health", "/openapi.json", "/admin/x"], snapshot=sealed(),
                key=KEY, proxy_url="http://aeroscan-gate:8899", runner=runner)
    args.update(kw)
    return run_perf(session, **args)


def test_refuses_unverified_target(session):
    k6 = FakeK6()
    with pytest.raises(PerfRefused, match="ownership verification"):
        go(session, k6)
    assert k6.argv is None
    assert session.exec(select(AuditEntry).where(AuditEntry.action == "perf.refused")).first()


def test_refuses_unsealed_snapshot_and_bad_proxy(session):
    self_verify_loopback(session, "127.0.0.1", "op")
    with pytest.raises(PerfRefused, match="seal"):
        go(session, FakeK6(), snapshot=sealed().model_copy(update={"seal": ""}))
    with pytest.raises(PerfRefused, match="proxy"):
        go(session, FakeK6(), proxy_url="socks5://x:1")


def test_refuses_when_nothing_in_scope(session):
    self_verify_loopback(session, "127.0.0.1", "op")
    with pytest.raises(PerfRefused, match="in scope"):
        go(session, FakeK6(), paths=["/admin/a", "/admin/b"])


def test_happy_path_scoped_and_capped(session, monkeypatch):
    monkeypatch.setenv("HTTPS_PROXY", "http://evil:1")
    self_verify_loopback(session, "127.0.0.1", "op")
    k6 = FakeK6()
    r = go(session, k6, profile=Profile("x", rps=999, duration_s=99999, vus=99))
    assert r["urls"] == [BASE + "/health", BASE + "/openapi.json"] and r["skipped_out_of_scope"] == 1
    assert "/admin" not in k6.script
    assert f"rate: {int(HARD_MAX_RPS)}," in k6.script and f"maxVUs: {HARD_MAX_CONCURRENCY}" in k6.script
    assert f"duration: '{MAX_DURATION_S}s'" in k6.script and "abortOnFail: true" in k6.script
    assert k6.env["HTTP_PROXY"] == "http://aeroscan-gate:8899" and "HTTPS_PROXY" not in k6.env
    assert r["latency_ms"] == {"avg": 12.3, "p50": 10.0, "p90": 20.0, "p95": 25.6, "max": 80.0}
    assert r["requests"] == 80 and r["error_rate"] == 0.0125 and not r["aborted_by_threshold"]
    actions = [e.action for e in session.exec(select(AuditEntry).order_by(AuditEntry.id))]
    assert actions[-2:] == ["perf.start", "perf.done"]


def test_threshold_abort_is_reported_not_raised(session):
    self_verify_loopback(session, "127.0.0.1", "op")
    r = go(session, FakeK6(code=99))
    assert r["aborted_by_threshold"] is True
    assert "stopped early" in format_summary(r)


@pytest.mark.parametrize("k6,exc", [(FakeK6(code=107), RuntimeError), (FakeK6(exc=FileNotFoundError()), PerfRefused)])
def test_k6_failures(session, k6, exc):
    self_verify_loopback(session, "127.0.0.1", "op")
    with pytest.raises(exc):
        go(session, k6)


def test_missing_summary_file_tolerated(session):
    self_verify_loopback(session, "127.0.0.1", "op")
    r = go(session, FakeK6(summary=None))
    assert r["requests"] == 0 and "p95 0.0" in format_summary(r)


def test_fractional_rate_script():
    s = render_script(["http://h/a"], Profile("slow", rps=0.25, duration_s=10, vus=1))
    assert "rate: 1, timeUnit: '4s'" in s


def test_profiles_and_overrides():
    assert {"smoke", "baseline", "peak"} == set(PROFILES)
    p = profile_from("baseline", {"rps": 500, "name": "hijack", "nonsense": 1})
    assert p.name == "baseline" and p.rps == HARD_MAX_RPS
    with pytest.raises(PerfRefused):
        profile_from("ddos")


def test_real_subprocess_runner():
    code, out, _ = subprocess_runner([sys.executable, "-c", "import os;print(os.environ['X'])"], {**os.environ, "X": "1"}, 10)
    assert code == 0 and out.strip() == "1"
