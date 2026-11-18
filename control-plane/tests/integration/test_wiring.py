"""Gate proxy lifecycle inside a scan, env-driven engine registration, and app bootstrap."""

from datetime import datetime, timedelta, timezone

import httpx
import pytest
from sqlmodel import Session, select

from app import config
from app.config import Settings
from app.engines import registry
from app.engines.base import RawFinding
from app.orchestrator import service
from app.orchestrator.state import ScanState
from app.scope.models import Verification
from app.scope.snapshot import ScopeDefinition
from app.scope.verification import self_verify_loopback

from ..conftest import SNAPSHOT_KEY

NOW = datetime.now(timezone.utc)


class ExternalLike:
    """Behaves like zap/nuclei: no python client, only the proxy address."""

    name = "external"
    needs_gate_proxy = True

    def run(self, client, scope, ctx):
        proxy = ctx.options["gate_proxy"]
        with httpx.Client(proxy=proxy, trust_env=False, timeout=5) as c:
            ok = c.get("http://127.0.0.1/bookings/X").status_code
            blocked = c.get("http://evil.com/").status_code
        return [RawFinding(engine="external", vuln_class="test", title="t", url="http://127.0.0.1/",
                           extra={"ok": ok, "blocked": blocked})]


def test_external_engine_goes_through_proxy_only_during_scan(session):
    sent = []

    def target(req):
        sent.append(str(req.url))
        return httpx.Response(200)

    self_verify_loopback(session, "127.0.0.1", "op")
    d = ScopeDefinition(hosts=["127.0.0.1"], window_start=NOW - timedelta(minutes=1), window_end=NOW + timedelta(hours=1))
    reg = {"external": ExternalLike}
    job = service.create_scan(session, "op", "http://127.0.0.1", d, ["external"], registry=reg)
    job = service.queue_scan(session, job, "op", SNAPSHOT_KEY, lambda _: None)
    job = service.execute_scan(session, job.id, SNAPSHOT_KEY, registry=reg, inner_transport=httpx.MockTransport(target))

    assert job.state == ScanState.COMPLETED
    raw = job.options["gate_stats"]
    assert raw["allowed"] == 1 and raw["denied"] == 1
    assert sent == ["http://127.0.0.1/bookings/X"]
    from app.findings.raw_store import load_raw

    (f,) = load_raw(session, job.id)
    assert f.extra == {"ok": 200, "blocked": 403}

    # proxy is gone once the scan is over
    with pytest.raises(httpx.HTTPError):
        httpx.get("http://evil.com/", proxy=job.options["gate_proxy"], timeout=1)


def settings(**kw):
    base = dict(database_url="sqlite://", redis_url="redis://x", snapshot_key=SNAPSHOT_KEY, operator_token="t" * 20)
    base.update(kw)
    return Settings(**base)


def test_register_from_settings(monkeypatch):
    monkeypatch.setattr(registry, "ENGINES", dict(registry.ENGINES))
    registry.register_from_settings(settings())
    assert "zap" not in registry.ENGINES and "nuclei" not in registry.ENGINES

    registry.register_from_settings(settings(zap_api_url="http://zap:8090", zap_api_key="k" * 20, nuclei_binary="nuclei",
                                             gate_proxy_public_host="worker", gate_proxy_port=8899))
    z = registry.ENGINES["zap"]()
    n = registry.ENGINES["nuclei"]()
    assert z.cfg.upstream_proxy == ("worker", 8899) and z.needs_gate_proxy
    assert n.cfg.proxy_url == "http://127.0.0.1:8899" and n.needs_gate_proxy

    with pytest.raises(ValueError):
        registry.register_from_settings(settings(zap_api_url="http://zap:8090", zap_api_key="change-me"))


def test_bootstrap_self_verifies_lab_only_when_asked(monkeypatch, tmp_path):
    import importlib

    from app.db import make_engine

    db = tmp_path / "boot.db"
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{db.as_posix()}")
    monkeypatch.setenv("SQUAWK_SNAPSHOT_KEY", SNAPSHOT_KEY.decode())
    monkeypatch.setenv("SQUAWK_OPERATOR_TOKEN", "operator-token-0123456789")
    monkeypatch.setenv("REDIS_URL", "redis://localhost:1/0")

    for flag, expected in (("false", 0), ("true", 1)):
        monkeypatch.setenv("SQUAWK_LAB_SELF_VERIFY", flag)
        config.get_settings.cache_clear()
        import app.main as main

        importlib.reload(main)
        with Session(make_engine(f"sqlite:///{db.as_posix()}")) as s:
            rows = s.exec(select(Verification)).all()
        assert len(rows) == expected
    assert rows[0].domain == "127.0.0.1" and rows[0].proof["method"] == "loopback"
    config.get_settings.cache_clear()
