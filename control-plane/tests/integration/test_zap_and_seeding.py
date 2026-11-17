"""ZAP adapter against a fake zap api, openapi seeding, and the gate proxy over a real socket."""

import hashlib
import hmac
from datetime import datetime, timedelta, timezone
from urllib.parse import parse_qs, urlsplit

import httpx
import pytest

from app.engines.base import ScanContext
from app.engines.openapi_seed import PLACEHOLDER, build_seed_set, seeds_from_openapi
from app.engines.zap_adapter import ZapAdapter, ZapConfig, ZapError, alert_to_finding
from app.orchestrator.gate_proxy import GateProxy
from app.orchestrator.guarded_client import GateStats, guarded_client
from app.scope.snapshot import ScopeSnapshot

KEY = b"zap-test-key-0123456789"
NOW = datetime.now(timezone.utc)

OPENAPI = {
    "openapi": "3.1.0",
    "paths": {
        "/health": {"get": {}},
        "/auth/token": {"post": {"requestBody": {}}},
        "/bookings/{pnr}": {"get": {"parameters": [{"in": "path", "name": "pnr"}, {"in": "header", "name": "authorization"}]}},
        "/bookings/{pnr}/checkin": {"post": {"parameters": [{"in": "header", "name": "authorization"}]}},
        "/admin/purge": {"delete": {}, "get": {}},
        "bogus": {"get": {}},
    },
}


def sealed(**kw):
    base = dict(job_id="job-zap", verified_hosts=("127.0.0.1",), allow_paths=("/",), deny_paths=("/admin",),
                window_start=NOW - timedelta(minutes=5), window_end=NOW + timedelta(hours=1),
                forbidden_methods=frozenset({"DELETE"}), proof_ref=(1,), captured_at=NOW)
    base.update(kw)
    s = ScopeSnapshot(**base)
    return s.model_copy(update={"seal": hmac.new(KEY, s.canonical_bytes(), hashlib.sha256).hexdigest()})


def target_transport(sent):
    def h(req):
        sent.append((req.method, str(req.url)))
        if req.url.path == "/openapi.json":
            return httpx.Response(200, json=OPENAPI)
        return httpx.Response(200, text="target says hi")
    return httpx.MockTransport(h)


# --- seeding ---

def test_seeds_from_openapi_shapes():
    seeds = {(s.method, s.template): s for s in seeds_from_openapi(OPENAPI, "http://127.0.0.1:8080/")}
    assert ("GET", "bogus") not in seeds
    b = seeds[("GET", "/bookings/{pnr}")]
    assert b.url == f"http://127.0.0.1:8080/bookings/{PLACEHOLDER}" and b.requires_auth
    assert seeds[("POST", "/auth/token")].has_body and not seeds[("GET", "/health")].requires_auth


def test_global_security_marks_auth():
    doc = {"security": [{"bearer": []}], "paths": {"/x": {"get": {}}, "/y": {"get": {"security": []}}}}
    s = {x.template: x.requires_auth for x in seeds_from_openapi(doc, "http://h")}
    assert s == {"/x": True, "/y": False}


def test_build_seed_set_drops_out_of_scope_and_fetches_through_gate():
    sent = []
    snap = sealed()
    with guarded_client(snap, KEY, inner_transport=target_transport(sent)) as c:
        seeds = build_seed_set(c, "http://127.0.0.1:8080", snap, KEY)
    templates = {(s.method, s.template) for s in seeds}
    assert ("GET", "/admin/purge") not in templates and ("DELETE", "/admin/purge") not in templates
    assert ("GET", "/bookings/{pnr}") in templates and ("GET", "/") in templates
    assert sent == [("GET", "http://127.0.0.1:8080/openapi.json")]


def test_seed_set_without_openapi():
    snap = sealed()
    with guarded_client(snap, KEY, inner_transport=httpx.MockTransport(lambda r: httpx.Response(404))) as c:
        assert [s.template for s in build_seed_set(c, "http://127.0.0.1", snap, KEY)] == ["/"]


def test_seed_fetch_tolerates_bad_json_and_errors():
    calls = iter([httpx.Response(200, text="not json"), httpx.Response(200, json=["list"])])

    def h(req):
        if req.url.path == "/v3/api-docs":
            raise httpx.ConnectError("nope")
        return next(calls)

    snap = sealed()
    with guarded_client(snap, KEY, inner_transport=httpx.MockTransport(h)) as c:
        assert len(build_seed_set(c, "http://127.0.0.1", snap, KEY)) == 1


# --- fake zap ---

class FakeZap:
    def __init__(self, alerts=None, spider_polls=2, error_on=None, never_finish=False):
        self.calls: list[tuple[str, dict]] = []
        self.alerts = alerts if alerts is not None else [
            {"pluginId": "10038", "alert": "CSP header not set", "risk": "Medium", "confidence": "High",
             "url": "http://127.0.0.1:8080/bookings/AEROSCAN0", "method": "GET", "cweid": "693", "evidence": ""},
            {"pluginId": "40018", "alert": "SQL Injection", "risk": "High", "confidence": "Low",
             "url": "http://127.0.0.1:8080/auth/token", "method": "POST", "param": "email", "cweid": "89"},
        ]
        self._polls = {"spider": spider_polls, "ascan": 1}
        self.error_on = error_on
        self.never_finish = never_finish

    def transport(self):
        def h(req):
            parts = urlsplit(str(req.url)).path.strip("/").split("/")
            _, component, kind, name = parts[:4]
            q = {k: v[0] for k, v in parse_qs(urlsplit(str(req.url)).query).items()}
            self.calls.append((f"{component}.{name}", q))
            if q.get("apikey") != "zk":
                return httpx.Response(403)
            if self.error_on == f"{component}.{name}":
                return httpx.Response(200, json={"code": "bad_param", "message": "nope"})
            if name == "scan":
                return httpx.Response(200, json={"scan": "7"})
            if name == "status":
                if self.never_finish:
                    return httpx.Response(200, json={"status": "10"})
                self._polls[component] -= 1
                return httpx.Response(200, json={"status": "100" if self._polls[component] <= 0 else "40"})
            if name == "alerts":
                start, count = int(q["start"]), int(q["count"])
                return httpx.Response(200, json={"alerts": self.alerts[start:start + count]})
            return httpx.Response(200, json={"Result": "OK"})
        return httpx.MockTransport(h)


def zap(fake, key=KEY, **cfg):
    config = ZapConfig(api_url="http://zap:8090", api_key="zk", upstream_proxy=("aeroscan-gate", 8899), poll_seconds=1, **cfg)
    return ZapAdapter(config, httpx.Client(base_url="http://zap:8090", transport=fake.transport()), sleep=lambda s: None, key=key)


def test_zap_run_sequence_and_mapping():
    fake = FakeZap()
    sent = []
    snap = sealed()
    with guarded_client(snap, KEY, inner_transport=target_transport(sent)) as c:
        findings = zap(fake).run(c, snap, ScanContext(job_id="j", base_url="http://127.0.0.1:8080"))

    names = [n for n, _ in fake.calls]
    assert names[:2] == ["network.setHttpProxy", "network.setHttpProxyEnabled"]
    assert fake.calls[0][1]["host"] == "aeroscan-gate" and fake.calls[0][1]["port"] == "8899"
    accessed = [q["url"] for n, q in fake.calls if n == "core.accessUrl"]
    assert "http://127.0.0.1:8080/admin/purge" not in accessed and f"http://127.0.0.1:8080/bookings/{PLACEHOLDER}" in accessed
    assert names.index("spider.scan") < names.index("ascan.scan") < names.index("core.alerts")

    by_class = {f.vuln_class: f for f in findings}
    assert by_class["sqli"].severity == "high" and by_class["sqli"].confidence == "low" and by_class["sqli"].param == "email"
    assert by_class["missing_security_header"].cwe == 693
    # adapter itself only ever talked to the target to fetch openapi
    assert sent == [("GET", "http://127.0.0.1:8080/openapi.json")]


def test_zap_alert_paging():
    alerts = [{"pluginId": "1", "alert": f"a{i}", "risk": "Low", "url": "http://127.0.0.1/"} for i in range(1200)]
    fake = FakeZap(alerts=alerts)
    assert len(zap(fake).collect_alerts("http://127.0.0.1")) == 1200


def test_zap_error_surfaces():
    with pytest.raises(ZapError):
        zap(FakeZap(error_on="spider.scan"), key=b"").run(None, sealed(), ScanContext(job_id="j", base_url="http://127.0.0.1"))


def test_zap_timeout_stops_scan():
    fake = FakeZap(never_finish=True)
    with pytest.raises(ZapError, match="timed out"):
        zap(fake, key=b"", spider_max_minutes=0).run(None, sealed(), ScanContext(job_id="j", base_url="http://127.0.0.1"))
    assert ("spider.stop", {"scanId": "7", "apikey": "zk"}) in fake.calls


def test_zap_http_error():
    a = ZapAdapter(ZapConfig("http://zap", "wrong", ("g", 1)),
                   httpx.Client(base_url="http://zap", transport=FakeZap().transport()), sleep=lambda s: None)
    with pytest.raises(ZapError, match="403"):
        a.configure_upstream()


@pytest.mark.parametrize("alert,sev,cwe", [
    ({"risk": "Informational", "cweid": "-1"}, "info", None),
    ({"risk": "weird", "cweid": "abc"}, "info", None),
    ({"risk": "High", "cweid": 79}, "high", 79),
])
def test_alert_mapping_edges(alert, sev, cwe):
    f = alert_to_finding(alert)
    assert f.severity == sev and f.cwe == cwe and f.vuln_class.startswith("zap_")


# --- gate proxy over a real socket ---

@pytest.fixture
def proxy():
    sent = []
    stats = GateStats()
    snap = sealed()
    client = guarded_client(snap, KEY, inner_transport=target_transport(sent), stats=stats)
    with GateProxy(client) as p:
        host, port = p.address
        yield httpx.Client(proxy=f"http://{host}:{port}", trust_env=False, timeout=5), sent, stats, (host, port)
    client.close()


def test_proxy_forwards_in_scope(proxy):
    c, sent, stats, _ = proxy
    r = c.get("http://127.0.0.1:8080/bookings/X")
    assert r.status_code == 200 and r.text == "target says hi"
    assert sent == [("GET", "http://127.0.0.1:8080/bookings/X")] and stats.allowed == 1


@pytest.mark.parametrize("method,url", [("GET", "http://evil.com/"), ("GET", "http://127.0.0.1/admin/x"), ("DELETE", "http://127.0.0.1/a")])
def test_proxy_blocks_out_of_scope(proxy, method, url):
    c, sent, stats, _ = proxy
    r = c.request(method, url)
    assert r.status_code == 403 and r.headers["x-aeroscan-gate"] == "deny"
    assert sent == [] and stats.denied == 1


def test_proxy_forwards_body(proxy):
    c, sent, _, _ = proxy
    assert c.post("http://127.0.0.1/auth/token", json={"a": 1}).status_code == 200
    assert sent == [("POST", "http://127.0.0.1/auth/token")]


def test_proxy_refuses_connect_and_relative(proxy):
    import socket

    _, sent, _, (host, port) = proxy
    for line in (b"CONNECT evil.com:443 HTTP/1.1\r\nHost: evil.com\r\n\r\n", b"GET /relative HTTP/1.1\r\nHost: x\r\n\r\n"):
        with socket.create_connection((host, port), timeout=5) as s:
            s.sendall(line)
            head = s.recv(200)
        assert head.split(b" ")[1] in (b"403", b"400")
    assert sent == []


def test_proxy_upstream_error_is_502():
    snap = sealed()

    def h(req):
        raise httpx.ConnectError("target down")

    client = guarded_client(snap, KEY, inner_transport=httpx.MockTransport(h))
    with GateProxy(client) as p:
        host, port = p.address
        with httpx.Client(proxy=f"http://{host}:{port}", trust_env=False) as c:
            assert c.get("http://127.0.0.1/x").status_code == 502
