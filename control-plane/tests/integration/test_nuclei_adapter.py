import json
import subprocess

import pytest

from app.engines.base import ScanContext
from app.engines.nuclei_adapter import (
    DEFAULT_TEMPLATES,
    HARD_MAX_CONCURRENCY,
    HARD_MAX_RPS,
    NucleiAdapter,
    NucleiConfig,
    NucleiError,
    parse_jsonl,
    record_to_finding,
    subprocess_runner,
)

CTX = ScanContext(job_id="j", base_url="http://127.0.0.1:8080")

HIT = {
    "template-id": "aeroscan-openapi-schema-exposed",
    "info": {"name": "OpenAPI schema publicly exposed", "severity": "low", "tags": ["exposure", "openapi"],
             "classification": {"cwe-id": ["cwe-200"]}, "description": "d"},
    "matched-at": "http://127.0.0.1:8080/openapi.json",
    "matcher-name": "",
    "extracted-results": ["3.1.0"],
}


class FakeRunner:
    def __init__(self, code=0, out="", err="", exc=None):
        self.argv = None
        self.result = (code, out, err)
        self.exc = exc

    def __call__(self, argv, timeout):
        self.argv = list(argv)
        if self.exc:
            raise self.exc
        return self.result


def adapter(runner, **kw):
    return NucleiAdapter(NucleiConfig(proxy_url="http://aeroscan-gate:8899", **kw), runner=runner)


def test_argv_forces_safety_flags_and_caps():
    r = FakeRunner(out=json.dumps(HIT) + "\n")
    adapter(r, rate_limit=500, concurrency=50, variables={"pnr": "ABC123"}).run(None, None, CTX)
    a = r.argv
    assert a[a.index("-proxy") + 1] == "http://aeroscan-gate:8899"
    assert "-no-interactsh" in a and "-duc" in a
    assert int(a[a.index("-rl") + 1]) == HARD_MAX_RPS and int(a[a.index("-c") + 1]) == HARD_MAX_CONCURRENCY
    assert a[a.index("-u") + 1] == CTX.base_url and a[a.index("-var") + 1] == "pnr=ABC123"
    assert a[a.index("-t") + 1] == str(DEFAULT_TEMPLATES)


def test_refuses_without_http_proxy():
    with pytest.raises(NucleiError):
        NucleiAdapter(NucleiConfig(proxy_url="socks5://x:1"), runner=FakeRunner()).run(None, None, CTX)


@pytest.mark.parametrize("variables", [{"pnr": "-u http://evil"}, {"bad key": "x"}])
def test_refuses_flag_like_variables(variables):
    with pytest.raises(NucleiError):
        adapter(FakeRunner(), variables=variables).argv(CTX.base_url)


def test_parse_maps_fields():
    f = parse_jsonl("[INF] banner line\n" + json.dumps(HIT) + "\n{broken json\n\n")
    assert len(f) == 1
    f = f[0]
    assert (f.engine, f.vuln_class, f.severity, f.cwe, f.confidence) == ("nuclei", "api_inventory_exposure", "low", 200, "high")
    assert f.url.endswith("/openapi.json") and f.evidence == "3.1.0"


@pytest.mark.parametrize("info,cls,sev,cwe", [
    ({"severity": "critical", "tags": "auth-bypass,airline", "classification": {"cwe-id": "CWE-306"}}, "broken_auth", "critical", 306),
    ({"severity": "unknown", "tags": None, "classification": {"cwe-id": ["nope"]}}, "nuclei_x", "info", None),
    ({"severity": "medium", "tags": ["misconfig"]}, "security_misconfiguration", "medium", None),
])
def test_record_mapping_edges(info, cls, sev, cwe):
    f = record_to_finding({"template-id": "x", "info": info, "host": "http://h", "request": "POST /a HTTP/1.1"})
    assert (f.vuln_class, f.severity, f.cwe, f.method) == (cls, sev, cwe, "POST")


@pytest.mark.parametrize("runner,match", [
    (FakeRunner(code=1, err="templates not found"), "exited 1"),
    (FakeRunner(exc=FileNotFoundError()), "not found"),
    (FakeRunner(exc=subprocess.TimeoutExpired("nuclei", 1)), "timed out"),
])
def test_failures_raise(runner, match):
    with pytest.raises(NucleiError, match=match):
        adapter(runner).run(None, None, CTX)


def test_real_subprocess_runner():
    import sys

    code, out, _ = subprocess_runner([sys.executable, "-c", "print('hi')"], 10)
    assert code == 0 and out.strip() == "hi"


def test_bundled_templates_present():
    names = {p.name for p in DEFAULT_TEMPLATES.glob("*.yaml")}
    assert {"openapi-schema-exposed.yaml", "missing-security-headers.yaml", "booking-lookup-unauthenticated.yaml"} <= names


def test_pnr_variable_borrowed_from_first_identity():
    r = FakeRunner(out="")
    ctx = ScanContext(job_id="j", base_url=CTX.base_url, identities=[{"label": "a", "objects": ["Q7X2KD"], "markers": ["m"]}])
    adapter(r).run(None, None, ctx)
    assert r.argv[r.argv.index("-var") + 1] == "pnr=Q7X2KD"


def test_explicit_pnr_variable_wins():
    r = FakeRunner(out="")
    ctx = ScanContext(job_id="j", base_url=CTX.base_url, identities=[{"label": "a", "objects": ["Q7X2KD"], "markers": ["m"]}])
    adapter(r, variables={"pnr": "ABC123"}).run(None, None, ctx)
    assert r.argv[r.argv.index("-var") + 1] == "pnr=ABC123"


def test_openapi_template_classified_as_inventory():
    f = record_to_finding({"template-id": "x", "info": {"tags": ["exposure", "openapi"]}})
    assert f.vuln_class == "api_inventory_exposure"
