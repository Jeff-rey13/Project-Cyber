import pytest
from hypothesis import given
from hypothesis import strategies as st

from app.engines.base import RawFinding
from app.findings.normalize import (
    RISK_MULT_CAP,
    EndpointContext,
    correlate,
    fingerprint,
    rank,
    risk_score,
    url_template,
)
from app.findings.raw_store import save_raw
from app.findings.store import findings_for, normalize_job


def raw(engine="zap", cls="bola", url="http://127.0.0.1:8080/bookings/Q7X2KD", sev="high", conf="medium", **kw):
    return RawFinding(engine=engine, vuln_class=cls, title=f"{cls} via {engine}", url=url, severity=sev, confidence=conf, **kw)


@pytest.mark.parametrize("url,expected", [
    ("http://h/bookings/Q7X2KD", "h/bookings/{id}"),
    ("http://h/bookings/ABCDEF/checkin", "h/bookings/{id}/checkin"),
    ("http://h/bookings/SQUAWK0", "h/bookings/{id}"),
    ("http://h/users/12345", "h/users/{id}"),
    ("http://h/u/550e8400-e29b-41d4-a716-446655440000", "h/u/{id}"),
    ("http://h/t/deadbeefdeadbeef", "h/t/{id}"),
    ("http://h/bookings", "h/bookings"),
    ("http://h/openapi.json", "h/openapi.json"),
    ("http://h/me/contact", "h/me/contact"),
    ("http://H:80/a?ts=1&sid=abc&ts=2", "h/a?sid&ts"),
    ("https://h:443/a", "h/a"),
    ("http://h:8080/", "h:8080/"),
    ("http://h", "h/"),
])
def test_url_template(url, expected):
    assert url_template(url) == expected


def test_same_issue_across_ids_collapses():
    a = raw(url="http://h/bookings/Q7X2KD")
    b = raw(url="http://h/bookings/M3PA9Z?session=xyz")
    c = raw(url="http://h/bookings/M3PA9Z", param="pnr")
    assert fingerprint(a) != fingerprint(b)  # query key set differs
    assert fingerprint(raw(url="http://h/bookings/ZZ9ZZ9")) == fingerprint(a)
    assert fingerprint(c) != fingerprint(a)


@given(st.from_regex(r"[A-Z0-9]{6}", fullmatch=True))
def test_any_pnr_shape_templates_the_same(pnr):
    assert url_template(f"http://h/bookings/{pnr}") == "h/bookings/{id}"


def test_correlate_merges_engines_and_raises_confidence():
    group = [
        raw(engine="authz", cls="broken_auth", sev="critical", conf="high", url="http://h/bookings/Q7X2KD", evidence="e1"),
        raw(engine="nuclei", cls="broken_auth", sev="high", conf="medium", url="http://h/bookings/M3PA9Z"),
        raw(engine="zap", cls="missing_security_header", sev="low", conf="low", url="http://h/health"),
    ]
    merged = {m.vuln_class: m for m in correlate(group)}
    ba = merged["broken_auth"]
    assert ba.sources == ["authz", "nuclei"] and ba.members == 2
    assert ba.severity == "critical" and ba.confidence == "high" and ba.evidence == "e1"
    assert merged["missing_security_header"].confidence == "low"


def test_single_engine_keeps_its_confidence():
    (m,) = correlate([raw(conf="low"), raw(conf="medium", url="http://127.0.0.1:8080/bookings/M3PA9Z")])
    assert m.confidence == "medium" and m.sources == ["zap"]


def test_explicit_cvss_wins():
    (m,) = correlate([raw(sev="medium", extra={"cvss": 6.4})])
    assert m.cvss_base == 6.4


@pytest.mark.parametrize("cls,method,evidence,ctx,expected_mult", [
    ("xss", "GET", "", EndpointContext(), 1.0),
    ("xss", "GET", "", EndpointContext(requires_auth=True), 1.3),
    ("xss", "GET", "dob [date]", EndpointContext(), 1.5),
    ("xss", "POST", "", EndpointContext(), 1.4),
    ("bola", "GET", "", EndpointContext(requires_auth=True), 1.95),
    ("bola", "POST", "", EndpointContext(requires_auth=True), RISK_MULT_CAP),
])
def test_risk_multipliers(cls, method, evidence, ctx, expected_mult):
    (m,) = correlate([raw(cls=cls, method=method, evidence=evidence, sev="medium")])
    score = risk_score(m, ctx)
    assert m.risk_factors["multiplier"] == pytest.approx(expected_mult)
    assert score == round(5.3 * expected_mult, 1)


def test_risk_tops_out_at_twice_cvss():
    (m,) = correlate([raw(cls="bola", sev="critical", method="POST")])
    assert risk_score(m, EndpointContext(requires_auth=True)) == round(9.1 * RISK_MULT_CAP, 1)


def test_serious_findings_stay_distinguishable():
    crit, high, med = correlate([
        raw(engine="authz", cls="broken_auth", sev="critical", url="http://h/bookings/Q7X2KD", evidence="[date]"),
        raw(engine="authz", cls="bola", sev="high", url="http://h/bookings/Q7X2KD"),
        raw(engine="api_checks", cls="excessive_data_exposure", sev="medium", url="http://h/bookings/Q7X2KD"),
    ])
    scores = [risk_score(f) for f in (crit, high, med)]
    assert scores == sorted(scores, reverse=True) and len(set(scores)) == 3


def test_rank_orders_by_risk_then_agreement():
    findings = correlate([
        raw(engine="zap", cls="xss", sev="medium", url="http://h/a"),
        raw(engine="zap", cls="sqli", sev="medium", url="http://h/b"),
        raw(engine="nuclei", cls="sqli", sev="medium", url="http://h/b"),
        raw(engine="authz", cls="bola", sev="high", url="http://h/bookings/Q7X2KD"),
        raw(engine="zap", cls="info", sev="info", url="http://h/c"),
    ])
    order = [f.vuln_class for f in rank(findings)]
    assert order[0] == "bola" and order[1] == "sqli" and order[-1] == "info"


def test_normalize_job_persists_and_is_rerunnable(session):
    save_raw(session, "job-1", [
        raw(engine="authz", cls="bola", url="http://h/bookings/Q7X2KD", evidence="[bob:marker0]"),
        raw(engine="authz", cls="bola", url="http://h/bookings/M3PA9Z"),
        raw(engine="zap", cls="xss", sev="medium", url="http://h/search?q=1"),
    ])
    rows = normalize_job(session, "job-1", {"h/bookings/{id}": EndpointContext(requires_auth=True)})
    assert [r.rank for r in rows] == [1, 2] and rows[0].vuln_class == "bola"
    assert rows[0].risk_factors["requires_auth"] == 1.3 and rows[0].url_template == "h/bookings/{id}"
    assert len(normalize_job(session, "job-1")) == 2
    assert [r.vuln_class for r in findings_for(session, "job-1")] == ["bola", "xss"]


def test_first_seen_carries_across_jobs(session):
    save_raw(session, "job-a", [raw()])
    first = normalize_job(session, "job-a")[0]
    save_raw(session, "job-b", [raw(url="http://127.0.0.1:8080/bookings/M3PA9Z")])
    second = normalize_job(session, "job-b")[0]
    assert second.fingerprint == first.fingerprint
    assert second.first_seen == first.first_seen and second.last_seen >= first.last_seen


def test_site_wide_header_findings_collapse_across_urls_and_engines():
    findings = correlate([
        raw(engine="zap", cls="missing_security_header", sev="low", url="http://h:8080/health", param="X-Content-Type-Options"),
        raw(engine="zap", cls="missing_security_header", sev="low", url="http://h:8080/bookings/Q7X2KD"),
        raw(engine="nuclei", cls="missing_security_header", sev="low", url="http://h:8080/health"),
        raw(engine="api_checks", cls="missing_security_header", sev="low", url="http://h:8080/"),
        raw(engine="zap", cls="version_disclosure", sev="low", url="http://h:8080/robots.txt"),
        raw(engine="zap", cls="version_disclosure", sev="low", url="http://h:8080/me"),
    ])
    by = {f.vuln_class: f for f in findings}
    assert len(findings) == 2
    hdr = by["missing_security_header"]
    assert hdr.url_template == "h:8080/*" and hdr.sources == ["api_checks", "nuclei", "zap"] and hdr.confidence == "high"
    assert by["version_disclosure"].members == 2


def test_path_level_classes_still_split_by_endpoint():
    assert len(correlate([raw(url="http://h/bookings/Q7X2KD"), raw(url="http://h/me")])) == 2


def test_authz_and_nuclei_views_of_unauth_access_merge():
    from app.engines.nuclei_adapter import record_to_finding

    authz = raw(engine="authz", cls="broken_auth", sev="critical", conf="high", url="http://h:8080/bookings/Q7X2KD",
                extra={"requires_auth": True})
    nuclei = record_to_finding({"template-id": "squawk-booking-lookup-unauthenticated", "matched-at": "http://h:8080/bookings/M3PA9Z",
                                "info": {"severity": "high", "tags": ["auth-bypass", "airline"]}})
    (m,) = correlate([authz, nuclei])
    assert m.sources == ["authz", "nuclei"] and m.severity == "critical"
