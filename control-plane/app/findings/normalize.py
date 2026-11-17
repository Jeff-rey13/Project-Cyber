"""De-duplication, cross-engine correlation and context-aware risk scoring (PRD 5.3, 5.4)."""

import hashlib
import re
from dataclasses import dataclass, field
from typing import Optional
from urllib.parse import parse_qsl, urlsplit

from ..engines.base import SEVERITIES, RawFinding

SEV_RANK = {s: i for i, s in enumerate(SEVERITIES)}
CONF_RANK = {"low": 0, "medium": 1, "high": 2}
# used when an engine gives us a severity but no cvss vector
SEVERITY_CVSS = {"info": 0.0, "low": 3.1, "medium": 5.3, "high": 7.5, "critical": 9.1}
STATE_CHANGING = {"POST", "PUT", "PATCH", "DELETE"}
RISK_MULT_CAP = 2.0

_UUID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.I)
_HEX = re.compile(r"^[0-9a-f]{16,}$", re.I)
_RECORD_LOCATOR = re.compile(r"^[A-Z0-9]{5,8}$")
_PII = [
    re.compile(r"\[(date|passport|phone|email|card)\]"),       # our own redaction tokens
    re.compile(r"\b\d{4}-\d{2}-\d{2}\b"),                          # dob-ish
    re.compile(r"\b[A-Z]\d{7}\b"),                                  # passport-ish
    re.compile(r"\b\d{4}[ -]?\*{4}[ -]?\*{4}[ -]?\d{4}\b"),         # masked pan
    re.compile(r"passport|date_of_birth|\bdob\b|card_masked", re.I),
]
PII_CLASSES = {"bola", "pii_disclosure", "excessive_data_exposure"}


def _is_dynamic(segment: str) -> bool:
    if not segment:
        return False
    if segment.isdigit() or _UUID.match(segment) or _HEX.match(segment):
        return True
    has_digit = any(c.isdigit() for c in segment)
    has_alpha = any(c.isalpha() for c in segment)
    if has_digit and has_alpha and len(segment) >= 5:
        return True
    # all-caps 5-8 char tokens are airline record locators far more often than real path words
    return bool(_RECORD_LOCATOR.match(segment))


def url_template(url: str) -> str:
    """/bookings/ABC123/checkin?ts=1&sid=x  ->  host/bookings/{id}/checkin?sid&ts"""
    parts = urlsplit(url)
    host = (parts.hostname or "").lower()
    port = parts.port
    if port and not ((parts.scheme == "http" and port == 80) or (parts.scheme == "https" and port == 443)):
        host = f"{host}:{port}"
    segments = ["{id}" if _is_dynamic(s) else s for s in (parts.path or "/").split("/")]
    path = "/".join(segments) or "/"
    # query values are volatile (tokens, timestamps); only the key set identifies the endpoint
    keys = sorted({k for k, _ in parse_qsl(parts.query, keep_blank_values=True)})
    return host + path + ("?" + "&".join(keys) if keys else "")


def fingerprint(f: RawFinding) -> str:
    return hashlib.sha256(f"{f.vuln_class}|{url_template(f.url)}|{f.param or ''}".encode()).hexdigest()


@dataclass
class EndpointContext:
    requires_auth: bool = False
    state_changing: bool = False


@dataclass
class MergedFinding:
    fingerprint: str
    vuln_class: str
    title: str
    description: str
    url_template: str
    param: Optional[str]
    method: str
    severity: str
    confidence: str
    sources: list[str]
    evidence: str
    cwe: Optional[int]
    cvss_base: float
    members: int = 1
    risk_score: float = 0.0
    risk_factors: dict[str, float] = field(default_factory=dict)
    extra: dict = field(default_factory=dict)


def _merge(group: list[RawFinding]) -> MergedFinding:
    # the most severe member supplies the headline text
    lead = max(group, key=lambda f: (SEV_RANK[f.severity], CONF_RANK.get(f.confidence, 1)))
    sources = sorted({f.engine for f in group})
    confidence = max((f.confidence for f in group), key=lambda c: CONF_RANK.get(c, 1))
    if len(sources) > 1:
        confidence = "high"  # independent engines agreeing is the strongest signal we have
    explicit_cvss = [f.extra.get("cvss") for f in group if isinstance(f.extra.get("cvss"), (int, float))]
    severity = max((f.severity for f in group), key=SEV_RANK.get)
    extra: dict = {}
    for f in group:
        for k, v in f.extra.items():
            extra.setdefault(k, v)
    return MergedFinding(
        fingerprint=fingerprint(lead),
        vuln_class=lead.vuln_class,
        title=lead.title,
        description=lead.description,
        url_template=url_template(lead.url),
        param=lead.param,
        method=lead.method,
        severity=severity,
        confidence=confidence,
        sources=sources,
        evidence=next((f.evidence for f in group if f.evidence), ""),
        cwe=next((f.cwe for f in group if f.cwe), None),
        cvss_base=max(explicit_cvss) if explicit_cvss else SEVERITY_CVSS[severity],
        members=len(group),
        extra=extra,
    )


def correlate(raw: list[RawFinding]) -> list[MergedFinding]:
    buckets: dict[str, list[RawFinding]] = {}
    for f in raw:
        buckets.setdefault(fingerprint(f), []).append(f)
    return [_merge(g) for g in buckets.values()]


def response_has_pii(f: MergedFinding) -> bool:
    return f.vuln_class in PII_CLASSES or any(p.search(f.evidence or "") for p in _PII)


def risk_score(f: MergedFinding, ctx: Optional[EndpointContext] = None) -> float:
    ctx = ctx or EndpointContext()
    factors: dict[str, float] = {}
    if ctx.requires_auth or f.extra.get("requires_auth"):
        factors["requires_auth"] = 1.3
    if response_has_pii(f):
        factors["pii"] = 1.5
    if ctx.state_changing or f.method.upper() in STATE_CHANGING:
        factors["state_changing"] = 1.4
    mult = 1.0
    for v in factors.values():
        mult *= v
    mult = min(mult, RISK_MULT_CAP)
    f.risk_factors = {**factors, "multiplier": round(mult, 3)}
    # 0..20 by design (cvss x a multiplier capped at 2). clamping to 10 would flatten every
    # serious finding into a tie and lose exactly the ordering this score exists for.
    f.risk_score = round(f.cvss_base * mult, 1)
    return f.risk_score


def rank(findings: list[MergedFinding], contexts: Optional[dict[str, EndpointContext]] = None) -> list[MergedFinding]:
    contexts = contexts or {}
    for f in findings:
        risk_score(f, contexts.get(f.url_template))
    return sorted(findings, key=lambda f: (-f.risk_score, -len(f.sources), -CONF_RANK[f.confidence], f.fingerprint))
