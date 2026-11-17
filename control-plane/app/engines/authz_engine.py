"""Object-level authorization engine: booking-reference BOLA/IDOR (PRD 5.2).

Generic scanners can't tell whose object a response belongs to. This engine
can, because the operator gives it two or more seeded test identities, each
with the object ids they own and "markers" (values only that identity's
record contains, e.g. their name). A cross-identity 200 only counts as a
leak if the victim's markers show up in the body.

Only safe methods are replayed across identities. Proving "A can check B in"
would mean actually checking B in, and this tool doesn't modify data that
isn't the caller's.
"""

import json
import re
from dataclasses import dataclass, field
from itertools import permutations
from typing import Optional
from urllib.parse import quote

import httpx

from ..scope.snapshot import ScopeSnapshot
from .base import RawFinding, ScanContext
from .openapi_seed import fetch_openapi

SAFE_METHODS = {"GET", "HEAD"}
_PARAM = re.compile(r"\{([^}/]+)\}")
# shapes of personal data we never want sitting in stored evidence
_PII_PATTERNS = [
    (re.compile(r"\b\d{4}-\d{2}-\d{2}\b"), "[date]"),
    (re.compile(r"\b[A-Z]\d{7}\b"), "[passport]"),
    (re.compile(r"\+?\d[\d ]{7,}\d"), "[phone]"),
    (re.compile(r"[^\s\"@]+@[^\s\"@]+\.[a-z]{2,}", re.I), "[email]"),
    (re.compile(r"\b\d{4} \*{4} \*{4} \d{4}\b"), "[card]"),
]
MAX_EVIDENCE = 400


@dataclass
class Identity:
    label: str
    objects: list[str]
    markers: list[str]
    email: Optional[str] = None
    password: Optional[str] = None
    token: Optional[str] = None

    @classmethod
    def from_dict(cls, d: dict) -> "Identity":
        if not d.get("objects") or not d.get("markers"):
            raise ValueError(f"identity {d.get('label')!r} needs at least one object id and one marker")
        return cls(label=d["label"], objects=list(d["objects"]), markers=[m for m in d["markers"] if m],
                   email=d.get("email"), password=d.get("password"), token=d.get("token"))


@dataclass
class Endpoint:
    method: str
    template: str
    param: str

    def url(self, base: str, object_id: str) -> str:
        return base.rstrip("/") + self.template.replace("{" + self.param + "}", quote(object_id, safe=""))


@dataclass
class AuthzResult:
    findings: list[RawFinding] = field(default_factory=list)
    # endpoint template -> {"alice->bob": True, "anon->bob": False, ...}
    matrix: dict[str, dict[str, bool]] = field(default_factory=dict)
    predictable: dict[str, bool] = field(default_factory=dict)
    skipped: dict[str, str] = field(default_factory=dict)


def object_endpoints(doc: dict) -> list[Endpoint]:
    """GET/HEAD endpoints that take exactly one path parameter (the object id)."""
    out = []
    for template, item in sorted((doc or {}).get("paths", {}).items()):
        params = _PARAM.findall(template)
        if len(params) != 1 or not isinstance(item, dict):
            continue
        for method in item:
            if method.upper() in SAFE_METHODS:
                out.append(Endpoint(method.upper(), template, params[0]))
    return out


def leaks_foreign_data(body: str, victim: Identity) -> list[str]:
    """Which of the victim's markers appear in the body (case-insensitive)."""
    low = body.lower()
    return [m for m in victim.markers if m.lower() in low]


def redact(body: str, identities: list[Identity]) -> str:
    out = body
    for ident in identities:
        for i, m in enumerate(ident.markers):
            out = re.sub(re.escape(m), f"[{ident.label}:marker{i}]", out, flags=re.I)
    for pattern, repl in _PII_PATTERNS:
        out = pattern.sub(repl, out)
    return out[:MAX_EVIDENCE]


def looks_predictable(a: str, b: str) -> bool:
    """Weak signal only: sequential numbers, or ids so short they're brute-forceable."""
    if a.isdigit() and b.isdigit():
        return abs(int(a) - int(b)) < 10_000
    if min(len(a), len(b)) <= 4:
        return True
    # shared long prefix suggests a counter with decoration, e.g. NM000123 / NM000124
    common = len(next((a[:i] for i in range(min(len(a), len(b)), 0, -1) if a[:i] == b[:i]), ""))
    return common >= max(len(a), len(b)) - 2


class AuthzEngine:
    name = "authz"

    def __init__(self, token_path: str = "/auth/token", endpoints: Optional[list[Endpoint]] = None):
        self.token_path = token_path
        self._endpoints = endpoints
        self.last: Optional[AuthzResult] = None

    def _login(self, client: httpx.Client, base: str, ident: Identity) -> Optional[str]:
        if ident.token:
            return ident.token
        if not (ident.email and ident.password):
            return None
        r = client.post(base.rstrip("/") + self.token_path, json={"email": ident.email, "password": ident.password})
        if r.status_code != 200:
            return None
        try:
            return r.json().get("access_token")
        except (ValueError, AttributeError):
            return None

    def _get(self, client: httpx.Client, ep: Endpoint, base: str, obj: str, token: Optional[str]) -> httpx.Response:
        headers = {"Authorization": f"Bearer {token}"} if token else {}
        return client.request(ep.method, ep.url(base, obj), headers=headers)

    def run(self, client: httpx.Client, scope: ScopeSnapshot, ctx: ScanContext) -> list[RawFinding]:
        result = self.assess(client, ctx)
        self.last = result
        return result.findings

    def assess(self, client: httpx.Client, ctx: ScanContext) -> AuthzResult:
        result = AuthzResult()
        identities = [Identity.from_dict(d) for d in ctx.identities]
        if len(identities) < 2:
            result.skipped["*"] = "need at least two test identities"
            return result

        base = ctx.base_url
        tokens = {i.label: self._login(client, base, i) for i in identities}
        endpoints = self._endpoints if self._endpoints is not None else object_endpoints(fetch_openapi(client, base) or {})

        for ep in endpoints:
            row: dict[str, bool] = {}
            for attacker, victim in permutations(identities, 2):
                own = self._get(client, ep, base, attacker.objects[0], tokens[attacker.label])
                if own.status_code != 200:
                    # endpoint isn't usable as modelled for this caller; don't guess
                    result.skipped[ep.template] = f"baseline for {attacker.label} returned {own.status_code}"
                    continue

                cross = self._get(client, ep, base, victim.objects[0], tokens[attacker.label])
                leaked = leaks_foreign_data(cross.text, victim) if cross.status_code == 200 else []
                row[f"{attacker.label}->{victim.label}"] = bool(leaked)
                if leaked:
                    result.findings.append(self._finding(
                        "bola", "high", ep, cross, identities,
                        f"{attacker.label} read {victim.label}'s object via {ep.template}",
                        {"attacker": attacker.label, "victim": victim.label, "leaked_markers": len(leaked)},
                    ))

            for victim in identities:
                anon = self._get(client, ep, base, victim.objects[0], None)
                leaked = leaks_foreign_data(anon.text, victim) if anon.status_code == 200 else []
                row[f"anon->{victim.label}"] = bool(leaked)
                if leaked:
                    result.findings.append(self._finding(
                        "broken_auth", "critical", ep, anon, identities,
                        f"unauthenticated caller read {victim.label}'s object via {ep.template}",
                        {"attacker": "anonymous", "victim": victim.label, "leaked_markers": len(leaked)},
                    ))

            result.matrix[ep.template] = row
            ids = [i.objects[0] for i in identities]
            result.predictable[ep.template] = any(looks_predictable(a, b) for a, b in permutations(ids, 2))

        for f in result.findings:
            tpl = f.extra["template"]
            f.extra["reachability"] = result.matrix.get(tpl, {})
            f.extra["predictable_ids"] = result.predictable.get(tpl, False)
        return result

    def _finding(self, cls, sev, ep, resp, identities, title, extra) -> RawFinding:
        return RawFinding(
            engine="authz",
            vuln_class=cls,
            title=title,
            url=str(resp.request.url),
            method=ep.method,
            param=ep.param,
            severity=sev,
            confidence="high",
            description=("object-level authorization missing: a caller received another identity's record, "
                         "confirmed by that identity's seed markers in the response body"),
            evidence=redact(_compact(resp.text), identities),
            cwe=639 if cls == "bola" else 306,
            extra={"template": ep.template, "status": resp.status_code, **extra},
        )


def _compact(text: str) -> str:
    try:
        return json.dumps(json.loads(text), separators=(",", ":"))
    except ValueError:
        return text
