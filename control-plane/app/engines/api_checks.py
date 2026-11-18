"""In-process API checks the dast engines can't see (OWASP API3, API4, API8, API9).

  excessive_data_exposure  own object comes back with dob/passport/card fields
  mass_assignment          privileged profile field writable through the contact update
  missing_rate_limit       a short burst on a lookup endpoint never gets a 429
  api_inventory_exposure   openapi schema served to anonymous callers
  missing_security_header  baseline response headers absent

Do-no-harm rules: only the first identity's own objects are touched, any
profile field changed by the mass-assignment probe is put back immediately,
and the rate-limit burst is small and still paced by the throttle.
"""

import json
from typing import Optional

import httpx

from ..scope.snapshot import ScopeSnapshot
from .authz_engine import Identity, object_endpoints, redact
from .base import RawFinding, ScanContext
from .openapi_seed import OPENAPI_PATHS, fetch_openapi

SENSITIVE_KEYS = ("dob", "date_of_birth", "passport", "card", "pan", "cvv", "password", "national_id")
PRIVILEGED_FIELDS = ("role", "loyalty_tier", "is_admin", "loyalty_points", "tier")
SENTINEL = "squawk-probe"
BURST = 25
BASELINE_HEADERS = ("x-content-type-options", "cache-control")


def _json(r: httpx.Response) -> Optional[dict]:
    try:
        body = r.json()
    except ValueError:
        return None
    return body if isinstance(body, dict) else None


def _sensitive_keys(obj, prefix="") -> list[str]:
    found = []
    if isinstance(obj, dict):
        for k, v in obj.items():
            path = f"{prefix}{k}"
            if any(s in k.lower() for s in SENSITIVE_KEYS):
                found.append(path)
            found += _sensitive_keys(v, path + ".")
    elif isinstance(obj, list):
        for item in obj[:5]:
            found += _sensitive_keys(item, prefix)
    return found


class ApiChecksEngine:
    name = "api_checks"

    def __init__(self, token_path: str = "/auth/token", profile_path: str = "/me", contact_path: str = "/me/contact"):
        self.token_path = token_path
        self.profile_path = profile_path
        self.contact_path = contact_path

    def _token(self, client: httpx.Client, base: str, ident: Identity) -> Optional[str]:
        if ident.token:
            return ident.token
        if not (ident.email and ident.password):
            return None
        r = client.post(base + self.token_path, json={"email": ident.email, "password": ident.password})
        body = _json(r) if r.status_code == 200 else None
        return body.get("access_token") if body else None

    def run(self, client: httpx.Client, scope: ScopeSnapshot, ctx: ScanContext) -> list[RawFinding]:
        base = ctx.base_url.rstrip("/")
        findings: list[RawFinding] = []
        doc = fetch_openapi(client, base) or {}

        findings += self.check_inventory(client, base)
        findings += self.check_headers(client, base)

        identities = [Identity.from_dict(d) for d in ctx.identities]
        if not identities:
            return findings
        me = identities[0]
        token = self._token(client, base, me)
        if not token:
            return findings
        auth = {"Authorization": f"Bearer {token}"}

        for ep in object_endpoints(doc):
            url = ep.url(base, me.objects[0])
            findings += self.check_exposure(client, url, ep.template, auth, identities)
            findings += self.check_rate_limit(client, url, ep.template, auth)
        findings += self.check_mass_assignment(client, base, auth)
        return findings

    # --- individual checks ---

    def check_inventory(self, client: httpx.Client, base: str) -> list[RawFinding]:
        for path in OPENAPI_PATHS:
            r = client.get(base + path)
            body = _json(r) if r.status_code == 200 else None
            if body and "paths" in body:
                return [RawFinding(
                    engine=self.name, vuln_class="api_inventory_exposure", title="OpenAPI schema served to anonymous callers",
                    url=base + path, severity="low", confidence="high", cwe=200,
                    description="the complete endpoint and parameter inventory is public",
                    evidence=f"{len(body['paths'])} paths published", extra={"paths": len(body["paths"])},
                )]
        return []

    def check_headers(self, client: httpx.Client, base: str) -> list[RawFinding]:
        r = client.get(base + "/")
        missing = [h for h in BASELINE_HEADERS if h not in r.headers]
        if not missing:
            return []
        return [RawFinding(
            engine=self.name, vuln_class="missing_security_header", title="Baseline security headers missing",
            url=base + "/", severity="low", confidence="high", cwe=693,
            description="responses lack " + ", ".join(missing), evidence="missing: " + ", ".join(missing),
            extra={"missing": missing},
        )]

    def check_exposure(self, client, url, template, auth, identities) -> list[RawFinding]:
        r = client.get(url, headers=auth)
        body = _json(r) if r.status_code == 200 else None
        keys = _sensitive_keys(body) if body else []
        if not keys:
            return []
        return [RawFinding(
            engine=self.name, vuln_class="excessive_data_exposure",
            title=f"{template} returns sensitive fields the client doesn't need",
            url=url, severity="medium", confidence="high", cwe=213,
            description="the response carries " + ", ".join(keys) + " on a lookup that only needs itinerary data",
            evidence=redact(json.dumps(body, separators=(",", ":")), identities),
            extra={"template": template, "fields": keys, "requires_auth": True},
        )]

    def check_rate_limit(self, client, url, template, auth) -> list[RawFinding]:
        codes = []
        for _ in range(BURST):
            r = client.get(url, headers=auth)
            codes.append(r.status_code)
            # either signal means a limiter exists; stop pushing as soon as we see it
            if r.status_code == 429 or any(h.lower().startswith(("x-ratelimit", "ratelimit", "retry-after")) for h in r.headers):
                return []
        return [RawFinding(
            engine=self.name, vuln_class="missing_rate_limit", title=f"No rate limiting on {template}",
            url=url, severity="medium", confidence="medium", cwe=770,
            description=f"{BURST} back-to-back lookups were all served with no 429 or rate-limit headers; "
                        "combined with guessable record locators this enables enumeration",
            evidence=f"statuses: {sorted(set(codes))}", extra={"template": template, "burst": BURST, "requires_auth": True},
        )]

    def check_mass_assignment(self, client, base, auth) -> list[RawFinding]:
        before_r = client.get(base + self.profile_path, headers=auth)
        before = _json(before_r) if before_r.status_code == 200 else None
        if not before:
            return []
        candidates = [f for f in PRIVILEGED_FIELDS if f in before and isinstance(before[f], str)]
        findings = []
        for field in candidates:
            client.patch(base + self.contact_path, headers=auth, json={field: SENTINEL})
            after = _json(client.get(base + self.profile_path, headers=auth)) or {}
            if after.get(field) == SENTINEL:
                # put it back before doing anything else
                client.patch(base + self.contact_path, headers=auth, json={field: before[field]})
                findings.append(RawFinding(
                    engine=self.name, vuln_class="mass_assignment",
                    title=f"Privileged field '{field}' writable via contact update",
                    url=base + self.contact_path, method="PATCH", param=field, severity="high", confidence="high", cwe=915,
                    description=f"sending {{\"{field}\": ...}} to the contact update changed the caller's {field}; "
                                "the value was restored after the probe",
                    evidence=f"{field}: original -> {SENTINEL} -> restored",
                    extra={"requires_auth": True, "restored": True},
                ))
        return findings
