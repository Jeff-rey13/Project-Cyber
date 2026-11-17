"""Crawl seeding from the target's own OpenAPI document (PRD 5.6).

Fetched through the guarded client like everything else. Path parameters get
a harmless placeholder so the seeds are concrete urls; every seed is then
re-checked against the gate before it's handed to an engine.
"""

import re
from dataclasses import dataclass
from urllib.parse import urljoin

import httpx

from ..scope.gate import authorize_request
from ..scope.snapshot import ScopeSnapshot

OPENAPI_PATHS = ("/openapi.json", "/swagger.json", "/v3/api-docs")
HTTP_METHODS = {"get", "post", "put", "patch", "delete", "head", "options"}
_PARAM = re.compile(r"\{([^}/]+)\}")
# placeholder that is obviously a test value and unlikely to collide with real ids
PLACEHOLDER = "AEROSCAN0"


@dataclass(frozen=True)
class Seed:
    method: str
    url: str
    template: str
    requires_auth: bool
    has_body: bool


def fetch_openapi(client: httpx.Client, base_url: str) -> dict | None:
    for path in OPENAPI_PATHS:
        try:
            r = client.get(urljoin(base_url.rstrip("/") + "/", path.lstrip("/")))
        except httpx.RequestError:
            continue
        if r.status_code == 200:
            try:
                doc = r.json()
            except ValueError:
                continue
            if isinstance(doc, dict) and isinstance(doc.get("paths"), dict):
                return doc
    return None


def _needs_auth(op: dict, doc: dict) -> bool:
    if "security" in op:
        return bool(op["security"])
    if doc.get("security"):
        return True
    # fastapi doesn't declare header-based auth as a security scheme, so fall back to the header param
    return any(p.get("in") == "header" and p.get("name", "").lower() == "authorization" for p in op.get("parameters", []))


def seeds_from_openapi(doc: dict, base_url: str) -> list[Seed]:
    out: list[Seed] = []
    base = base_url.rstrip("/")
    for template, item in sorted(doc.get("paths", {}).items()):
        if not isinstance(item, dict) or not template.startswith("/"):
            continue
        concrete = _PARAM.sub(PLACEHOLDER, template)
        for method, op in item.items():
            if method.lower() not in HTTP_METHODS or not isinstance(op, dict):
                continue
            out.append(Seed(method.upper(), base + concrete, template, _needs_auth(op, doc), "requestBody" in op))
    return out


def build_seed_set(client: httpx.Client, base_url: str, scope: ScopeSnapshot, key: bytes) -> list[Seed]:
    seeds = [Seed("GET", base_url.rstrip("/") + "/", "/", False, False)]
    doc = fetch_openapi(client, base_url)
    if doc:
        seeds += seeds_from_openapi(doc, base_url)
    # belt and braces: the client would refuse these anyway, but don't even hand them out
    seen: set[tuple[str, str]] = set()
    kept: list[Seed] = []
    for s in seeds:
        if (s.method, s.template) in seen:
            continue
        if authorize_request(s.method, s.url, scope, key):
            seen.add((s.method, s.template))
            kept.append(s)
    return kept
