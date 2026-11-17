"""OWASP ZAP adapter: openapi-seeded spider + active scan, driven over ZAP's json api.

Two kinds of traffic here, kept apart on purpose:
  - control traffic: this adapter -> zap api. a plain client pinned to the zap
    api base url, never pointed at the target.
  - target traffic: zap -> target. zap is configured to use the gate proxy as
    its upstream, so every request it makes passes authorize_request.
"""

import time
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any, Optional

import httpx

from ..scope.snapshot import ScopeSnapshot
from .base import RawFinding, ScanContext
from .openapi_seed import build_seed_set

RISK_TO_SEVERITY = {"informational": "info", "low": "low", "medium": "medium", "high": "high"}
CONFIDENCE = {"false positive": "low", "low": "low", "medium": "medium", "high": "high", "confirmed": "high"}

# rough zap alert -> our vuln class; anything unmapped keeps zap's plugin id so correlation still works
PLUGIN_CLASS = {
    "40012": "xss", "40014": "xss", "40018": "sqli", "40019": "sqli", "90019": "ssi",
    "10202": "csrf", "10038": "missing_security_header", "10021": "missing_security_header",
    "10020": "missing_security_header", "10035": "missing_security_header", "10096": "info_disclosure",
    "10062": "pii_disclosure", "90022": "info_disclosure", "10036": "version_disclosure", "10037": "version_disclosure",
    "6": "path_traversal", "7": "rfi", "90033": "loose_cookie",
}


class ZapError(RuntimeError):
    pass


@dataclass
class ZapConfig:
    api_url: str            # e.g. http://zap:8090
    api_key: str
    upstream_proxy: tuple[str, int]  # where the gate proxy listens, as zap sees it
    spider_max_minutes: int = 5
    ascan_max_minutes: int = 20
    poll_seconds: float = 2.0
    # informational alerts (user-agent fuzzer, content-type notes) are one-per-url noise
    include_info: bool = False


class ZapAdapter:
    name = "zap"
    needs_gate_proxy = True

    def __init__(self, config: ZapConfig, api_client: Optional[httpx.Client] = None,
                 sleep: Callable[[float], None] = time.sleep, key: bytes = b""):
        self.cfg = config
        self._api = api_client or httpx.Client(base_url=config.api_url, timeout=30.0, trust_env=False)
        self._sleep = sleep
        self._key = key

    # --- zap api plumbing ---

    def _call(self, component: str, kind: str, endpoint: str, /, **params: Any) -> dict:
        # positional-only: zap's own query params include "name", which must not collide with ours
        r = self._api.get(f"/JSON/{component}/{kind}/{endpoint}/", params={**params, "apikey": self.cfg.api_key})
        if r.status_code != 200:
            raise ZapError(f"zap {component}.{endpoint} -> http {r.status_code}")
        body = r.json()
        if isinstance(body, dict) and body.get("code") and body.get("message"):
            raise ZapError(f"zap {component}.{endpoint}: {body['message']}")
        return body

    def _wait(self, component: str, scan_id: str, max_minutes: int) -> None:
        deadline = max_minutes * 60
        waited = 0.0
        while waited <= deadline:
            status = int(self._call(component, "view", "status", scanId=scan_id).get("status", 0))
            if status >= 100:
                return
            self._sleep(self.cfg.poll_seconds)
            waited += self.cfg.poll_seconds
        self._call(component, "action", "stop", scanId=scan_id)
        raise ZapError(f"{component} scan {scan_id} timed out after {max_minutes} min")

    def configure_upstream(self) -> None:
        host, port = self.cfg.upstream_proxy
        # network add-on api (zap >= 2.12); older core.setOptionProxyChain* calls are deprecated
        self._call("network", "action", "setHttpProxy", host=host, port=str(port), realm="", username="", password="")
        self._call("network", "action", "setHttpProxyEnabled", enabled="true")

    # --- engine contract ---

    def run(self, client: httpx.Client, scope: ScopeSnapshot, ctx: ScanContext) -> list[RawFinding]:
        # zap keeps its site tree and alerts between scans; without a fresh session old results leak in
        self._call("core", "action", "newSession", name="", overwrite="true")
        self.configure_upstream()
        seeds = build_seed_set(client, ctx.base_url, scope, self._key) if self._key else []
        for s in seeds:
            if s.method == "GET":
                self._call("core", "action", "accessUrl", url=s.url, followRedirects="false")

        spider = self._call("spider", "action", "scan", url=ctx.base_url, recurse="true", subtreeOnly="true")
        self._wait("spider", str(spider.get("scan")), self.cfg.spider_max_minutes)

        ascan = self._call("ascan", "action", "scan", url=ctx.base_url, recurse="true", inScopeOnly="false")
        self._wait("ascan", str(ascan.get("scan")), self.cfg.ascan_max_minutes)

        return self.collect_alerts(ctx.base_url)

    def collect_alerts(self, base_url: str, page: int = 500) -> list[RawFinding]:
        findings: list[RawFinding] = []
        start = 0
        while True:
            alerts = self._call("core", "view", "alerts", baseurl=base_url, start=str(start), count=str(page)).get("alerts", [])
            mapped = [alert_to_finding(a) for a in alerts]
            findings += [f for f in mapped if self.cfg.include_info or f.severity != "info"]
            if len(alerts) < page:
                return findings
            start += page


def alert_to_finding(a: dict) -> RawFinding:
    plugin = str(a.get("pluginId", ""))
    cwe = a.get("cweid")
    return RawFinding(
        engine="zap",
        vuln_class=PLUGIN_CLASS.get(plugin, f"zap_{plugin or 'unknown'}"),
        title=a.get("alert") or a.get("name") or "zap alert",
        url=a.get("url", ""),
        method=(a.get("method") or "GET").upper(),
        param=a.get("param") or None,
        severity=RISK_TO_SEVERITY.get(str(a.get("risk", "")).lower(), "info"),
        confidence=CONFIDENCE.get(str(a.get("confidence", "")).lower(), "medium"),
        description=a.get("description", ""),
        evidence=(a.get("evidence") or "")[:500],
        cwe=int(cwe) if str(cwe or "").lstrip("-").isdigit() and int(cwe) > 0 else None,
        extra={"plugin_id": plugin, "solution": a.get("solution", ""), "reference": a.get("reference", "")},
    )
