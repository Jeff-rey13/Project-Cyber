"""Scoped load testing with k6 (PRD 6.6).

Same rules as every other engine: verified target, sealed snapshot, every url
pre-checked by the gate, traffic forced through the gate proxy, rates capped
at the throttle's hard ceilings. On top of that k6's own thresholds abort the
run early if the target starts erroring or slowing down.
"""

import json
import os
import subprocess
import tempfile
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Optional
from urllib.parse import urlsplit

from sqlmodel import Session

from ..orchestrator.throttle import HARD_MAX_CONCURRENCY, HARD_MAX_RPS
from ..scope import audit
from ..scope.gate import authorize_request
from ..scope.snapshot import ScopeSnapshot
from ..scope.verification import is_verified

MAX_DURATION_S = 300


@dataclass(frozen=True)
class Profile:
    name: str
    rps: float
    duration_s: int
    vus: int
    p95_abort_ms: int = 1500
    error_abort_rate: float = 0.2


PROFILES = {
    "smoke": Profile("smoke", rps=1, duration_s=10, vus=1),
    "baseline": Profile("baseline", rps=5, duration_s=30, vus=2),
    "peak": Profile("peak", rps=HARD_MAX_RPS, duration_s=60, vus=HARD_MAX_CONCURRENCY),
}

Runner = Callable[[Sequence[str], dict, float], tuple[int, str, str]]


class PerfRefused(Exception):
    pass


def subprocess_runner(argv: Sequence[str], env: dict, timeout: float) -> tuple[int, str, str]:
    p = subprocess.run(list(argv), capture_output=True, text=True, timeout=timeout, env=env, check=False)
    return p.returncode, p.stdout, p.stderr


def clamp(profile: Profile) -> Profile:
    return Profile(
        profile.name,
        rps=min(max(profile.rps, 0.1), HARD_MAX_RPS),
        duration_s=min(max(profile.duration_s, 1), MAX_DURATION_S),
        vus=min(max(profile.vus, 1), HARD_MAX_CONCURRENCY),
        p95_abort_ms=profile.p95_abort_ms,
        error_abort_rate=min(profile.error_abort_rate, 0.5),
    )


def render_script(urls: list[str], p: Profile) -> str:
    # k6 wants an integer rate; express fractional rps as N per M seconds
    rate, unit = (int(p.rps), "1s") if p.rps >= 1 else (1, f"{round(1 / p.rps)}s")
    return f"""import http from 'k6/http';

export const options = {{
  discardResponseBodies: true,
  scenarios: {{
    scoped: {{
      executor: 'constant-arrival-rate',
      rate: {rate}, timeUnit: '{unit}', duration: '{p.duration_s}s',
      preAllocatedVUs: {p.vus}, maxVUs: {p.vus},
    }},
  }},
  thresholds: {{
    http_req_failed: [{{ threshold: 'rate<{p.error_abort_rate}', abortOnFail: true, delayAbortEval: '5s' }}],
    http_req_duration: [{{ threshold: 'p(95)<{p.p95_abort_ms}', abortOnFail: true, delayAbortEval: '5s' }}],
  }},
}};

const URLS = {json.dumps(urls)};

export default function () {{
  http.get(URLS[Math.floor(Math.random() * URLS.length)], {{ tags: {{ aeroscan: 'perf' }} }});
}}
"""


def summarize(summary: dict, profile: Profile, aborted: bool) -> dict:
    m = summary.get("metrics", {})
    dur = m.get("http_req_duration", {})
    failed = m.get("http_req_failed", {})
    reqs = m.get("http_reqs", {})
    return {
        "profile": profile.name,
        "target_rps": profile.rps,
        "achieved_rps": round(reqs.get("rate", 0.0), 2),
        "requests": int(reqs.get("count", 0)),
        "latency_ms": {k: round(dur.get(src, 0.0), 1) for k, src in
                       (("avg", "avg"), ("p50", "med"), ("p90", "p(90)"), ("p95", "p(95)"), ("max", "max"))},
        "error_rate": round(failed.get("value", failed.get("rate", 0.0)), 4),
        "aborted_by_threshold": aborted,
    }


def run_perf(
    session: Session,
    actor: str,
    base_url: str,
    paths: list[str],
    snapshot: ScopeSnapshot,
    key: bytes,
    proxy_url: str,
    profile: Profile = PROFILES["smoke"],
    runner: Runner = subprocess_runner,
    binary: str = "k6",
) -> dict:
    if not snapshot.is_sealed_with(key):
        raise PerfRefused("scope snapshot missing or seal invalid")
    host = urlsplit(base_url).hostname or ""
    if not is_verified(session, host):
        audit.append(session, actor, "perf.refused", {"base_url": base_url, "reason": "target not verified"})
        raise PerfRefused(f"{host} has not passed ownership verification")
    if not proxy_url.startswith("http://"):
        raise PerfRefused("k6 must run behind the http gate proxy")

    urls = [base_url.rstrip("/") + p for p in paths]
    allowed = [u for u in urls if authorize_request("GET", u, snapshot, key)]
    if not allowed:
        audit.append(session, actor, "perf.refused", {"base_url": base_url, "reason": "no in-scope urls"})
        raise PerfRefused("none of the requested urls are in scope")

    p = clamp(profile)
    with tempfile.TemporaryDirectory(prefix="aeroscan-k6-") as tmp:
        script = Path(tmp) / "scoped.js"
        summary_path = Path(tmp) / "summary.json"
        script.write_text(render_script(allowed, p), encoding="utf-8")
        # k6 honours HTTP_PROXY for plain http; scrub anything else proxy-ish from the inherited env
        env = {k: v for k, v in os.environ.items() if "proxy" not in k.lower()}
        env.update({"HTTP_PROXY": proxy_url, "K6_NO_USAGE_REPORT": "true"})
        argv = [binary, "run", "--quiet", "--no-color", "--summary-export", str(summary_path), str(script)]
        audit.append(session, actor, "perf.start", {"base_url": base_url, "profile": p.name, "rps": p.rps, "urls": len(allowed)})
        try:
            code, _, err = runner(argv, env, p.duration_s + 120)
        except FileNotFoundError as exc:
            raise PerfRefused(f"k6 binary not found: {binary}") from exc
        # 99 = thresholds crossed (k6 aborted to protect the target); anything else non-zero is a real error
        if code not in (0, 99):
            raise RuntimeError(f"k6 exited {code}: {err.strip()[:300]}")
        summary = json.loads(summary_path.read_text(encoding="utf-8")) if summary_path.exists() else {}

    result = {**summarize(summary, p, aborted=code == 99), "urls": allowed, "skipped_out_of_scope": len(urls) - len(allowed)}
    audit.append(session, actor, "perf.done", {k: v for k, v in result.items() if k != "urls"})
    return result


def format_summary(r: dict) -> str:
    lat = r["latency_ms"]
    lines = [
        f"profile {r['profile']}: {r['requests']} requests at {r['achieved_rps']} req/s (target {r['target_rps']})",
        f"latency ms  p50 {lat['p50']}  p90 {lat['p90']}  p95 {lat['p95']}  max {lat['max']}",
        f"error rate  {r['error_rate']:.2%}",
    ]
    if r["aborted_by_threshold"]:
        lines.append("stopped early: target crossed the latency/error thresholds")
    return "\n".join(lines)


def profile_from(name: str, overrides: Optional[dict] = None) -> Profile:
    if name not in PROFILES:
        raise PerfRefused(f"unknown profile {name!r}")
    base = PROFILES[name]
    fields = {k: v for k, v in (overrides or {}).items() if k in Profile.__dataclass_fields__ and k != "name"}
    return clamp(Profile(**{**base.__dict__, **fields}))
