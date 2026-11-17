"""Nuclei adapter: templated checks, run as a subprocess behind the gate proxy.

Flags that matter for safety, all forced here rather than left to config:
  -proxy           every request goes via the gate proxy
  -no-interactsh   no out-of-band callbacks to third-party servers
  -duc             no update check phoning home mid-scan
  -rl / -c         rate and concurrency capped at the same hard ceilings as everything else
"""

import json
import shutil
import subprocess
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

import httpx

from ..scope.snapshot import ScopeSnapshot
from .base import SEVERITIES, RawFinding, ScanContext

# shared with the throttle module later; not operator-tunable above this
HARD_MAX_RPS = 20
HARD_MAX_CONCURRENCY = 4
DEFAULT_TEMPLATES = Path(__file__).resolve().parents[2] / "nuclei-templates"

# template tags -> our vuln class, first match wins
TAG_CLASS = [
    ("sqli", "sqli"), ("xss", "xss"), ("exposure", "info_disclosure"), ("openapi", "api_inventory_exposure"),
    ("swagger", "api_inventory_exposure"), ("misconfig", "security_misconfiguration"), ("headers", "missing_security_header"),
    ("default-login", "broken_auth"), ("auth-bypass", "broken_auth"), ("idor", "bola"), ("lfi", "path_traversal"),
]

Runner = Callable[[Sequence[str], float], tuple[int, str, str]]


class NucleiError(RuntimeError):
    pass


def subprocess_runner(argv: Sequence[str], timeout: float) -> tuple[int, str, str]:
    p = subprocess.run(list(argv), capture_output=True, text=True, timeout=timeout, check=False)
    return p.returncode, p.stdout, p.stderr


@dataclass
class NucleiConfig:
    proxy_url: str                      # gate proxy, as nuclei sees it
    binary: str = "nuclei"
    templates: list[str] = field(default_factory=lambda: [str(DEFAULT_TEMPLATES)])
    severities: tuple[str, ...] = ("low", "medium", "high", "critical")
    rate_limit: int = 10
    concurrency: int = 2
    timeout_seconds: float = 900
    # template variables, e.g. {"pnr": "<a seeded test pnr>"}
    variables: dict[str, str] = field(default_factory=dict)


class NucleiAdapter:
    name = "nuclei"
    needs_gate_proxy = True

    def __init__(self, config: NucleiConfig, runner: Runner = subprocess_runner):
        self.cfg = config
        self._run = runner

    def argv(self, target: str) -> list[str]:
        if not self.cfg.proxy_url.startswith("http://"):
            raise NucleiError("nuclei must run behind the http gate proxy")
        binary = shutil.which(self.cfg.binary) or self.cfg.binary
        args = [
            binary, "-u", target, "-jsonl", "-silent", "-no-color",
            "-proxy", self.cfg.proxy_url,
            "-no-interactsh", "-duc",
            "-rl", str(min(self.cfg.rate_limit, HARD_MAX_RPS)),
            "-c", str(min(self.cfg.concurrency, HARD_MAX_CONCURRENCY)),
            "-severity", ",".join(self.cfg.severities),
            "-timeout", "10", "-retries", "0",
        ]
        for t in self.cfg.templates:
            args += ["-t", t]
        for k, v in sorted(self.cfg.variables.items()):
            # argv list, no shell, so no quoting games; still refuse anything that looks like a flag
            if not k.isidentifier() or str(v).startswith("-"):
                raise NucleiError(f"refusing odd template variable {k!r}")
            args += ["-var", f"{k}={v}"]
        return args

    def run(self, client: Optional[httpx.Client], scope: ScopeSnapshot, ctx: ScanContext) -> list[RawFinding]:
        try:
            code, out, err = self._run(self.argv(ctx.base_url), self.cfg.timeout_seconds)
        except FileNotFoundError as exc:
            raise NucleiError(f"nuclei binary not found: {self.cfg.binary}") from exc
        except subprocess.TimeoutExpired as exc:
            raise NucleiError(f"nuclei timed out after {self.cfg.timeout_seconds}s") from exc
        # nuclei exits 0 with or without matches; anything else is a real failure
        if code != 0:
            raise NucleiError(f"nuclei exited {code}: {err.strip()[:300]}")
        return parse_jsonl(out)


def parse_jsonl(text: str) -> list[RawFinding]:
    findings = []
    for line in text.splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            rec = json.loads(line)
        except json.JSONDecodeError:
            continue
        findings.append(record_to_finding(rec))
    return findings


def _cwe(classification: dict) -> Optional[int]:
    ids = classification.get("cwe-id") or []
    if isinstance(ids, str):
        ids = [ids]
    for raw in ids:
        digits = str(raw).lower().removeprefix("cwe-")
        if digits.isdigit():
            return int(digits)
    return None


def _vuln_class(template_id: str, tags) -> str:
    tags = tags if isinstance(tags, list) else str(tags or "").split(",")
    tags = {t.strip().lower() for t in tags}
    for tag, cls in TAG_CLASS:
        if tag in tags:
            return cls
    return f"nuclei_{template_id}"


def record_to_finding(rec: dict) -> RawFinding:
    info = rec.get("info") or {}
    sev = str(info.get("severity", "info")).lower()
    tid = rec.get("template-id", "unknown")
    extracted = rec.get("extracted-results") or []
    return RawFinding(
        engine="nuclei",
        vuln_class=_vuln_class(tid, info.get("tags")),
        title=info.get("name") or tid,
        url=rec.get("matched-at") or rec.get("url") or rec.get("host", ""),
        method=str((rec.get("request") or "GET").split(" ", 1)[0]).upper() if rec.get("request") else "GET",
        severity=sev if sev in SEVERITIES else "info",
        # templates are deterministic matchers; treat a hit as high confidence
        confidence="high",
        description=info.get("description", ""),
        evidence=", ".join(map(str, extracted))[:500] or str(rec.get("matcher-name") or ""),
        cwe=_cwe(info.get("classification") or {}),
        extra={"template_id": tid, "matcher": rec.get("matcher-name"), "tags": info.get("tags")},
    )
