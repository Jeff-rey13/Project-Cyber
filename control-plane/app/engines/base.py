"""Common engine contract (PRD 4.2): run(client, scope, ctx) -> list[RawFinding].

Engines get the guarded client handed to them. They have no way to build
their own, and the orchestrator never passes them anything else.
"""

from dataclasses import dataclass, field
from typing import Any, Optional, Protocol

import httpx

from ..scope.snapshot import ScopeSnapshot

SEVERITIES = ("info", "low", "medium", "high", "critical")


@dataclass
class RawFinding:
    engine: str
    vuln_class: str
    title: str
    url: str
    method: str = "GET"
    param: Optional[str] = None
    severity: str = "info"
    confidence: str = "medium"  # low | medium | high
    description: str = ""
    evidence: str = ""
    cwe: Optional[int] = None
    extra: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self):
        if self.severity not in SEVERITIES:
            raise ValueError(f"unknown severity {self.severity!r}")


@dataclass
class ScanContext:
    job_id: str
    base_url: str
    # operator-provided test identities for the authz engine, never real accounts
    identities: list[dict] = field(default_factory=list)
    options: dict[str, Any] = field(default_factory=dict)


class Engine(Protocol):
    name: str

    def run(self, client: httpx.Client, scope: ScopeSnapshot, ctx: ScanContext) -> list[RawFinding]: ...
