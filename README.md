# AeroScan

**A security scanner for airline booking APIs that refuses to scan anything you haven't proven you own.**

- **What:** a self-hosted DAST platform. It verifies domain ownership, freezes the scan scope, runs ZAP, Nuclei and a purpose-built booking-reference BOLA engine through one default-deny gate, correlates and risk-scores the results, and maps each one to OWASP, PCI DSS v4.0 and MAS TRM.
- **Why:** airline systems carry passport-grade data and are safety-adjacent. A scanner that can be pointed at anything, or that hammers a struggling backend, is a liability. This one is built so it can't do either.
- **Target:** ships with **Nimbus Air**, a fictional airline booking API with five deliberate flaws, each with a `secure_mode` fix. It is the only thing this project scans.

## Run it

```bash
make up           # generates .env secrets, builds, starts; the lab self-verifies
make refuse-demo  # watch it refuse an unverified host
make scan         # full scan of the lab with all engines
```

Dashboard: <http://127.0.0.1:8000/dashboard/> (operator token is `AEROSCAN_OPERATOR_TOKEN` in `.env`).
Lab API docs: <http://127.0.0.1:8080/docs>. Everything binds to loopback only.

No Docker? The test suite runs the same story in-process:

```bash
python -m venv .venv && .venv/Scripts/pip install -r control-plane/requirements.txt   # bin/ on macOS/Linux
make test
```

## What a scan of the lab finds

| # | Finding | Severity | Risk (0–20) | OWASP | PCI DSS v4.0 |
|---|---|---|---|---|---|
| 1 | Booking lookup needs no authentication | critical | 17.7 | API2:2023 | 8.3.1 |
| 2 | BOLA: passengers can read each other's bookings | high | 14.6 | API1:2023 | 7.2.1 |
| 3 | Loyalty tier writable via contact update | high | 13.6 | API3:2023 | 7.2.2 |
| 4 | Itinerary lookup returns passport, DOB, card | medium | 10.3 | API3:2023 | 3.4.1 |
| 5 | No rate limit on booking lookup | medium | 6.9 | API4:2023 | 8.3.4 |
| 6 | OpenAPI schema public | low | 3.1 | API9:2023 | 12.5.1 |
| 7 | Security headers missing | low | 3.1 | API8:2023 | 2.2.1 |

With `NIMBUS_SECURE_MODE=true`, 1–5 disappear (posture score 31 → 94).

## How the safety works

| Control | Where | Proven by |
|---|---|---|
| Ownership proof (DNS TXT / hosted file / loopback-only for the lab) | `control-plane/app/scope/verification.py` | `tests/unit/test_verification.py` |
| Sealed, immutable per-scan scope | `app/scope/snapshot.py` | `tests/unit/test_snapshot_and_audit.py` |
| Default-deny gate on every request | `app/scope/gate.py` | `tests/property/test_gate_properties.py` (Hypothesis) |
| One guarded client; external engines only via the gate proxy | `app/orchestrator/guarded_client.py`, `gate_proxy.py` | `tests/integration/test_guarded_client.py`, `test_wiring.py` |
| Adaptive throttle with hard ceilings and abort | `app/orchestrator/throttle.py` | `tests/integration/test_throttle_forced_latency.py` |
| Hash-chained audit log | `app/scope/audit.py` | `test_audit_chain_intact_then_detects_tamper` |
| Refuse unverified targets end to end | API + lifecycle | `tests/e2e/test_end_to_end.py` |

Coverage: 99% control plane, 99% `scope/`.

## Repository

```
control-plane/     AeroScan: api, scope gate, orchestrator, engines, findings, compliance, perf
target-plane/      Nimbus Air: the fictional vulnerable booking API
dashboard/         static dashboard reading /metrics
compliance/        generated control matrix
docs/              threat model, pentest report, deck source, demo script
```

## Engines

| Engine | What it does | How it reaches the target |
|---|---|---|
| `authz` | Booking-reference BOLA/IDOR with seeded identities and a reachability matrix | guarded client |
| `api_checks` | Excessive data exposure, mass assignment, rate limiting, inventory, headers | guarded client |
| `zap` | OpenAPI-seeded spider + active scan | gate proxy (compose) |
| `nuclei` | Templated checks incl. bundled lab templates; interactsh disabled | gate proxy (compose) |
| k6 perf | Scoped load profiles, aborts on latency/error thresholds | gate proxy |

## Known limits

External engines can't scan HTTPS targets yet (the gate proxy doesn't terminate TLS), and post-verification DNS rebinding isn't detected. Both are covered in `docs/threat-model.md` §2.5.

## Ethics

Nimbus Air and all its data are fictional and synthetic. Real airlines appear only as cited case studies in `docs/report.md`. Don't point AeroScan at anything you don't own; it's built to stop you, but the responsibility is still yours.
