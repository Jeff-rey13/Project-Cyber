# Product Requirements Document — Squawk: Authorization-Gated Aviation Security Scanner

**Author:** [Your Full Name]
**Contact:** [your email]
**Version:** 2.0
**Last updated:** 2026-11-17
**Status:** Build spec — ready for implementation

---

## 0. How to use this document (read first)

This is the single source of truth. Build strictly in the order given in **Section 13 (Build Order)**. Do not scaffold modules out of sequence, and do not add anything not specified here without flagging it first. If a requirement is ambiguous, stop and ask before writing code. Accuracy and safety beat speed.

Four hard rules that bind every line of code, every commit, every document:

1. **Authorization is the product, not a feature.** Squawk must be structurally incapable of sending a single packet to a host that has not passed ownership verification. This is enforced in code at the request boundary with a default-deny gate (Section 5.1). There is no configuration, flag, or code path that bypasses it. A reviewer will try to break this; it must not break.
2. **Everything that imitates a real airline is fictional.** The only scan target in this project is the bundled, author-owned **Nimbus Air** lab. Real-company material (Scoot, SIA, aviation CVEs) appears only inside written research documents as case studies — never as a cloned site, a live target, or a submitted URL.
3. **Authorship is the repository owner's, and only theirs.** See Section 11.3. No co-author trailers, tool credits, or "generated with" notices anywhere — commits, PRs, headers, docstrings, READMEs, LICENSE.
4. **Comments read like a working engineer wrote them.** See Section 11.2. Explain intent and trade-offs, not the obvious. Natural and concise. Never manufacture artificial flaws or staged uncertainty.

---

## 1. Executive summary

Squawk is a self-hosted, authorization-first dynamic application security testing (DAST) platform built around the threats that matter to a modern airline: broken object-level authorization on booking references, broken authentication, excessive data exposure, and the API supply-chain surface created by interline and loyalty integrations.

Its defining property is restraint. Before any scan runs, the operator must cryptographically prove control of the target domain. Every outbound request is checked against an immutable, per-job scope policy with a default-deny gate. An adaptive throttle continuously backs off if the target shows stress — a "do no harm" control modelled on the reality that airline systems are safety-adjacent and must never be degraded by a security test.

The platform ships with its own test range: **Nimbus Air**, a deliberately vulnerable (fictional) airline booking stack. Squawk scans that range end to end, correlates findings from multiple engines, scores them by real-world context, and maps every result to OWASP, PCI DSS v4.0, and the MAS Technology Risk Management Guidelines.

The project is a portfolio piece for an Information Security & Risk Management internship. It is scoped so that one person can finish and polish it, and it is designed so that the single most impressive thing about it — a scanner that refuses to run until you prove you own the target — is also the thing that signals the right professional instinct to an aviation security team.

## 2. Goals and success criteria

### 2.1 Goals
- Demonstrate an authorization-first security engineering mindset in the architecture itself.
- Demonstrate real DAST capability: orchestrating industry engines, correlating output, scoring risk in context.
- Demonstrate aviation-specific depth with a purpose-built authorization-testing engine for booking-reference IDOR/BOLA.
- Demonstrate governance literacy: map every finding to OWASP, PCI DSS v4.0, and MAS TRM.
- Demonstrate testing maturity, including property-based testing of the safety-critical scope gate and a structured manual penetration test cross-checking the automated findings.

### 2.2 Success criteria (acceptance)
The project is done when all of the following hold:
- A reviewer clones the repo and reaches a fully working environment with one command.
- Squawk will not scan an unverified target — proven by an automated test suite that attempts to and is blocked every time.
- A full scan of the Nimbus Air range detects at least five distinct vulnerability classes, de-duplicated and correlated across engines.
- The authorization-testing engine independently finds the booking-reference BOLA and reports which identities could reach which objects.
- The adaptive throttle measurably backs off when the target is stressed (demonstrated with a forced-latency test).
- Every finding traces to a control ID in the compliance matrix across all three frameworks.
- The scope gate has property-based tests proving default-deny holds across fuzzed inputs; overall test coverage ≥ 85% on the control plane.
- A manual penetration-test report exists, aligned to OWASP WSTG, cross-checking Squawk's automated results.
- A 10-slide report PDF and a 3-minute demo script exist in `/docs`.
- The attribution audit (Section 11.3) returns zero tool/co-author strings across the tree and git history.

## 3. Scope

### 3.1 In scope
- Squawk: a self-hosted DAST control plane with ownership verification, scope enforcement, scanner orchestration, an authorization-testing engine, findings correlation, risk scoring, compliance mapping, scoped performance testing, and a dashboard.
- Nimbus Air: a bundled, deliberately vulnerable, fictional airline booking stack that serves as the only scan target.
- A manual penetration test of Nimbus Air and written research artifacts analysing the real aviation threat landscape as case studies.

### 3.2 Out of scope (do not build)
- Any ability to scan, stress, or probe a host the operator has not verified they control. No "quick scan this URL" path exists.
- Any reproduction of a real airline's branding, domain, login flow, or live endpoints.
- Multi-tenancy, billing, user self-service signup, or public hosting of the scanner. This is a single-operator, self-hosted tool.
- Any storage of real third-party personal data.

### 3.3 Ethics, legal, and safety guardrails (enforced in code, not just prose)
- **Verification precondition:** a target enters `VERIFIED` state only after a DNS TXT (or hosted-file) proof-of-control check passes. Scans accept only `VERIFIED` targets. The Nimbus Air lab self-verifies at bring-up via a loopback mechanism so the demo is turnkey, and that mechanism works only for the bundled loopback range — never for an arbitrary host.
- **Default-deny request gate:** every outbound request passes through `authorize_request()` (Section 5.1). Unknown host, out-of-scope path, or out-of-window time → deny and log.
- **Do-no-harm throttle:** the adaptive throttle (Section 5.5) reduces request rate automatically on rising latency or error rate. A hard ceiling on concurrency and requests-per-second is non-configurable above a safe maximum.
- **Isolation:** scanner engines run in their own container with no host network access beyond the scope-approved target.
- **Audit trail:** every scan records who initiated it, the verified scope, the proof-of-control artifact, and a full request log, written append-only.

## 4. System architecture

### 4.1 Two planes
The system separates the **target plane** (the thing being tested) from the **control plane** (the thing doing the testing). They never share a trust boundary; Squawk treats Nimbus Air as a black box reached only over the network, exactly as it would treat any external target.

```
┌───────────────────────────── CONTROL PLANE (Squawk) ─────────────────────────────┐
│                                                                                     │
│   ┌──────────────┐   ┌─────────────────────┐   ┌───────────────────────────────┐    │
│   │  Dashboard   │◄──│   Control API        │──►│  Scope & Authorization svc    │    │
│   │ (metrics/    │   │  (FastAPI)           │   │  - ownership verification     │    │
│   │  reports)    │   │  - scan lifecycle    │   │  - scope policy store         │    │
│   └──────────────┘   │  - auth on the tool  │   │  - authorize_request() gate   │    │
│                      └──────────┬───────────┘   └───────────────┬───────────────┘    │
│                                 │ enqueues jobs                 │ consulted on       │
│                                 ▼                               │ every request      │
│                      ┌──────────────────────┐                   │                    │
│                      │  Orchestrator /       │◄──────────────────┘                    │
│                      │  job queue (Redis)    │                                        │
│                      └──────────┬───────────┘                                         │
│          ┌──────────────────────┼───────────────────────┐                            │
│          ▼                      ▼                        ▼                            │
│  ┌───────────────┐    ┌──────────────────┐    ┌────────────────────┐                  │
│  │ ZAP adapter   │    │ Nuclei adapter   │    │ AuthZ test engine  │  (airline BOLA/  │
│  │ (DAST crawl)  │    │ (templated CVE)  │    │ (IDOR/BOLA probe)  │   IDOR, custom)  │
│  └───────┬───────┘    └────────┬─────────┘    └─────────┬──────────┘                  │
│          └──────────────┬──────┴────────────────────────┘                             │
│                         ▼                                                              │
│              ┌──────────────────────┐   ┌───────────────────────┐                     │
│              │ Findings normalizer   │──►│ Compliance mapper      │                     │
│              │ (dedup + correlate +  │   │ (OWASP/PCI/MAS TRM)    │                     │
│              │  risk scoring)        │   └───────────────────────┘                     │
│              └──────────────────────┘                                                 │
└───────────────────────────────────┬─────────────────────────────────────────────────┘
                                     │ network only, scope-gated
┌────────────────────────────────── ▼ ─────────── TARGET PLANE ─────────────────────────┐
│   Nimbus Air booking stack (FastAPI + SQLite, synthetic data, intentional vulns)       │
└────────────────────────────────────────────────────────────────────────────────────────┘
```

### 4.2 Squawk internal design notes
- **Scan lifecycle is an explicit state machine:** `DRAFT → PENDING_VERIFICATION → VERIFIED → QUEUED → RUNNING → (COMPLETED | FAILED | ABORTED)`. Transitions are centralised and logged; nothing runs a scan by reaching into internals.
- **The scope gate is a chokepoint, not a sprinkle.** All outbound HTTP from every adapter routes through one instrumented client that calls `authorize_request()` first. Adapters cannot construct their own unguarded client; the guarded client is the only one injected.
- **Engines are adapters behind a common interface** (`run(target, scope) -> list[RawFinding]`), so adding an engine never touches the gate or the normalizer.
- **The control API authenticates its own callers.** The scanner is a sensitive tool; its API is not open (Section 8).

### 4.3 Technology stack
Chosen for maturity and documentation, not novelty.
- **Control plane:** Python 3.12, FastAPI, Pydantic v2, SQLModel over PostgreSQL (SQLite acceptable for the single-operator build).
- **Job queue / workers:** Redis + RQ (simpler than Celery for this scale; swap only if justified).
- **Scanner engines:** OWASP ZAP (DAST crawl + active scan, run via its API in a container), Nuclei (templated checks). Wrapped, never reimplemented.
- **AuthZ test engine:** custom Python (this is your differentiator — see Section 5.2).
- **Performance testing:** k6, scope-gated and rate-capped.
- **Target plane:** Python 3.12, FastAPI, SQLModel over SQLite, synthetic seed data.
- **Dashboard:** vanilla HTML + Chart.js reading a metrics JSON endpoint. Dependency-light.
- **Testing:** pytest, Hypothesis (property-based), schemathesis (API contract/fuzz), coverage.py.
- **Packaging:** Docker Compose for one-command bring-up; Makefile fallback.

### 4.4 Repository structure
```
squawk/
├── README.md
├── PRD.md
├── docker-compose.yml
├── Makefile
├── .gitignore
├── .env.example
├── control-plane/
│   ├── app/
│   │   ├── main.py
│   │   ├── api/                 # scan lifecycle, target mgmt, reports
│   │   ├── scope/               # verification, policy store, authorize_request()
│   │   ├── orchestrator/        # job queue, state machine, guarded http client
│   │   ├── engines/             # zap_adapter.py, nuclei_adapter.py, authz_engine.py
│   │   ├── findings/            # normalizer, dedup, correlation, risk scoring
│   │   ├── compliance/          # framework mappers
│   │   └── perf/                # k6 orchestration (scoped)
│   └── tests/
│       ├── unit/
│       ├── property/            # scope-gate fuzzing (Hypothesis)
│       ├── integration/
│       └── e2e/
├── target-plane/
│   └── nimbus-air/              # the bundled vulnerable lab
│       ├── app/
│       └── tests/
├── compliance/
│   └── control-matrix.md
├── dashboard/
└── docs/
    ├── threat-model.md
    ├── pentest-report.md
    ├── report.md
    └── demo-script.md
```

## 5. Core algorithms (build these carefully — they are the technical heart)

### 5.1 Target authorization gate (safety-critical, default-deny)
Every outbound request is authorized before it leaves. The gate loads an immutable scope snapshot at job start; it is never re-read from mutable state mid-scan.

```
function authorize_request(request, job):
    # default deny — any path that does not explicitly ALLOW returns DENY
    host = canonical_host(request.url)            # lowercase, strip port if default, punycode-normalize
    scope = job.scope_snapshot                    # immutable, captured at VERIFIED->QUEUED

    if host not in scope.verified_hosts:          return DENY("host not verified")
    if not within_window(now(), scope.window):    return DENY("outside scan window")
    if path_denied(request.url.path, scope.deny):  return DENY("path on exclusion list")
    if not path_allowed(request.url.path, scope.allow): return DENY("path not in allow-list")
    if request.method in scope.forbidden_methods:  return DENY("method not permitted")
    return ALLOW
```

Ownership verification (precondition for a host ever entering `verified_hosts`):
```
function begin_verification(domain):
    token = hex(csprng(32))                       # cryptographically random, single-use
    store Verification(domain, token, expires=now()+24h, status=PENDING)
    return "_squawk-challenge." + domain + " TXT = " + token

function check_verification(domain):
    v = load_pending(domain)
    if v is None or expired(v):                   return FAIL
    published = dns_txt("_squawk-challenge." + domain)
    if any(constant_time_eq(r, v.token) for r in published):
        mark Verified(domain, proof=published, verified_at=now())
        return PASS
    return FAIL
```
Notes: constant-time comparison; single-use token; time-boxed; proof artifact retained for the audit trail. The bundled Nimbus Air loopback range self-verifies through an equivalent local proof so the demo needs no real DNS, and that shortcut is hard-restricted to the loopback range.

### 5.2 Authorization-testing engine — booking-reference BOLA/IDOR (your differentiator)
Generic scanners miss object-level authorization because they don't understand "whose object is this." This engine does, using seeded test identities.

```
function test_object_authorization(endpoints, identityA, identityB):
    findings = []
    for E in endpoints where E takes an object identifier:
        own = request(E, id=identityA.object_id, auth=identityA)      # baseline, expect 200
        if own.status != 200: continue                                # endpoint not usable as modelled

        # 1) horizontal: can A reach B's object?
        cross = request(E, id=identityB.object_id, auth=identityA)
        if cross.status == 200 and leaks_foreign_data(cross, identityB):
            findings.add(BOLA, E, severity=HIGH, evidence=redacted(cross))

        # 2) unauthenticated access
        anon = request(E, id=identityB.object_id, auth=None)
        if anon.status == 200:
            findings.add(BROKEN_AUTH, E, severity=CRITICAL, evidence=redacted(anon))

        # 3) identifier predictability signal (informs risk, not a finding alone)
        if looks_sequential_or_low_entropy(identityA.object_id, identityB.object_id):
            annotate(E, predictable_ids=True)
    return findings
```
Safeguards: runs only against verified-scope targets; uses only seeded identities the operator created; evidence is redacted before storage. `leaks_foreign_data` compares returned records against identityB's known seed markers so a 200 alone isn't treated as a leak.

### 5.3 Finding de-duplication and correlation
ZAP, Nuclei, and the AuthZ engine will overlap. Collapse them to one ranked list.
```
function fingerprint(finding):
    template = url_template(finding.url)          # /bookings/ABC123/checkin -> /bookings/{id}/checkin
    return sha256(finding.vuln_class + "|" + template + "|" + (finding.param or ""))

function correlate(raw_findings):
    buckets = group_by(fingerprint, raw_findings)
    merged = []
    for group in buckets:
        m = merge(group)
        m.severity   = max(f.severity for f in group)
        m.confidence = max(f.confidence for f in group)
        m.sources    = unique(f.engine for f in group)   # multi-engine agreement raises confidence
        merged.add(m)
    return merged
```
`url_template` canonicalizes dynamic path segments and strips volatile query values (session tokens, timestamps) so the same issue across many IDs collapses to one finding.

### 5.4 Context-aware risk scoring
CVSS alone is blunt. Weight by where the issue lives.
```
function risk_score(finding):
    base = cvss_base(finding)                     # 0..10
    mult = 1.0
    if finding.endpoint.requires_auth:            mult *= 1.3
    if finding.response_has_pii:                  mult *= 1.5   # names, DOB, passport, card patterns
    if finding.endpoint.state_changing:           mult *= 1.4   # POST/PUT/DELETE
    mult = min(mult, 2.0)                          # cap
    return round(base * mult, 1)

# scan report orders findings by risk_score desc, then by multi-engine confidence
```

### 5.5 Adaptive throttle (do-no-harm)
Protect the target. This is the control an airline reviewer will love.
```
# token bucket per host, with latency/error-driven rate adaptation
state: rate R (req/s), bucket B, rolling window W of (latency, status)

before each request:
    block until a token is available in B

after each response, every W_interval:
    avg_latency = mean(latency in W)
    err_rate    = fraction(status in {5xx, timeout} in W)
    if avg_latency > L_MAX or err_rate > E_MAX:
        R = max(R_MIN, R * 0.5)                    # back off hard
        log("throttle: backing off", R)
    elif healthy_for(N_windows):
        R = min(R_MAX, R * 1.2)                    # ramp gently
```
`R_MAX` and global concurrency have non-configurable hard ceilings. A sustained unhealthy signal aborts the scan with a clear reason rather than pushing through.

### 5.6 Crawl seeding and coverage
Feed ZAP good seeds and keep it in bounds.
```
function build_seed_set(target, scope):
    seeds = [target.base_url]
    seeds += parse_openapi(target)                # FastAPI exposes /openapi.json -> precise endpoint list
    seeds = [u for u in seeds if authorize_request(u, job) == ALLOW]
    return dedupe_by_template(seeds)
```
Using the target's own OpenAPI schema as a seed source gives near-complete endpoint coverage and doubles as an API inventory artifact in the report.

## 6. Module specifications

### 6.1 Target plane — Nimbus Air (the bundled, fictional vulnerable range)
A FastAPI booking stack over SQLite with synthetic data. Endpoints: token issuance, `GET /bookings/{pnr}`, check-in, baggage, contact update, `GET /me`, plus `/openapi.json`.

Intentional, documented weaknesses, each behind a `secure_mode` flag so fixed vs. broken can be shown side by side:
1. **BOLA** on `GET /bookings/{pnr}` — no ownership check; the centrepiece finding.
2. **Broken authentication** on the token path.
3. **Excessive data exposure** — booking returns masked card, DOB, full itinerary.
4. **Mass assignment** on contact update.
5. **Missing rate limiting** on booking lookup (enables enumeration) — gives the throttle and enumeration story something to bite on.

All data synthetic, obviously fake card values, generated by a deterministic seed. Every weakness ships with a reproducing test and a plain-language docstring. Acceptance: pytest proves each is exploitable in insecure mode and blocked in secure mode.

### 6.2 Scope & Authorization service
Implements Sections 5.1 verification and gate. Stores targets, verification proofs, and immutable per-job scope snapshots. Exposes: begin verification, check verification, define scope (allow/deny paths, window, methods). Acceptance: no target reaches `VERIFIED` without a passing proof; the gate is the sole outbound chokepoint.

### 6.3 Orchestrator + scanner adapters
State machine, Redis-backed job queue, and the single guarded HTTP client injected into every adapter. ZAP adapter drives crawl + active scan via ZAP's API; Nuclei adapter runs templated checks. Adapters return `RawFinding`s in the common shape. Acceptance: a scan runs engines concurrently within concurrency caps, and no adapter can emit a request that bypasses the gate (proven by test).

### 6.4 Authorization-testing engine
Implements Section 5.2. Acceptance: independently finds the Nimbus Air BOLA and the unauthenticated-access case, and reports the identity-to-object reachability matrix with redacted evidence.

### 6.5 Findings normalizer + compliance mapper
Implements 5.3 and 5.4, then maps each merged finding to OWASP API/Web Top 10, OWASP LLM Top 10 (if the chatbot stretch module is included), PCI DSS v4.0, and MAS TRM domains. Acceptance: a single ranked findings list, every item carrying all three framework references.

### 6.6 Performance testing module (scoped, safe)
k6 load profiles that run only against a `VERIFIED` target, through the same rate ceilings and the adaptive throttle. Reports latency percentiles and error rate under load. Acceptance: refuses an unverified target; respects hard caps; produces a short performance summary.

### 6.7 Dashboard
Reads a `/metrics` JSON endpoint. Panels: scan posture score, findings by severity and framework, throttle behaviour over a scan (rate vs. latency), authorization-gate denials counter, compliance coverage heatmap. All live from real scan activity, never hardcoded.

### 6.8 Stretch module (optional) — LLM booking-assistant sandbox
If time allows, add the Nimbus Air chatbot (local LLM + function calling) and a prompt-injection test suite mapped to the OWASP LLM Top 10, with a hardened system prompt + tool allow-list as the mitigation. Clearly marked optional in the build order.

## 7. Data model (key schemas)

**Finding (normalized):**
```
id, fingerprint, vuln_class, title, description,
url_template, param, method,
severity (info|low|medium|high|critical), cvss_base, risk_score, confidence,
sources[] (zap|nuclei|authz), evidence_redacted,
frameworks { owasp[], pci_dss_v4[], mas_trm[] },
remediation, first_seen, last_seen
```
**Scope snapshot (immutable per job):**
```
job_id, verified_hosts[], allow_paths[], deny_paths[], window, forbidden_methods[],
proof_ref, captured_at
```

## 8. Security of the tool itself
A scanner is a sensitive asset; secure it like one.
- The control API requires authentication (local operator token); it is not exposed publicly.
- Scope snapshots are integrity-protected; the audit log is append-only.
- Scanner engines run in an isolated container with egress limited to the scope-approved target.
- Secrets live only in environment, never in the repo; `.gitignore` covers env files, scan artifacts, and any binary.
- Redacted evidence only — no raw PII, even synthetic, beyond what a finding needs to be credible.

## 9. Testing strategy (top-notch, and the acceptance gate for shipping)

### 9.1 Layers
- **Unit tests** for every pure function: canonicalization, fingerprinting, risk scoring, throttle math.
- **Property-based tests (Hypothesis) on the scope gate** — the safety-critical component. Generate adversarial hosts, paths, encodings (unicode, punycode, path traversal, case tricks, embedded credentials, SSRF-style `host@evil`, IP-literal and decimal-IP forms) and assert `authorize_request` returns DENY for anything not explicitly in scope. Default-deny must hold across the entire generated space.
- **Contract/fuzz tests (schemathesis)** against the control API from its OpenAPI schema.
- **Integration tests** for the state machine, queue, and engine adapters (adapters pointed at a mock target; assert every request passed the gate).
- **Paired exploit/fix tests** on Nimbus Air: each vuln exploitable in insecure mode, blocked in secure mode.
- **End-to-end:** bring up lab → verify → scan → assert the expected findings appear, correlated and scored; assert a scan against an unverified target is refused.
- **Throttle test:** inject artificial latency into the target and assert the measured request rate drops.

### 9.2 Coverage and CI
- Control-plane coverage ≥ 85%; the `scope/` package ≥ 95% (it is safety-critical).
- `make test` runs everything; CI runs it on every push and blocks merge on failure or coverage regression.

## 10. Penetration testing methodology and deliverables (top-notch, human-led)
Automated scanning is necessary but not sufficient; a strong candidate shows they know that.

- **Methodology:** align to OWASP WSTG and PTES. Phases: scoping → information gathering (use the OpenAPI inventory) → threat modelling (STRIDE, feeds `docs/threat-model.md`) → manual testing with **Burp Suite** → exploitation PoC → remediation → retest.
- **Manual testing focus:** object-level authorization (confirm the engine's BOLA finding by hand and extend it), authentication logic, business-logic flaws a scanner can't see (e.g. price/seat manipulation, enumeration-driven PNR harvesting), and input handling.
- **Cross-check:** a section of the report compares Squawk's automated findings against the manual findings — what the tool caught, what it missed, and why. This single comparison is one of the most senior things in the whole project.
- **Deliverable:** `docs/pentest-report.md` with an executive summary, methodology, findings (each with CVSS, reproduction steps, redacted PoC, business impact, remediation), and a retest outcome after fixes.

## 11. Coding standards and conventions

### 11.1 General
- Python: PEP 8, type hints on public functions, `ruff` clean. Small functions, clear names.
- Commit in small logical units with present-tense messages ("add scope gate default-deny", "wire nuclei adapter through guarded client").

### 11.2 Comment and docstring voice
Write for a teammate. Comment the *why* and the non-obvious, not the obvious. Keep them short and conversational; lowercase-casual inline is fine, full sentences in docstrings where needed. Lead a docstring with the verb or the point, not "This function...". It's good to note honestly why a shortcut exists or where a known limitation sits — e.g. `# loopback self-verify only; anything outside 127.0.0.0/8 must go through real dns proof`. Don't over-comment, and never narrate how the code was produced. Do not manufacture fake typos, staged uncertainty, or artificial mistakes — natural means clear, not broken.

### 11.3 Authorship and attribution (strict)
- The repository owner named at the top is the sole author of all work.
- Do not add co-author trailers, "generated with" lines, tool credits, or assistant identities to any commit, PR description, file header, docstring, README, or LICENSE.
- Git `user.name`/`user.email` are the owner's; commits carry only the owner's identity.
- LICENSE and any copyright line name only the owner.
- Remove any such line a scaffold tries to insert before committing. The final acceptance step greps the tree and `git log` for tool/assistant/co-author strings; there must be zero.

## 12. Non-functional requirements
- One-command bring-up (`docker compose up` / `make up`) yields a working environment with Nimbus Air self-verified and ready to scan.
- Deterministic seed data.
- No secrets in the repo; `.env.example` provided.
- Core demo runs offline (no paid third-party API).
- README leads with a 60-second what/why/how-to-run.

## 13. Build order (follow exactly)
1. Repo skeleton, `.gitignore`, `.env.example`, Docker Compose, Makefile, README stub. Commit.
2. Nimbus Air: data model + deterministic seed. Commit.
3. Nimbus Air: endpoints in **secure mode** first (prove correct behaviour). Commit.
4. Nimbus Air: insecure-mode toggles + paired exploit tests. Commit.
5. Scope service: ownership verification + immutable scope snapshot. Commit.
6. The guarded HTTP client + `authorize_request()` gate, with **property-based tests first** (default-deny must hold before anything can scan). Commit.
7. Orchestrator + state machine + Redis queue. Commit.
8. ZAP adapter through the guarded client; OpenAPI-seeded crawl. Commit.
9. Nuclei adapter. Commit.
10. Authorization-testing engine (BOLA/IDOR) + tests. Commit.
11. Findings normalizer: dedup, correlation, risk scoring + tests. Commit.
12. Compliance mapper (OWASP + PCI DSS v4.0 + MAS TRM). Commit.
13. Adaptive throttle + forced-latency test. Commit.
14. Dashboard reading live metrics. Commit.
15. Performance module (k6, scoped). Commit.
16. End-to-end tests, including the "refuse unverified target" case. Commit.
17. Threat model, pentest report, report source, demo script. Commit.
18. Optional stretch: LLM chatbot sandbox + injection suite.
19. Final pass: acceptance checklist (Section 2.2), attribution audit (Section 11.3), README polish. Tag v1.0.

## 14. Deliverables checklist
- [ ] One-command working environment with Nimbus Air self-verified
- [ ] Scope gate with property-based default-deny tests (≥95% coverage on `scope/`)
- [ ] Ownership verification working, with retained proof artifact
- [ ] ZAP + Nuclei adapters routed through the guarded client
- [ ] Authorization-testing engine finding the booking BOLA independently
- [ ] Findings correlated across engines, context-risk-scored
- [ ] Adaptive throttle with a demonstrated back-off
- [ ] Compliance matrix across OWASP + PCI DSS v4.0 + MAS TRM
- [ ] Live security dashboard
- [ ] Scoped k6 performance module
- [ ] Threat model + manual pentest report cross-checking the automated findings
- [ ] "Refuse unverified target" proven by an automated test
- [ ] 10-slide report PDF + 3-minute demo script
- [ ] Attribution audit passed (zero tool/co-author strings)

## 15. Interview and presentation assets
- `docs/report.md` is the source for a 10-slide PDF: aviation threat landscape → why authorization-first → architecture → the scope gate (and a live refusal of an unverified target) → BOLA engine demo → correlated findings + risk scoring → adaptive throttle (do-no-harm) → compliance mapping → manual-vs-automated comparison → recommendations/closing.
- `docs/demo-script.md` is a tight 3 minutes: attempt a scan on an unverified host (watch it refuse), verify the lab, run the scan, watch the BOLA engine surface the finding and the throttle back off under injected latency, open the dashboard.

---

*End of document.*
