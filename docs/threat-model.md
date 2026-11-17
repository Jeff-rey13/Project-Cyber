# Threat model

Two systems, two models. Nimbus Air is the thing under test; AeroScan is a
security tool that can itself do damage if it's misused or compromised. The
second model matters more, because a scanner is a loaded weapon pointed at
whatever its operator types in.

Method: STRIDE per element, then a short list of abuse cases. Each threat
names the control that addresses it and where that control is tested.

---

## 1. Nimbus Air (target plane)

### 1.1 What it is and why it's shaped this way

A booking API for a fictional airline. It mirrors the three things that make
airline APIs different from a generic CRUD app:

- **The record locator (PNR) is treated as a credential.** "Manage my booking"
  flows have historically accepted surname + 6-character PNR, and PNRs end up
  printed on boarding passes, luggage tags and screenshots.
- **One booking record carries identity documents and payment data** (passport,
  DOB, masked card) because check-in and APIS need them.
- **Loyalty value is money.** Tier and points are fraud targets, so privileged
  profile fields have real value.

### 1.2 Data flow

```
passenger / partner app ──(bearer token)──► /auth/token, /me, /me/contact
                         ──(pnr [+ token])──► /bookings/{pnr}[/checkin|/baggage]
                                                  │
                                                  ▼
                                           sqlite (customers, bookings)
```

Trust boundary: the internet edge. Everything left of the arrow is untrusted.

### 1.3 STRIDE

| # | Threat | Element | Lab weakness | Control in secure mode | Test |
|---|---|---|---|---|---|
| S1 | Spoof another passenger by forging a token | `/auth/token`, bearer check | VULN-2: signature and expiry not verified | HMAC-SHA256 signed tokens, expiry enforced, constant-time compare | `test_vuln2_forged_token_impersonates_another_customer` |
| S2 | Act as a passenger using only their PNR | `GET /bookings/{pnr}` | VULN-2: anonymous lookups allowed | Bearer token required | `test_vuln2_anonymous_booking_lookup` |
| T1 | Raise own loyalty tier / role | `PATCH /me/contact` | VULN-4: mass assignment | `extra="forbid"` input model, privileged fields not bindable | `test_vuln4_mass_assignment_on_contact_update` |
| T2 | Check in or change bags on someone else's booking | `POST /bookings/{pnr}/*` | none (always owner-checked) | Ownership check, 404 on mismatch | `test_cannot_mutate_someone_elses_booking` |
| R1 | Passenger denies changing contact details | `/me/contact` | not addressed in the lab | Out of lab scope; would need an append-only change log | — |
| I1 | Read another passenger's booking | `GET /bookings/{pnr}` | VULN-1: BOLA | Owner check, same 404 for "not yours" and "doesn't exist" | `test_vuln1_bola_cross_customer_booking_read` |
| I2 | Itinerary lookup leaks DOB, passport, card | booking response | VULN-3: excessive data exposure | Separate minimal response schema | `test_vuln3_booking_leaks_passenger_pii` |
| I3 | Learn which emails have accounts | `/auth/token` | none | Identical error for unknown user and bad password | `test_login_rejects_bad_password_and_unknown_email_identically` |
| I4 | Learn the full API surface | `/openapi.json` | published by design | Accepted in the lab; flagged by the scanner as API9 | `api_inventory_exposure` finding |
| D1 | Enumerate PNRs to harvest bookings | `GET /bookings/{pnr}` | VULN-5: no rate limit | Per-client, per-identity fixed-window limiter, 429 + Retry-After | `test_vuln5_*` |
| E1 | Customer becomes admin | `/me/contact` | VULN-4 (role field) | Same as T1 | as T1 |

VULN-1 + VULN-2 + VULN-5 together form the realistic attack chain: no
credential needed, no throttle, and every valid PNR returns a full passenger
record. `test_vuln5_enumeration_actually_harvests_bookings` proves the chain
end to end.

---

## 2. AeroScan (control plane)

### 2.1 Assets

1. **Third parties' availability and data.** The biggest risk AeroScan carries
   is to systems that aren't its operator's.
2. The scan scope (what we're allowed to touch) and its proof of ownership.
3. Findings and evidence (they describe live weaknesses).
4. Operator credentials, the snapshot signing key, test-identity passwords.
5. The audit trail.

### 2.2 Trust boundaries

```
operator ──token──► control API ──► sqlite (jobs, scope, findings, audit)
                        │
                        ▼ enqueue
                     worker ──► guarded client ──► GATE ──► throttle ──► target
                        │                            ▲
                        └── gate proxy ◄── zap / nuclei / k6 (no other egress)
```

The gate is the one place where "should this packet leave?" is decided.
Everything else is arranged so there is no other way out.

### 2.3 STRIDE

| # | Threat | Control | Where tested |
|---|---|---|---|
| S1 | Someone other than the operator drives the scanner | Operator token on every route except `/health`; constant-time compare; API bound to host loopback in compose | `test_health_is_open_everything_else_needs_token` |
| S2 | Operator claims a domain they don't control | DNS TXT or hosted-file proof with a single-use, 24h, 256-bit token; old challenges retired on reissue | `test_verification.py` |
| S3 | "It resolves to 127.0.0.1, so it's the lab" (DNS rebinding) | Loopback self-verify accepts literal loopback addresses and `localhost` only; never resolves names | `test_loopback_self_verify_refuses_everything_else` |
| T1 | Scope edited mid-scan to add a host | Scope snapshot is frozen at queue time, HMAC-sealed, and the gate refuses any snapshot whose seal fails | `test_tampered_snapshot_*` (unit, property, integration) |
| T2 | Audit log rewritten to hide a scan | Hash-chained, append-only log; `verify_chain` reports the first broken entry; no update or delete code exists | `test_audit_chain_intact_then_detects_tamper` |
| R1 | Operator denies running a scan | Every verification step, scope capture, state transition and refusal is in the audit chain with actor | `test_every_step_is_audited`, `test_transitions_are_audited` |
| I1 | Evidence store becomes a PII store | Evidence redacted before storage (seed markers, DOB, passport, phone, email, card shapes); 400-char cap | `test_redaction_strips_markers_and_pii_shapes`, e2e evidence check |
| I2 | Test-identity passwords leak via the API | Stripped from every job view | `test_full_scan_through_api` |
| D1 | Scanner degrades the target | Adaptive throttle, non-configurable ceilings (20 req/s, 4 concurrent), abort after sustained stress; k6 aborts on its own thresholds | `test_throttle.py`, `test_throttle_forced_latency.py` |
| E1 | An engine sends traffic outside scope | Gate in the transport layer (sees redirects and hand-built requests); env proxies ignored; external engines only reach the target via the gate proxy, on an internal network | `test_guarded_client.py`, `test_gate_properties.py`, `test_external_engine_goes_through_proxy_only_during_scan` |
| E2 | URL parsing tricks bypass the gate | Strict parser: userinfo rejected, decoded-path dot segments rejected, `%5c` and control chars rejected, numeric TLDs rejected, IDNA alternate dots rejected; anything unexpected is DENY | Hypothesis suite (thousands of generated URLs per run) |

### 2.4 Abuse cases worth calling out

- **"Just scan this one URL quickly."** No code path does that. A scan needs a
  VERIFIED target, and the only ways to VERIFIED are the three proofs above.
- **Out-of-band callbacks.** Nuclei's interactsh would send data to a third-party
  server; it is force-disabled on the command line.
- **Engine compromise.** ZAP runs on a network with no internet and no route to
  the target. A compromised ZAP can only talk to the gate proxy, which only
  forwards in-scope requests.

### 2.5 Known gaps (honest list)

- External engines are HTTP-only through the gate proxy. HTTPS would need the
  proxy to terminate TLS to see paths; the in-process engines handle HTTPS fine.
- DNS rebinding *after* verification (a verified name later pointed at someone
  else's IP) isn't detected. Pinning the resolved IP into the snapshot is the
  fix.
- SQLite on a shared volume is fine for one operator. It is not a multi-user
  design.
- MAS TRM mappings are chapter-level; sub-clauses need checking against the
  published text.
