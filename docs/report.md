# AeroScan: authorization-first security testing for airline APIs

Source for the 10-slide deck. One `##` per slide; speaker notes under each.

---

## 1. Airline APIs leak through authorization, not exotic exploits

- British Airways, 2018: payment-page skimming, roughly 400k customers; £20m ICO fine (2020)
- Cathay Pacific, 2018: about 9.4m passengers' records exposed
- SITA PSS, 2021: a shared passenger-service provider breached, affecting many carriers' frequent-flyer members including Singapore Airlines KrisFlyer
- Pattern: identity documents and loyalty value, reachable via APIs and partners

*Notes: check every figure against the regulator or company statement before
presenting. The point isn't the numbers, it's that the data is identity-grade
and the paths are integrations.*

## 2. Why "authorization-first"

- A scanner is a weapon pointed at whatever URL you type
- Airline systems are safety-adjacent: degrading them is unacceptable
- So the product's first job is refusing to scan. Finding bugs comes second.

## 3. Architecture

- Control plane (AeroScan) vs target plane (Nimbus Air), network-only contact
- One guarded HTTP client; external engines (ZAP, Nuclei, k6) only via the gate proxy
- Scan lifecycle as an explicit state machine; every transition audited

*Diagram: threat-model.md §2.2.*

## 4. The scope gate

- Ownership proof: DNS TXT / hosted file, single-use 256-bit token, 24h expiry
- Scope frozen at queue time and HMAC-sealed; the gate refuses a broken seal
- Default deny: host, window, method, deny-list, allow-list, then ALLOW
- Hypothesis property tests: userinfo, `%2e%2e`, `%5c`, decimal IPs, IDNA dots
- **Live: refuse an unverified host**

*Notes: mention that the property tests found two real bypass candidates
during development (encoded backslash, ideographic full stop), both fixed.*

## 5. Booking-reference BOLA engine

- Two seeded identities, each with their own PNRs and "markers" (name, passport)
- A response only counts as a leak if the *victim's* markers appear
- Output: identity × object reachability matrix, evidence redacted before storage
- Only replays safe methods across identities: it never checks someone else in

## 6. Correlation and context risk

- Fingerprint = class + URL template + param, so 1000 PNRs collapse to one finding
- Multi-engine agreement raises confidence
- Risk = CVSS × context (auth 1.3, PII 1.5, state-changing 1.4, cap 2×)
- Lab result: 7 findings, ranked 17.7 → 3.1

## 7. Do-no-harm throttle

- Token bucket; halve on high latency or errors, ×1.2 after sustained health
- Hard ceilings: 20 req/s, 4 concurrent, not configurable upward
- Sustained stress means the scan aborts and says why
- Forced-latency test against the real lab: 10 → 5 → 2.5 → 1.25 → 0.625 req/s

## 8. Compliance mapping

- Every finding → OWASP API Top 10 2023 + OWASP Top 10 2021, PCI DSS v4.0, MAS TRM
- Generated control matrix, tested to stay in sync with the code
- MAS TRM is a financial-sector guideline, used as the Singapore benchmark for payments + loyalty

## 9. Automated vs manual

- Scanner found all five lab flaws and the hygiene issues
- It did **not** separately report forged-token acceptance: hidden behind the unauthenticated-access finding
- Business logic (fare/seat manipulation, races) needs a human with Burp
- [Fill from pentest-report.md §5 after the manual session]

## 10. What I'd do next

- Pin resolved IPs into the scope snapshot (closes post-verification DNS rebinding)
- TLS-terminating gate proxy so external engines can scan HTTPS targets
- Authorization matrix for partner/interline API keys, not just passengers
- Recommendations for an airline: treat the PNR as an identifier, not a credential; per-identity rate limits on lookup; response schemas per use case
