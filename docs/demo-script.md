# Demo script (3 minutes)

Setup before the call: `make up` already run, dashboard open in a browser tab
and logged in with the operator token, a terminal in the repo root, `make
identities` already run. Font size up.

---

**0:00 to 0:20: the premise**

> "Squawk is a security scanner for airline booking APIs. The thing I want
> you to remember about it is that it won't send a single packet to a host
> until you've proven you own it. Let me show you it refusing."

**0:20 to 0:45: refusal**

```
make refuse-demo
```

Point at: `PENDING_VERIFICATION`, then `409 ... only VERIFIED scans can be queued`.

> "No flag turns that off. The check isn't in the UI, it's in the one HTTP
> client every engine is given, and it's property-tested against thousands of
> generated URL tricks: userinfo, encoded traversal, decimal IPs, Unicode dots."

**0:45 to 1:05: verification**

> "The lab on the right is Nimbus Air, a fake airline I wrote with five
> deliberate flaws. It's on loopback, so it verified itself at startup. A
> real domain would need a DNS TXT record with a one-time token."

Dashboard: gate denials panel shows the refusal from a moment ago.

**1:05 to 2:00: the scan**

```
make scan ENGINES=authz,api_checks
```

While it runs:

> "Generic scanners miss the booking-reference bug because they don't know
> whose booking is whose. This engine logs in as two seeded passengers and
> asks for each other's bookings. It only calls it a leak if the other
> person's name or passport actually appears in the response."

When it finishes, read the top three lines aloud: unauthenticated booking
read (critical), BOLA (high), mass assignment (high), each with an OWASP, PCI
DSS and MAS TRM reference.

**2:00 to 2:35: do no harm**

```
NIMBUS_INJECT_LATENCY_MS=400 docker compose up -d nimbus-air
make scan ENGINES=authz,api_checks
```

Dashboard: throttle panel. The rate line steps down as the latency line rises,
and the scan ends ABORTED with "stopping to avoid harm".

> "Airline systems are safety-adjacent. If the target looks stressed, the
> scanner halves its rate, and if it stays stressed it stops and says why."

**2:35 to 3:00: close**

Flip `NIMBUS_SECURE_MODE=true`, restart the lab, rescan (or show a
pre-recorded result): posture score goes from about 31 to 94, the five
application findings are gone.

> "Same scanner, same lab, flaws fixed: the findings go away. Thanks, happy
> to go into the gate, the engine or the compliance mapping."

---

Fallback if Docker misbehaves: `make test` shows the same story from the end-to-end tests
(`tests/e2e/test_end_to_end.py`), including the refusal test.
