"""Thin operator cli over the control api.

    python -m app.cli scan --identities identities.json --engines authz,api_checks,zap,nuclei
    python -m app.cli try-unverified http://example.com
    python -m app.cli findings <scan-id>

Reads SQUAWK_API (default http://127.0.0.1:8000) and SQUAWK_OPERATOR_TOKEN.
"""

import argparse
import json
import os
import sys
import time
from datetime import datetime, timedelta, timezone
from urllib.parse import urlsplit

import httpx

TERMINAL = {"COMPLETED", "FAILED", "ABORTED"}


def _client() -> httpx.Client:
    # inside the api container the token is already in the environment via env_file
    token = os.getenv("SQUAWK_OPERATOR_TOKEN", "")
    if not token:
        sys.exit("set SQUAWK_OPERATOR_TOKEN")
    return httpx.Client(base_url=os.getenv("SQUAWK_API", "http://127.0.0.1:8000"),
                        headers={"Authorization": f"Bearer {token}"}, timeout=30, trust_env=False)


def _scope(host: str, hours: float, deny: list[str]) -> dict:
    now = datetime.now(timezone.utc)
    return {"hosts": [host], "deny_paths": deny, "window_start": now.isoformat(),
            "window_end": (now + timedelta(hours=hours)).isoformat()}


def _print_findings(rows: list[dict]) -> None:
    if not rows:
        print("no findings")
        return
    for f in rows:
        fw = f["frameworks"]
        print(f"{f['rank']:>2}. [{f['severity']:<8}] risk {f['risk_score']:>4}  {f['title']}")
        print(f"     {f['url_template']}  engines={','.join(f['sources'])}")
        print(f"     {fw['owasp'][0]} | PCI {fw['pci_dss_v4'][0].split(' ')[0]} | {fw['mas_trm'][0]}")


def cmd_scan(a) -> int:
    if a.identities == "-":
        # piped in, so nothing has to be copied into the container first
        opts = json.load(sys.stdin)
    elif a.identities:
        with open(a.identities, encoding="utf-8") as fh:
            opts = json.load(fh)
    else:
        opts = {}
    host = urlsplit(a.base_url).hostname
    with _client() as c:
        r = c.post("/scans", json={"base_url": a.base_url, "scope": _scope(host, a.hours, a.deny),
                                   "engines": a.engines.split(","), "options": opts})
        if r.status_code != 201:
            print(f"refused: {r.json().get('detail')}")
            return 1
        job = r.json()
        print(f"scan {job['id']} created, state {job['state']}")
        q = c.post(f"/scans/{job['id']}/queue")
        if q.status_code != 200:
            print(f"refused to queue: {q.json().get('detail')}")
            return 1
        state = q.json()["state"]
        while state not in TERMINAL:
            time.sleep(2)
            state = c.get(f"/scans/{job['id']}").json()["state"]
            print(f"  ... {state}")
        final = c.get(f"/scans/{job['id']}").json()
        if final.get("error"):
            print(f"note: {final['error']}")
        errors = (final.get("options") or {}).get("engine_errors") or []
        for e in errors:
            # partial results are still results, but nobody should mistake them for a clean scan
            print(f"WARNING engine failed: {e}")
        _print_findings(c.get(f"/scans/{job['id']}/findings").json())
    return 0 if state == "COMPLETED" and not errors else 2


def cmd_try_unverified(a) -> int:
    host = urlsplit(a.url).hostname
    with _client() as c:
        r = c.post("/scans", json={"base_url": a.url, "scope": _scope(host, 1, []), "engines": ["authz"]})
        if r.status_code != 201:
            print(f"refused at create: {r.json().get('detail')}")
            return 0
        job = r.json()
        print(f"scan {job['id']} is {job['state']}")
        q = c.post(f"/scans/{job['id']}/queue")
        print(f"queue -> {q.status_code}: {q.json().get('detail', q.json().get('state'))}")
        return 0 if q.status_code == 409 else 1


def cmd_findings(a) -> int:
    with _client() as c:
        _print_findings(c.get(f"/scans/{a.scan_id}/findings").json())
    return 0


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="squawk")
    sub = p.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("scan")
    s.add_argument("--base-url", default="http://127.0.0.1:8080")
    s.add_argument("--identities", help="json file with {'identities': [...]}, or - for stdin")
    s.add_argument("--engines", default="authz,api_checks")
    s.add_argument("--hours", type=float, default=1.0)
    s.add_argument("--deny", action="append", default=[])
    s.set_defaults(fn=cmd_scan)
    t = sub.add_parser("try-unverified")
    t.add_argument("url")
    t.set_defaults(fn=cmd_try_unverified)
    f = sub.add_parser("findings")
    f.add_argument("scan_id")
    f.set_defaults(fn=cmd_findings)
    a = p.parse_args(argv)
    return a.fn(a)


if __name__ == "__main__":
    sys.exit(main())
