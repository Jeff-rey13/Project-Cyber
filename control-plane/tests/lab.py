"""Spin up a real Nimbus Air process on loopback for integration tests.

Runs in a subprocess so the lab's `app` package doesn't collide with ours,
and so the scanner talks to it over a real socket like it would in prod.
"""

import os
import socket
import sqlite3
import subprocess
import sys
import time
from contextlib import contextmanager
from pathlib import Path

import httpx

LAB_DIR = Path(__file__).resolve().parents[2] / "target-plane" / "nimbus-air"
IDENTITIES = {"alice": ("alice@nimbus.test", "alice-lab-pass"), "bob": ("bob@nimbus.test", "bob-lab-pass")}


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@contextmanager
def nimbus(tmp_path: Path, secure: bool, extra_env: dict | None = None):
    port = _free_port()
    db = tmp_path / f"nimbus-{'secure' if secure else 'insecure'}.db"
    env = {**os.environ, "NIMBUS_SECURE_MODE": "true" if secure else "false",
           "NIMBUS_DATABASE_URL": f"sqlite:///{db.as_posix()}", **(extra_env or {})}
    proc = subprocess.Popen(
        [sys.executable, "-m", "uvicorn", "app.asgi:app", "--host", "127.0.0.1", "--port", str(port), "--log-level", "warning"],
        cwd=LAB_DIR, env=env, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
    )
    base = f"http://127.0.0.1:{port}"
    try:
        for _ in range(100):
            try:
                if httpx.get(base + "/health", timeout=0.5).status_code == 200:
                    break
            except httpx.HTTPError:
                time.sleep(0.1)
        else:
            raise RuntimeError("nimbus lab did not start: " + (proc.stderr.read().decode() if proc.stderr else ""))
        yield base, db
    finally:
        proc.terminate()
        proc.wait(timeout=10)


def identities_from_db(db: Path) -> list[dict]:
    """What an operator would put in their scan config for the two seeded lab identities."""
    con = sqlite3.connect(db)
    try:
        out = []
        for label, (email, password) in IDENTITIES.items():
            cid, name, passport = con.execute("select id, full_name, passport_no from customer where email=?", (email,)).fetchone()
            pnrs = [r[0] for r in con.execute("select pnr from booking where customer_id=? order by pnr", (cid,))]
            out.append({"label": label, "email": email, "password": password, "objects": pnrs, "markers": [name, passport]})
        return out
    finally:
        con.close()
