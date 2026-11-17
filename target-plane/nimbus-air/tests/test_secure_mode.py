"""Secure mode is the reference behaviour; these pin it down before any weakness is added."""

import time

import pytest
from fastapi.testclient import TestClient
from sqlmodel import Session, select

from app import tokens
from app.config import Settings
from app.db import init_db, make_engine
from app.main import create_app
from app.models import Booking, Customer

ALICE = ("alice@nimbus.test", "alice-lab-pass")
BOB = ("bob@nimbus.test", "bob-lab-pass")


@pytest.fixture
def lab():
    engine = make_engine("sqlite://")
    init_db(engine)
    settings = Settings(secure_mode=True, database_url="sqlite://", lookup_limit=5)
    return TestClient(create_app(settings, engine)), engine, settings


def login(client, creds):
    r = client.post("/auth/token", json={"email": creds[0], "password": creds[1]})
    assert r.status_code == 200, r.text
    return {"Authorization": f"Bearer {r.json()['access_token']}"}


def pnrs_of(engine, email):
    with Session(engine) as s:
        cid = s.exec(select(Customer.id).where(Customer.email == email)).one()
        return [b.pnr for b in s.exec(select(Booking).where(Booking.customer_id == cid))]


def test_health_reports_mode(lab):
    client, _, _ = lab
    assert client.get("/health").json() == {"status": "ok", "secure_mode": True}


def test_openapi_is_published(lab):
    client, _, _ = lab
    paths = client.get("/openapi.json").json()["paths"]
    assert {"/auth/token", "/me", "/me/contact", "/bookings/{pnr}", "/bookings/{pnr}/checkin", "/bookings/{pnr}/baggage"} <= set(paths)


# --- auth ---

def test_login_rejects_bad_password_and_unknown_email_identically(lab):
    client, _, _ = lab
    a = client.post("/auth/token", json={"email": ALICE[0], "password": "nope"})
    b = client.post("/auth/token", json={"email": "ghost@nimbus.test", "password": "nope"})
    assert a.status_code == b.status_code == 401
    assert a.json() == b.json()


def test_forged_token_rejected(lab):
    client, engine, _ = lab
    forged = tokens.issue(1, "not-the-secret", 3600)
    assert client.get("/me", headers={"Authorization": f"Bearer {forged}"}).status_code == 401


def test_expired_token_rejected(lab):
    client, _, settings = lab
    old = tokens.issue(1, settings.token_secret, 60, now=time.time() - 3600)
    assert client.get("/me", headers={"Authorization": f"Bearer {old}"}).status_code == 401


@pytest.mark.parametrize("header", ["", "Bearer", "Bearer garbage", "Basic abc", "Bearer a.b"])
def test_malformed_auth_rejected(lab, header):
    client, _, _ = lab
    assert client.get("/me", headers={"Authorization": header} if header else {}).status_code == 401


# --- object-level authorization ---

def test_owner_can_read_own_booking(lab):
    client, engine, _ = lab
    pnr = pnrs_of(engine, ALICE[0])[0]
    r = client.get(f"/bookings/{pnr}", headers=login(client, ALICE))
    assert r.status_code == 200 and r.json()["pnr"] == pnr


def test_cannot_read_someone_elses_booking(lab):
    client, engine, _ = lab
    bob_pnr = pnrs_of(engine, BOB[0])[0]
    r = client.get(f"/bookings/{bob_pnr}", headers=login(client, ALICE))
    # same answer as a pnr that doesn't exist
    assert r.status_code == 404
    assert client.get("/bookings/ZZZZZZ", headers=login(client, ALICE)).json() == r.json()


def test_anonymous_booking_lookup_rejected(lab):
    client, engine, _ = lab
    assert client.get(f"/bookings/{pnrs_of(engine, BOB[0])[0]}").status_code == 401


@pytest.mark.parametrize("action,body", [("checkin", None), ("baggage", {"bags": 2})])
def test_cannot_mutate_someone_elses_booking(lab, action, body):
    client, engine, _ = lab
    bob_pnr = pnrs_of(engine, BOB[0])[0]
    r = client.post(f"/bookings/{bob_pnr}/{action}", json=body, headers=login(client, ALICE))
    assert r.status_code == 404
    with Session(engine) as s:
        b = s.get(Booking, bob_pnr)
        assert not b.checked_in and b.bags == 0


# --- data exposure ---

def test_booking_response_has_no_sensitive_fields(lab):
    client, engine, _ = lab
    pnr = pnrs_of(engine, ALICE[0])[0]
    body = client.get(f"/bookings/{pnr}", headers=login(client, ALICE)).json()
    for field in ("passenger_dob", "passport_no", "card_masked", "customer_id", "phone", "email"):
        assert field not in body


def test_profile_never_returns_password_hash_or_passport(lab):
    client, _, _ = lab
    body = client.get("/me", headers=login(client, ALICE)).json()
    assert "password_hash" not in body and "passport_no" not in body and "role" not in body


# --- mass assignment ---

def test_contact_update_changes_allowed_fields(lab):
    client, _, _ = lab
    r = client.patch("/me/contact", json={"phone": "+65 91234567"}, headers=login(client, ALICE))
    assert r.status_code == 200 and r.json()["phone"] == "+65 91234567"


@pytest.mark.parametrize("field,value", [("role", "admin"), ("loyalty_tier", "platinum"), ("loyalty_points", 999999)])
def test_contact_update_rejects_privileged_fields(lab, field, value):
    client, engine, _ = lab
    r = client.patch("/me/contact", json={field: value}, headers=login(client, ALICE))
    assert r.status_code == 422
    with Session(engine) as s:
        alice = s.exec(select(Customer).where(Customer.email == ALICE[0])).one()
        assert getattr(alice, field) != value


def test_contact_update_email_clash(lab):
    client, _, _ = lab
    r = client.patch("/me/contact", json={"email": BOB[0]}, headers=login(client, ALICE))
    assert r.status_code == 409


# --- business rules ---

def test_checkin_then_baggage_locked(lab):
    client, engine, _ = lab
    h = login(client, ALICE)
    pnr = pnrs_of(engine, ALICE[0])[0]
    assert client.post(f"/bookings/{pnr}/baggage", json={"bags": 2}, headers=h).json()["bags"] == 2
    assert client.post(f"/bookings/{pnr}/checkin", headers=h).json()["checked_in"] is True
    assert client.post(f"/bookings/{pnr}/baggage", json={"bags": 3}, headers=h).status_code == 409


@pytest.mark.parametrize("bags", [-1, 4, 100])
def test_baggage_bounds(lab, bags):
    client, engine, _ = lab
    pnr = pnrs_of(engine, ALICE[0])[0]
    assert client.post(f"/bookings/{pnr}/baggage", json={"bags": bags}, headers=login(client, ALICE)).status_code == 422


# --- rate limiting ---

def test_booking_lookup_is_rate_limited(lab):
    client, engine, settings = lab
    h = login(client, ALICE)
    pnr = pnrs_of(engine, ALICE[0])[0]
    codes = [client.get(f"/bookings/{pnr}", headers=h).status_code for _ in range(settings.lookup_limit + 3)]
    assert codes[: settings.lookup_limit] == [200] * settings.lookup_limit
    assert codes[-1] == 429
