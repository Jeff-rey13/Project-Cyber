"""Each intentional weakness: exploitable with secure_mode off, blocked with it on.

These double as executable write-ups of the five lab vulnerabilities.
"""

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


def build(secure: bool):
    engine = make_engine("sqlite://")
    init_db(engine)
    settings = Settings(secure_mode=secure, database_url="sqlite://", lookup_limit=5)
    return TestClient(create_app(settings, engine)), engine, settings


@pytest.fixture(params=[False, True], ids=["insecure", "secure"])
def lab(request):
    client, engine, settings = build(request.param)
    return client, engine, settings, request.param


def login(client, creds):
    r = client.post("/auth/token", json={"email": creds[0], "password": creds[1]})
    return {"Authorization": f"Bearer {r.json()['access_token']}"}


def customer(engine, email) -> Customer:
    with Session(engine) as s:
        return s.exec(select(Customer).where(Customer.email == email)).one()


def first_pnr(engine, email) -> str:
    cid = customer(engine, email).id
    with Session(engine) as s:
        return s.exec(select(Booking.pnr).where(Booking.customer_id == cid).order_by(Booking.pnr)).first()


def test_vuln1_bola_cross_customer_booking_read(lab):
    """Alice, logged in as herself, asks for Bob's pnr."""
    client, engine, _, secure = lab
    bob_pnr = first_pnr(engine, BOB[0])
    r = client.get(f"/bookings/{bob_pnr}", headers=login(client, ALICE))
    if secure:
        assert r.status_code == 404
    else:
        assert r.status_code == 200
        assert r.json()["passenger_name"] == customer(engine, BOB[0]).full_name


def test_vuln2_forged_token_impersonates_another_customer(lab):
    """Unsigned token claiming to be bob. No password, no secret."""
    client, engine, _, secure = lab
    bob_id = customer(engine, BOB[0]).id
    forged = tokens.issue(bob_id, "attacker-guess", 3600)
    r = client.get("/me", headers={"Authorization": f"Bearer {forged}"})
    if secure:
        assert r.status_code == 401
    else:
        assert r.status_code == 200 and r.json()["email"] == BOB[0]


def test_vuln2_anonymous_booking_lookup(lab):
    client, engine, _, secure = lab
    r = client.get(f"/bookings/{first_pnr(engine, BOB[0])}")
    assert r.status_code == (401 if secure else 200)


def test_vuln3_booking_leaks_passenger_pii(lab):
    """Even the owner shouldn't get dob/passport back from an itinerary lookup."""
    client, engine, _, secure = lab
    body = client.get(f"/bookings/{first_pnr(engine, ALICE[0])}", headers=login(client, ALICE)).json()
    leaked = {"passenger_dob", "passport_no", "card_masked", "phone", "email"} & set(body)
    if secure:
        assert not leaked
    else:
        assert leaked == {"passenger_dob", "passport_no", "card_masked", "phone", "email"}
        assert body["passport_no"] == customer(engine, ALICE[0]).passport_no


@pytest.mark.parametrize("field,value", [("role", "admin"), ("loyalty_tier", "platinum"), ("loyalty_points", 999999)])
def test_vuln4_mass_assignment_on_contact_update(lab, field, value):
    client, engine, _, secure = lab
    r = client.patch("/me/contact", json={"phone": "+65 90000000", field: value}, headers=login(client, ALICE))
    stored = getattr(customer(engine, ALICE[0]), field)
    if secure:
        assert r.status_code == 422 and stored != value
    else:
        assert r.status_code == 200 and stored == value


def test_vuln4_password_hash_stays_unwritable_even_insecure():
    client, engine, _ = build(secure=False)
    before = customer(engine, ALICE[0]).password_hash
    client.patch("/me/contact", json={"password_hash": "x", "id": 999}, headers=login(client, ALICE))
    after = customer(engine, ALICE[0])
    assert after.password_hash == before and after.id != 999


def test_vuln5_pnr_enumeration_unthrottled(lab):
    """Spray guesses. Insecure: no 429 ever. Secure: cut off after the limit."""
    client, engine, settings, secure = lab
    h = login(client, ALICE)
    codes = [client.get(f"/bookings/AA{n:04d}", headers=h).status_code for n in range(settings.lookup_limit * 4)]
    if secure:
        assert 429 in codes
    else:
        assert 429 not in codes


def test_vuln5_enumeration_actually_harvests_bookings():
    """End-to-end: an anonymous caller walking known pnrs gets every passenger name."""
    client, engine, _ = build(secure=False)
    with Session(engine) as s:
        all_pnrs = [b.pnr for b in s.exec(select(Booking))]
    names = {client.get(f"/bookings/{p}").json()["passenger_name"] for p in all_pnrs}
    with Session(engine) as s:
        assert names == {c.full_name for c in s.exec(select(Customer))}
