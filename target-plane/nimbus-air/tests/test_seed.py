import re

from sqlmodel import Session, select

from app.db import init_db, make_engine
from app.models import Booking, Customer
from app.security import verify_password
from app.seed import BACKGROUND_CUSTOMERS, BOOKINGS_PER_CUSTOMER, KNOWN_IDENTITIES, seed


def _snapshot(seed_value):
    eng = make_engine("sqlite://")
    init_db(eng)
    with Session(eng) as s:
        seed(s, seed_value)
        customers = [(c.email, c.dob, c.phone, c.passport_no) for c in s.exec(select(Customer).order_by(Customer.id))]
        bookings = [(b.pnr, b.customer_id, b.flight_no, b.card_masked) for b in s.exec(select(Booking).order_by(Booking.pnr))]
    return customers, bookings


def test_seed_is_deterministic():
    assert _snapshot(1337) == _snapshot(1337)


def test_different_seed_gives_different_data():
    assert _snapshot(1337)[1] != _snapshot(42)[1]


def test_row_counts(session):
    customers = session.exec(select(Customer)).all()
    bookings = session.exec(select(Booking)).all()
    assert len(customers) == len(KNOWN_IDENTITIES) + BACKGROUND_CUSTOMERS
    assert len(bookings) == len(customers) * BOOKINGS_PER_CUSTOMER


def test_seed_is_idempotent(engine):
    with Session(engine) as s:
        seed(s, 1337)
        assert len(s.exec(select(Customer)).all()) == len(KNOWN_IDENTITIES) + BACKGROUND_CUSTOMERS


def test_known_identities_can_authenticate(session):
    for ident in KNOWN_IDENTITIES:
        c = session.exec(select(Customer).where(Customer.email == ident["email"])).one()
        assert verify_password(ident["password"], c.password_hash)
        assert not verify_password("wrong", c.password_hash)


def test_only_masked_cards_stored(session):
    for b in session.exec(select(Booking)):
        assert re.fullmatch(r"\d{4} \*{4} \*{4} \d{4}", b.card_masked)


def test_pnrs_unique_and_well_formed(session):
    pnrs = [b.pnr for b in session.exec(select(Booking))]
    assert len(pnrs) == len(set(pnrs))
    assert all(re.fullmatch(r"[A-Z0-9]{6}", p) for p in pnrs)
