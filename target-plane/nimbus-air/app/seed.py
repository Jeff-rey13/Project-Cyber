"""Deterministic synthetic seed data.

Same seed in, same rows out, so scan results and tests are reproducible.
alice and bob are the two identities the authz engine uses as A and B; the
rest is background population so enumeration has something to find.
"""

import random
import string
from datetime import date, datetime, timedelta

from sqlmodel import Session, select

from .models import Booking, Customer
from .security import hash_password

# lab-only demo credentials, documented in the README so the authz engine can be pointed at them
KNOWN_IDENTITIES = [
    {"email": "alice@nimbus.test", "password": "alice-lab-pass", "full_name": "Alice Tan"},
    {"email": "bob@nimbus.test", "password": "bob-lab-pass", "full_name": "Bob Lim"},
]

_FIRST = ["Mei", "Arjun", "Siti", "Daniel", "Hana", "Ravi", "Chloe", "Wei", "Nur", "Lucas"]
_LAST = ["Ng", "Kumar", "Rahman", "Wong", "Lee", "Goh", "Ong", "Chua", "Ismail", "Teo"]
_AIRPORTS = ["SIN", "BKK", "KUL", "HKG", "NRT", "SYD", "DPS", "MNL", "CGK", "TPE"]
# test-range prefixes only, and we only ever keep the masked form
_CARD_PREFIXES = ["4000", "5100", "3700"]
_PNR_ALPHABET = string.ascii_uppercase + string.digits

BACKGROUND_CUSTOMERS = 10
BOOKINGS_PER_CUSTOMER = 2
BASE_DATE = datetime(2027, 1, 1, 8, 0)


def _pnr(rng: random.Random, taken: set[str]) -> str:
    while True:
        candidate = "".join(rng.choice(_PNR_ALPHABET) for _ in range(6))
        if candidate not in taken:
            taken.add(candidate)
            return candidate


def _booking(rng: random.Random, customer_id: int, taken: set[str]) -> Booking:
    origin, destination = rng.sample(_AIRPORTS, 2)
    return Booking(
        pnr=_pnr(rng, taken),
        customer_id=customer_id,
        flight_no=f"NM{rng.randint(100, 999)}",
        origin=origin,
        destination=destination,
        departure=BASE_DATE + timedelta(days=rng.randint(0, 120), hours=rng.randint(0, 23)),
        seat=f"{rng.randint(1, 40)}{rng.choice('ABCDEF')}",
        fare_class=rng.choice(["Y", "Y", "W", "J"]),
        total_amount=round(rng.uniform(120, 1800), 2),
        card_masked=f"{rng.choice(_CARD_PREFIXES)} **** **** {rng.randint(0, 9999):04d}",
    )


def _customer(rng: random.Random, email: str, full_name: str, password: str) -> Customer:
    # salt derived from the email so seeded hashes are deterministic too. fine for a lab, not for prod.
    salt = email.encode().ljust(16, b"\0")[:16]
    return Customer(
        email=email,
        password_hash=hash_password(password, salt=salt),
        full_name=full_name,
        dob=date(1970, 1, 1) + timedelta(days=rng.randint(0, 365 * 35)),
        phone=f"+65 9{rng.randint(0, 9999999):07d}",
        passport_no=f"X{rng.randint(0, 9999999):07d}",
        loyalty_points=rng.randint(0, 50_000),
    )


def seed(session: Session, seed_value: int = 1337) -> None:
    """Populate an empty database. No-op if customers already exist."""
    if session.exec(select(Customer)).first() is not None:
        return

    rng = random.Random(seed_value)
    taken: set[str] = set()

    people = [(i["email"], i["full_name"], i["password"]) for i in KNOWN_IDENTITIES]
    for n in range(BACKGROUND_CUSTOMERS):
        first, last = _FIRST[n % len(_FIRST)], _LAST[(n * 3) % len(_LAST)]
        people.append((f"{first.lower()}.{last.lower()}{n}@nimbus.test", f"{first} {last}", f"pass-{n}"))

    for email, full_name, password in people:
        customer = _customer(rng, email, full_name, password)
        session.add(customer)
        session.flush()
        for _ in range(BOOKINGS_PER_CUSTOMER):
            session.add(_booking(rng, customer.id, taken))

    session.commit()
