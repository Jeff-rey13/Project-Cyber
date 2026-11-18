"""Print the seeded test identities as Squawk scan options.

    docker compose exec nimbus-air python -m app.identities > identities.json

Lab-only convenience: these are the synthetic accounts the authz engine
plays as identity A and B. A real target would have the operator create
their own test accounts instead.
"""

import json
import sys

from sqlmodel import Session, select

from .config import load_settings
from .db import init_db, make_engine
from .models import Booking, Customer
from .seed import KNOWN_IDENTITIES, seed


def identities(session: Session) -> list[dict]:
    out = []
    for ident in KNOWN_IDENTITIES:
        c = session.exec(select(Customer).where(Customer.email == ident["email"])).one()
        pnrs = list(session.exec(select(Booking.pnr).where(Booking.customer_id == c.id).order_by(Booking.pnr)))
        out.append({
            "label": ident["email"].split("@")[0],
            "email": ident["email"],
            "password": ident["password"],
            "objects": pnrs,
            "markers": [c.full_name, c.passport_no],
        })
    return out


def main() -> None:
    settings = load_settings()
    engine = make_engine(settings.database_url)
    init_db(engine)
    with Session(engine) as s:
        seed(s, settings.seed)
        json.dump({"identities": identities(s)}, sys.stdout, indent=2)
    sys.stdout.write("\n")


if __name__ == "__main__":
    main()
