"""Nimbus Air: a fictional airline booking API used as Squawk's only scan target.

Every weakness is gated on `settings.secure_mode` so the broken and fixed
behaviour can be shown side by side. Search for "VULN-" to find them all:

  VULN-1  BOLA on GET /bookings/{pnr}            (no ownership check)
  VULN-2  broken authentication                   (token signature/expiry not verified,
                                                   anonymous "manage booking" by pnr)
  VULN-3  excessive data exposure                 (full passenger record in booking response)
  VULN-4  mass assignment on PATCH /me/contact    (role / loyalty fields writable)
  VULN-5  no rate limiting on booking lookup      (pnr enumeration)
"""

import asyncio
from collections.abc import Iterator
from typing import Optional, Union

from fastapi import Body, Depends, FastAPI, Header, HTTPException, Request, status
from pydantic import ValidationError
from sqlmodel import Session, select

from . import tokens
from .config import Settings, load_settings
from .db import init_db, make_engine
from .models import Booking, Customer
from .ratelimit import FixedWindowLimiter
from .schemas import (
    BaggageRequest,
    BookingFullOut,
    BookingOut,
    ContactUpdate,
    ProfileOut,
    TokenRequest,
    TokenResponse,
)
from .security import verify_password
from .seed import seed

# never writable, even in insecure mode. the lab should be exploitable, not brickable.
_NEVER_ASSIGNABLE = {"id", "password_hash"}


def create_app(settings: Optional[Settings] = None, engine=None) -> FastAPI:
    settings = settings or load_settings()
    engine = engine or make_engine(settings.database_url)
    secure = settings.secure_mode
    init_db(engine)
    with Session(engine) as s:
        seed(s, settings.seed)

    app = FastAPI(title="Nimbus Air", version="1.0.0", description="Fictional airline booking lab. Synthetic data only.")
    app.state.settings = settings
    app.state.engine = engine
    app.state.lookup_limiter = FixedWindowLimiter(settings.lookup_limit, settings.lookup_window_seconds)

    if settings.inject_latency_ms > 0:
        # simulates a struggling backend so the scanner's throttle has something to react to
        @app.middleware("http")
        async def slow_down(request: Request, call_next):
            await asyncio.sleep(settings.inject_latency_ms / 1000)
            return await call_next(request)

    def get_session() -> Iterator[Session]:
        with Session(engine) as s:
            yield s

    def resolve_customer(authorization: Optional[str], session: Session) -> Optional[Customer]:
        if not authorization or not authorization.lower().startswith("bearer "):
            return None
        try:
            # VULN-2: insecure mode trusts whatever the token body says
            claims = tokens.decode(authorization[7:].strip(), settings.token_secret, verify_signature=secure)
        except tokens.TokenError:
            # from None: the token internals aren't useful to anyone reading the traceback
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, "invalid token", headers={"WWW-Authenticate": "Bearer"}) from None
        customer = session.get(Customer, claims["sub"])
        if customer is None:
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, "invalid token")
        return customer

    def current_customer(
        authorization: Optional[str] = Header(default=None),
        session: Session = Depends(get_session),
    ) -> Customer:
        customer = resolve_customer(authorization, session)
        if customer is None:
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, "missing bearer token", headers={"WWW-Authenticate": "Bearer"})
        return customer

    def optional_customer(
        authorization: Optional[str] = Header(default=None),
        session: Session = Depends(get_session),
    ) -> Optional[Customer]:
        return resolve_customer(authorization, session)

    def owned_booking(pnr: str, customer: Customer, session: Session) -> Booking:
        booking = session.get(Booking, pnr.upper())
        # 404 for "not yours" as well as "doesn't exist" so the response isn't an existence oracle
        if booking is None or booking.customer_id != customer.id:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "booking not found")
        return booking

    def full_view(booking: Booking, session: Session) -> BookingFullOut:
        owner = session.get(Customer, booking.customer_id)
        return BookingFullOut(
            **BookingOut.model_validate(booking, from_attributes=True).model_dump(),
            customer_id=owner.id,
            passenger_name=owner.full_name,
            passenger_dob=owner.dob,
            passport_no=owner.passport_no,
            phone=owner.phone,
            email=owner.email,
            card_masked=booking.card_masked,
            total_amount=booking.total_amount,
            currency=booking.currency,
        )

    @app.get("/health")
    def health() -> dict:
        return {"status": "ok", "secure_mode": secure}

    @app.post("/auth/token", response_model=TokenResponse)
    def issue_token(body: TokenRequest, session: Session = Depends(get_session)) -> TokenResponse:
        customer = session.exec(select(Customer).where(Customer.email == body.email.lower())).first()
        # same message either way; don't reveal which emails exist
        if customer is None or not verify_password(body.password, customer.password_hash):
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, "invalid credentials")
        return TokenResponse(access_token=tokens.issue(customer.id, settings.token_secret, settings.token_ttl_seconds))

    @app.get("/me", response_model=ProfileOut)
    def me(customer: Customer = Depends(current_customer)) -> ProfileOut:
        return ProfileOut.model_validate(customer, from_attributes=True)

    @app.patch("/me/contact", response_model=ProfileOut)
    def update_contact(
        body: dict = Body(..., examples=[{"phone": "+65 91234567"}]),
        customer: Customer = Depends(current_customer),
        session: Session = Depends(get_session),
    ) -> ProfileOut:
        if secure:
            try:
                changes = ContactUpdate.model_validate(body).model_dump(exclude_unset=True, exclude_none=True)
            except ValidationError as exc:
                detail = exc.errors(include_url=False, include_context=False)
                raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, detail) from exc
        else:
            # VULN-4: binds every known model field straight from the request
            changes = {k: v for k, v in body.items() if k in Customer.model_fields and k not in _NEVER_ASSIGNABLE}

        if "email" in changes:
            changes["email"] = str(changes["email"]).lower()
            clash = session.exec(select(Customer).where(Customer.email == changes["email"], Customer.id != customer.id)).first()
            if clash:
                raise HTTPException(status.HTTP_409_CONFLICT, "email already in use")
        for field, value in changes.items():
            setattr(customer, field, value)
        session.add(customer)
        session.commit()
        session.refresh(customer)
        return ProfileOut.model_validate(customer, from_attributes=True)

    @app.get("/bookings/{pnr}", response_model=Union[BookingFullOut, BookingOut])
    def get_booking(
        pnr: str,
        request: Request,
        customer: Optional[Customer] = Depends(optional_customer),
        session: Session = Depends(get_session),
    ):
        if secure:
            if customer is None:
                raise HTTPException(status.HTTP_401_UNAUTHORIZED, "missing bearer token", headers={"WWW-Authenticate": "Bearer"})
            client = request.client.host if request.client else "unknown"
            if not app.state.lookup_limiter.allow(f"{client}:{customer.id}"):
                retry = {"Retry-After": str(settings.lookup_window_seconds)}
                raise HTTPException(status.HTTP_429_TOO_MANY_REQUESTS, "slow down", headers=retry)
            return BookingOut.model_validate(owned_booking(pnr, customer, session), from_attributes=True)

        # VULN-5: no limiter here at all
        # VULN-2: anonymous callers allowed, the pnr is treated as the credential
        # VULN-1: no ownership check, any valid pnr comes back
        booking = session.get(Booking, pnr.upper())
        if booking is None:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "booking not found")
        # VULN-3: whole passenger record, not just the itinerary
        return full_view(booking, session)

    @app.post("/bookings/{pnr}/checkin", response_model=BookingOut)
    def check_in(pnr: str, customer: Customer = Depends(current_customer), session: Session = Depends(get_session)) -> BookingOut:
        booking = owned_booking(pnr, customer, session)
        booking.checked_in = True
        session.add(booking)
        session.commit()
        session.refresh(booking)
        return BookingOut.model_validate(booking, from_attributes=True)

    @app.post("/bookings/{pnr}/baggage", response_model=BookingOut)
    def add_baggage(
        pnr: str,
        body: BaggageRequest,
        customer: Customer = Depends(current_customer),
        session: Session = Depends(get_session),
    ) -> BookingOut:
        booking = owned_booking(pnr, customer, session)
        if booking.checked_in:
            raise HTTPException(status.HTTP_409_CONFLICT, "baggage locked after check-in")
        booking.bags = body.bags
        session.add(booking)
        session.commit()
        session.refresh(booking)
        return BookingOut.model_validate(booking, from_attributes=True)

    return app
