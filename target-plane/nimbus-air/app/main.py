"""Nimbus Air: a fictional airline booking API used as AeroScan's only scan target."""

from collections.abc import Iterator
from typing import Optional

from fastapi import Depends, FastAPI, Header, HTTPException, Request, status
from sqlmodel import Session, select

from . import tokens
from .config import Settings, load_settings
from .db import init_db, make_engine
from .models import Booking, Customer
from .ratelimit import FixedWindowLimiter
from .schemas import (
    BaggageRequest,
    BookingOut,
    ContactUpdate,
    ProfileOut,
    TokenRequest,
    TokenResponse,
)
from .security import verify_password
from .seed import seed


def create_app(settings: Optional[Settings] = None, engine=None) -> FastAPI:
    settings = settings or load_settings()
    engine = engine or make_engine(settings.database_url)
    init_db(engine)
    with Session(engine) as s:
        seed(s, settings.seed)

    app = FastAPI(title="Nimbus Air", version="1.0.0", description="Fictional airline booking lab. Synthetic data only.")
    app.state.settings = settings
    app.state.engine = engine
    app.state.lookup_limiter = FixedWindowLimiter(settings.lookup_limit, settings.lookup_window_seconds)

    def get_session() -> Iterator[Session]:
        with Session(engine) as s:
            yield s

    def current_customer(
        authorization: Optional[str] = Header(default=None),
        session: Session = Depends(get_session),
    ) -> Customer:
        if not authorization or not authorization.lower().startswith("bearer "):
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, "missing bearer token", headers={"WWW-Authenticate": "Bearer"})
        try:
            claims = tokens.decode(authorization[7:].strip(), settings.token_secret)
        except tokens.TokenError:
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, "invalid token", headers={"WWW-Authenticate": "Bearer"})
        customer = session.get(Customer, claims["sub"])
        if customer is None:
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, "invalid token")
        return customer

    def owned_booking(pnr: str, customer: Customer, session: Session) -> Booking:
        booking = session.get(Booking, pnr.upper())
        # 404 for "not yours" as well as "doesn't exist" so the response isn't an existence oracle
        if booking is None or booking.customer_id != customer.id:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "booking not found")
        return booking

    @app.get("/health")
    def health() -> dict:
        return {"status": "ok", "secure_mode": settings.secure_mode}

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
        body: ContactUpdate,
        customer: Customer = Depends(current_customer),
        session: Session = Depends(get_session),
    ) -> ProfileOut:
        changes = body.model_dump(exclude_unset=True, exclude_none=True)
        if "email" in changes:
            changes["email"] = changes["email"].lower()
            clash = session.exec(select(Customer).where(Customer.email == changes["email"], Customer.id != customer.id)).first()
            if clash:
                raise HTTPException(status.HTTP_409_CONFLICT, "email already in use")
        for field, value in changes.items():
            setattr(customer, field, value)
        session.add(customer)
        session.commit()
        session.refresh(customer)
        return ProfileOut.model_validate(customer, from_attributes=True)

    @app.get("/bookings/{pnr}", response_model=BookingOut)
    def get_booking(
        pnr: str,
        request: Request,
        customer: Customer = Depends(current_customer),
        session: Session = Depends(get_session),
    ) -> BookingOut:
        client = request.client.host if request.client else "unknown"
        if not app.state.lookup_limiter.allow(f"{client}:{customer.id}"):
            raise HTTPException(status.HTTP_429_TOO_MANY_REQUESTS, "slow down", headers={"Retry-After": str(settings.lookup_window_seconds)})
        return BookingOut.model_validate(owned_booking(pnr, customer, session), from_attributes=True)

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
