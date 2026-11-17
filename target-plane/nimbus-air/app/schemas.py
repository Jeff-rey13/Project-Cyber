"""Request/response shapes. The response models are the data-exposure boundary."""

from datetime import date, datetime
from typing import Optional

from pydantic import BaseModel, ConfigDict, Field


class TokenRequest(BaseModel):
    email: str
    password: str


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"


class ContactUpdate(BaseModel):
    # forbid, not ignore: an unknown field is a client bug or an attack, either way say so
    model_config = ConfigDict(extra="forbid")
    phone: Optional[str] = Field(default=None, pattern=r"^\+?[0-9 ]{6,20}$")
    email: Optional[str] = Field(default=None, pattern=r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


class BaggageRequest(BaseModel):
    bags: int = Field(ge=0, le=3)


class ProfileOut(BaseModel):
    id: int
    email: str
    full_name: str
    phone: str
    loyalty_tier: str
    loyalty_points: int


class BookingOut(BaseModel):
    """What a passenger legitimately needs to see. No dob, passport or card data."""

    pnr: str
    flight_no: str
    origin: str
    destination: str
    departure: datetime
    seat: Optional[str]
    fare_class: str
    checked_in: bool
    bags: int


class BookingFullOut(BookingOut):
    """Insecure-mode booking shape. Ships the whole passenger record (excessive data exposure)."""

    customer_id: int
    passenger_name: str
    passenger_dob: date
    passport_no: str
    phone: str
    email: str
    card_masked: str
    total_amount: float
    currency: str
