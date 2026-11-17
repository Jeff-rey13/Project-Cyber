"""Data model for the lab. Everything stored here is synthetic."""

from datetime import date, datetime
from typing import Optional

from sqlmodel import Field, SQLModel


class Customer(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    email: str = Field(index=True, unique=True)
    password_hash: str
    full_name: str
    dob: date
    phone: str
    passport_no: str
    # privileged fields; contact update must never be able to touch these (mass assignment target)
    role: str = "customer"
    loyalty_tier: str = "blue"
    loyalty_points: int = 0


class Booking(SQLModel, table=True):
    pnr: str = Field(primary_key=True, max_length=6)
    customer_id: int = Field(foreign_key="customer.id", index=True)
    flight_no: str
    origin: str
    destination: str
    departure: datetime
    seat: Optional[str] = None
    fare_class: str = "Y"
    total_amount: float
    currency: str = "SGD"
    # stored already masked; the lab never holds a full pan, fake or not
    card_masked: str
    checked_in: bool = False
    bags: int = 0
