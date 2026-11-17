"""Engine helpers for the control plane."""

from sqlalchemy.pool import StaticPool
from sqlmodel import SQLModel, create_engine


def make_engine(url: str):
    if url.startswith("sqlite"):
        kwargs = {"connect_args": {"check_same_thread": False}}
        if url == "sqlite://" or ":memory:" in url:
            kwargs["poolclass"] = StaticPool
        return create_engine(url, **kwargs)
    return create_engine(url)


def init_db(engine) -> None:
    # import for side effect: registers every table on the metadata
    from .scope import models  # noqa: F401

    SQLModel.metadata.create_all(engine)
