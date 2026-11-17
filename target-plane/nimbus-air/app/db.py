"""Engine helpers."""

from sqlalchemy.pool import StaticPool
from sqlmodel import SQLModel, create_engine


def make_engine(url: str):
    if url.startswith("sqlite"):
        kwargs = {"connect_args": {"check_same_thread": False}}
        # in-memory dbs vanish per connection unless they all share one
        if url == "sqlite://" or ":memory:" in url:
            kwargs["poolclass"] = StaticPool
        return create_engine(url, **kwargs)
    return create_engine(url)


def init_db(engine) -> None:
    SQLModel.metadata.create_all(engine)
