import sys
from pathlib import Path

import pytest
from sqlmodel import Session

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.db import init_db, make_engine  # noqa: E402

SNAPSHOT_KEY = b"test-snapshot-key-0123456789"


@pytest.fixture
def session():
    engine = make_engine("sqlite://")
    init_db(engine)
    with Session(engine) as s:
        yield s
