"""uvicorn entrypoint: `uvicorn app.main:app`. Reads config from the environment and fails closed."""

from sqlmodel import Session

from .api.routes import create_api
from .config import get_settings
from .db import init_db, make_engine
from .engines.registry import register_from_settings
from .orchestrator.worker import enqueuer, make_queue
from .scope.verification import self_verify_loopback

LAB_HOST = "127.0.0.1"


def build():
    settings = get_settings()
    register_from_settings(settings)
    engine = make_engine(settings.database_url)
    init_db(engine)
    if settings.lab_self_verify:
        # bundled lab only; self_verify_loopback refuses anything that isn't a loopback literal
        with Session(engine) as s:
            self_verify_loopback(s, LAB_HOST, "bootstrap")
    return create_api(settings, engine, enqueuer(make_queue()))


app = build()
