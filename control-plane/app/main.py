"""uvicorn entrypoint: `uvicorn app.main:app`. Reads config from the environment and fails closed."""

from .api.routes import create_api
from .config import get_settings
from .db import make_engine
from .orchestrator.worker import enqueuer, make_queue


def build():
    settings = get_settings()
    return create_api(settings, make_engine(settings.database_url), enqueuer(make_queue()))


app = build()
