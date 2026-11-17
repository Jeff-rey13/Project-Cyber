"""uvicorn entrypoint: `uvicorn app.asgi:app`. Kept separate so importing main has no side effects."""

from .main import create_app

app = create_app()
