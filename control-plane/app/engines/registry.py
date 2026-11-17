"""Name -> engine factory. Adapters register themselves as they're added."""

from collections.abc import Callable

from .base import Engine

EngineFactory = Callable[[], Engine]

ENGINES: dict[str, EngineFactory] = {}


def register(name: str, factory: EngineFactory) -> None:
    ENGINES[name] = factory


def known() -> set[str]:
    return set(ENGINES)
