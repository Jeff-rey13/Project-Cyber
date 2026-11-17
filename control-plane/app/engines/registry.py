"""Name -> engine factory. Adapters register themselves as they're added."""

from collections.abc import Callable

from .base import Engine

EngineFactory = Callable[[], Engine]

ENGINES: dict[str, EngineFactory] = {}


def register(name: str, factory: EngineFactory) -> None:
    ENGINES[name] = factory


def known() -> set[str]:
    return set(ENGINES)


def register_defaults() -> None:
    """Engines that need no external binary or service. zap/nuclei register from config at startup."""
    from .api_checks import ApiChecksEngine
    from .authz_engine import AuthzEngine

    register("authz", AuthzEngine)
    register("api_checks", ApiChecksEngine)


register_defaults()
