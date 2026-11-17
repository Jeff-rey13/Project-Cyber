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


def register_from_settings(settings) -> None:
    """zap and nuclei only exist when their service/binary is configured."""
    if settings.zap_api_url:
        from .zap_adapter import ZapAdapter, ZapConfig

        if not settings.zap_api_key or settings.zap_api_key.startswith("change-me"):
            raise ValueError("ZAP_API_KEY must be set when ZAP_API_URL is")
        zap_cfg = ZapConfig(settings.zap_api_url, settings.zap_api_key,
                            (settings.gate_proxy_public_host, settings.gate_proxy_port))
        # bind via default args; a shared closure name here once handed zap the nuclei config
        register("zap", lambda c=zap_cfg, k=settings.snapshot_key: ZapAdapter(c, key=k))
    if settings.nuclei_binary:
        from .nuclei_adapter import NucleiAdapter, NucleiConfig

        nuclei_cfg = NucleiConfig(proxy_url=f"http://127.0.0.1:{settings.gate_proxy_port}", binary=settings.nuclei_binary)
        register("nuclei", lambda c=nuclei_cfg: NucleiAdapter(c))
