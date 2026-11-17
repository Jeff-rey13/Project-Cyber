"""Control-plane settings, from the environment only (no secrets in the repo)."""

import os
from dataclasses import dataclass
from functools import lru_cache


class ConfigError(RuntimeError):
    pass


@dataclass(frozen=True)
class Settings:
    database_url: str
    redis_url: str
    snapshot_key: bytes
    operator_token: str
    # where the gate proxy listens, and the address external engines should use to reach it
    gate_proxy_bind: str = "127.0.0.1"
    gate_proxy_port: int = 8899
    gate_proxy_public_host: str = "127.0.0.1"
    zap_api_url: str = ""
    zap_api_key: str = ""
    nuclei_binary: str = ""
    lab_self_verify: bool = False


def _required(name: str, min_len: int = 16) -> str:
    value = os.getenv(name, "")
    # fail closed: a missing or toy secret means we don't start, rather than start insecure
    if len(value) < min_len or value.startswith("change-me"):
        raise ConfigError(f"{name} must be set to a real value (>= {min_len} chars)")
    return value


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings(
        database_url=os.getenv("DATABASE_URL", "sqlite:///./aeroscan.db"),
        redis_url=os.getenv("REDIS_URL", "redis://localhost:6379/0"),
        snapshot_key=_required("AEROSCAN_SNAPSHOT_KEY").encode(),
        operator_token=_required("AEROSCAN_OPERATOR_TOKEN"),
        gate_proxy_bind=os.getenv("AEROSCAN_GATE_PROXY_BIND", "127.0.0.1"),
        gate_proxy_port=int(os.getenv("AEROSCAN_GATE_PROXY_PORT", "8899")),
        gate_proxy_public_host=os.getenv("AEROSCAN_GATE_PROXY_HOST", "127.0.0.1"),
        zap_api_url=os.getenv("ZAP_API_URL", ""),
        zap_api_key=os.getenv("ZAP_API_KEY", ""),
        nuclei_binary=os.getenv("NUCLEI_BINARY", ""),
        lab_self_verify=os.getenv("AEROSCAN_LAB_SELF_VERIFY", "").lower() in {"1", "true", "yes"},
    )
