"""Runtime settings for the Nimbus Air lab, read once from the environment."""

import os
from dataclasses import dataclass


def _flag(name: str, default: bool) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


@dataclass
class Settings:
    # false = intentionally vulnerable. the lab defaults to broken so the scanner has something to find.
    secure_mode: bool = False
    seed: int = 1337
    database_url: str = "sqlite:///./nimbus.db"
    token_secret: str = "nimbus-lab-only-secret"
    token_ttl_seconds: int = 3600
    # booking lookups per client per window, only enforced in secure mode
    lookup_limit: int = 20
    lookup_window_seconds: int = 60
    # test hook for the scanner's do-no-harm throttle: every response is delayed by this much
    inject_latency_ms: int = 0


def load_settings() -> Settings:
    return Settings(
        secure_mode=_flag("NIMBUS_SECURE_MODE", False),
        seed=int(os.getenv("NIMBUS_SEED", "1337")),
        database_url=os.getenv("NIMBUS_DATABASE_URL", "sqlite:///./nimbus.db"),
        token_secret=os.getenv("NIMBUS_TOKEN_SECRET", "nimbus-lab-only-secret"),
        inject_latency_ms=int(os.getenv("NIMBUS_INJECT_LATENCY_MS", "0")),
    )
