"""Configuration and secrets, loaded from the environment / .env file."""

from __future__ import annotations

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_prefix="CONIUGATA_", extra="ignore")

    # API keys. All optional: keyed modules are skipped when their key is absent.
    shodan_key: str | None = None
    urlscan_key: str | None = None
    hibp_key: str | None = None
    vt_key: str | None = None

    # Runtime knobs
    request_timeout: float = 20.0
    concurrency: int = 10
    cache_dir: str = ".cache/coniugata"
    cache_ttl: int = 3600
    user_agent: str | None = None
