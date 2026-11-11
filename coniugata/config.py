"""Configuration and secrets, loaded from the environment / .env file."""

from __future__ import annotations

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_prefix="CONIUGATA_", extra="ignore")

    # API keys. All optional: keyed modules are skipped when their key is absent.
    shodan_key: str | None = None
    urlscan_key: str | None = None
    hibp_key: str | None = None
    vt_key: str | None = None

    # Runtime knobs
    request_timeout: float = Field(20.0, gt=0, le=600)
    concurrency: int = Field(10, ge=1, le=100)
    cache_dir: str = ".cache/coniugata"
    cache_ttl: int = Field(3600, ge=0)
    user_agent: str | None = None

    # theHarvester subprocess wrapper
    theharvester_bin: str = "theHarvester"
    theharvester_sources: str = "crtsh,otx,hackertarget,rapiddns"
    theharvester_limit: int = Field(500, ge=1, le=5000)
    theharvester_timeout: float = Field(180.0, gt=0, le=3600)
