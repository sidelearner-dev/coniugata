"""Configuration and secrets, loaded from the environment / .env file."""

from __future__ import annotations

import logging
import os
from pathlib import Path
from typing import Literal

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict

logger = logging.getLogger("coniugata.config")


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

    # Anonymous per-install identity. Generated on first use and stored with
    # mode 0600 unless this override is set.
    instance_token: str | None = None
    identity_mode: Literal["install", "run", "none"] = "install"

    # Local scan-history database. None means the XDG data directory.
    db_path: str | None = None

    # Refuse response bodies larger than this (decompressed bytes), so a
    # malicious or broken provider cannot exhaust memory.
    max_response_bytes: int = Field(16 * 1024 * 1024, ge=1024, le=256 * 1024 * 1024)

    # Maximum findings kept per scan (0 disables the cap). A malicious or very
    # large upstream result set must not create unbounded tasks or memory use.
    max_entities: int = Field(50000, ge=0, le=1_000_000)

    # theHarvester subprocess wrapper
    theharvester_bin: str = "theHarvester"
    theharvester_sources: str = "crtsh,otx,hackertarget,rapiddns"
    theharvester_limit: int = Field(500, ge=1, le=5000)
    theharvester_timeout: float = Field(180.0, gt=0, le=3600)


def _safe_env_file(path: Path) -> Path | None:
    """Return ``path`` only if it is a private, user-owned regular file.

    A ``.env`` is read from the current directory, which may be an untrusted
    repository. An attacker-planted file could redirect theHarvester to an
    arbitrary binary or move the database, so unsafe files are ignored.
    """
    if path.is_symlink():
        logger.warning("ignoring symlinked env file: %s", path)
        return None
    try:
        info = path.stat()
    except OSError:
        return None
    getuid = getattr(os, "getuid", None)
    if getuid is not None and info.st_uid != getuid():
        logger.warning("ignoring env file not owned by you: %s", path)
        return None
    if info.st_mode & 0o022:
        logger.warning("ignoring env file writable by group/others: %s", path)
        return None
    if info.st_mode & 0o077:
        logger.warning("env file is readable by group/others; chmod 600 %s", path)
    return path


def load_settings() -> Settings:
    """Load settings, ignoring an unsafe ``.env`` in the current directory.

    Override the path with ``CONIUGATA_ENV_FILE``; environment variables still
    take precedence as usual.
    """
    configured = os.environ.get("CONIUGATA_ENV_FILE", ".env")
    env_file = _safe_env_file(Path(configured).expanduser())
    return Settings(_env_file=env_file)
