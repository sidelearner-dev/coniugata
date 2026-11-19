"""Anonymous per-install identity.

The first run generates a random token and stores it under the user's config
directory with mode ``0600``. Requests carry only a truncated SHA-256
fingerprint of that token, so two installs are distinguishable from each other
but cannot be linked back to the author or to the token itself.

Set ``CONIUGATA_INSTANCE_TOKEN`` to supply a token explicitly (useful for
ephemeral/containerised runs); otherwise a fresh one is created on demand.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import secrets
import tempfile
from pathlib import Path

logger = logging.getLogger("coniugata.identity")

TOKEN_BYTES = 16  # 128 bits of entropy, rendered as 32 hex characters
FILENAME = "instance.json"
IDENTITY_MODES = ("install", "run", "none")


def config_home() -> Path:
    """Return the XDG config directory, or the conventional fallback."""
    override = os.environ.get("CONIUGATA_CONFIG_DIR")
    if override:
        return Path(override).expanduser()
    base = os.environ.get("XDG_CONFIG_HOME")
    return Path(base).expanduser() if base else Path.home() / ".config"


def instance_path() -> Path:
    return config_home() / "coniugata" / FILENAME


def fingerprint(token: str) -> str:
    """A short, one-way, stable label for a token. Safe to put on the wire."""
    return hashlib.sha256(token.encode("utf-8")).hexdigest()[:12]


def _read_token(path: Path) -> str | None:
    if path.is_symlink():
        logger.warning("refusing symlinked identity file: %s", path)
        return None
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return None
    except (OSError, ValueError):
        logger.warning("ignoring unreadable identity file: %s", path)
        return None
    token = payload.get("token") if isinstance(payload, dict) else None
    if isinstance(token, str) and len(token) >= 2 * TOKEN_BYTES:
        return token
    return None


def _write_token(path: Path, token: str) -> None:
    """Atomically write ``token`` with owner-only permissions."""
    if path.parent.is_symlink():
        raise OSError(f"refusing symlinked identity directory: {path.parent}")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.parent.chmod(0o700)
    if path.is_symlink():
        raise OSError(f"refusing symlinked identity file: {path}")
    fd, temporary = tempfile.mkstemp(dir=path.parent, prefix=".instance-", suffix=".tmp")
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump({"token": token}, handle)
        os.replace(temporary, path)
        path.chmod(0o600)
    except BaseException:
        Path(temporary).unlink(missing_ok=True)
        raise


def load_or_create_token(path: str | Path | None = None) -> str:
    """Return this install's token, creating and persisting one if needed.

    A read-only or hostile home directory must not break scanning, so failure
    to persist falls back to a process-local token.
    """
    target = Path(path).expanduser() if path else instance_path()
    token = _read_token(target)
    if token is not None:
        return token

    token = ephemeral_token()
    try:
        _write_token(target, token)
    except OSError as exc:
        logger.debug("could not persist identity token: %s", exc)
    return token


def ephemeral_token() -> str:
    """A fresh token that is never written to disk."""
    return secrets.token_hex(TOKEN_BYTES)


def base_user_agent(*, version: str = "0.1") -> str:
    """User-Agent used when no install identity is sent at all."""
    return f"coniugata/{version} (authorized security research)"


def request_user_agent(token: str | None, *, version: str = "0.1") -> str:
    """Build the default User-Agent.

    Deliberately contains no author contact details, repository URL or token;
    only an opaque per-install fingerprint (or nothing at all).
    """
    if not token:
        return base_user_agent(version=version)
    return f"coniugata/{version} (authorized security research; instance:{fingerprint(token)})"


def user_agent_for(mode: str, explicit_token: str | None = None, *, version: str = "0.1") -> str:
    """Resolve the User-Agent for an identity mode.

    ``install`` reuses/persists one token; ``run`` generates a fresh token per
    process; ``none`` sends no fingerprint. An explicit token always wins.
    """
    if explicit_token:
        return request_user_agent(explicit_token, version=version)

    normalized = (mode or "install").strip().lower()
    if normalized == "none":
        return request_user_agent(None, version=version)
    if normalized == "run":
        return request_user_agent(ephemeral_token(), version=version)
    if normalized == "install":
        return request_user_agent(load_or_create_token(), version=version)
    raise ValueError(
        f"unknown identity mode {mode!r}; choose one of: {', '.join(IDENTITY_MODES)}"
    )
