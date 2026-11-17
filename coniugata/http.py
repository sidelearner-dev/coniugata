"""Shared HTTP plumbing: one client per scan, throttling, on-disk caching."""

from __future__ import annotations

import asyncio
import json
import logging
import time
from pathlib import Path
from typing import Any

import httpx

from .config import Settings
from .identity import user_agent_for

logger = logging.getLogger("coniugata.http")

DEFAULT_MAX_RESPONSE_BYTES = 16 * 1024 * 1024


def _wrap_cache(
    transport: httpx.AsyncBaseTransport, settings: Settings | None
) -> httpx.AsyncBaseTransport:
    """Wrap a transport in hishel's on-disk cache when the cache extra is installed."""
    try:
        from hishel import AsyncSqliteStorage
        from hishel.httpx import AsyncCacheTransport
    except ImportError:
        logger.debug("hishel not installed; response caching disabled")
        return transport

    cache_dir = Path(settings.cache_dir if settings else ".cache/coniugata")
    # A symlinked cache path could redirect writes (or the SQLite file) to a
    # location an attacker controls. Refuse rather than follow it.
    if cache_dir.is_symlink():
        logger.warning("refusing symlinked cache directory: %s", cache_dir)
        return transport
    try:
        cache_dir.mkdir(parents=True, exist_ok=True)
        cache_dir.chmod(0o700)
        db_path = cache_dir / "http.db"
        if db_path.is_symlink():
            logger.warning("refusing symlinked cache database: %s", db_path)
            return transport
        db_path.touch(mode=0o600, exist_ok=True)
        db_path.chmod(0o600)
        storage = AsyncSqliteStorage(
            database_path=str(db_path),
            default_ttl=settings.cache_ttl if settings else 3600,
        )
    except (ImportError, OSError) as exc:
        logger.debug("response caching unavailable: %s", exc)
        return transport

    return AsyncCacheTransport(next_transport=transport, storage=storage)


def make_client(
    settings: Settings | None = None,
    *,
    use_cache: bool = True,
    transport: httpx.AsyncBaseTransport | None = None,
) -> httpx.AsyncClient:
    """Build the single async client shared by every module in a scan."""
    next_transport = transport or httpx.AsyncHTTPTransport(retries=2)
    if use_cache:
        next_transport = _wrap_cache(next_transport, settings)

    timeout = settings.request_timeout if settings else 20.0
    user_agent = settings.user_agent if settings and settings.user_agent else None
    if not user_agent:
        mode = settings.identity_mode if settings else "install"
        token = settings.instance_token if settings else None
        user_agent = user_agent_for(mode, token)
    return httpx.AsyncClient(
        transport=next_transport,
        timeout=httpx.Timeout(timeout, connect=min(10.0, timeout)),
        limits=httpx.Limits(max_connections=50, max_keepalive_connections=20),
        http2=True,
        follow_redirects=True,
        max_redirects=5,
        headers={"User-Agent": user_agent},
    )


class TokenBucket:
    """Async token bucket for smooth per-source rate limiting."""

    def __init__(self, rate: float, burst: int | None = None) -> None:
        self.rate = max(rate, 0.01)
        self.burst = max(burst or int(self.rate * 2) or 1, 1)
        self._tokens = float(self.burst)
        self._updated = time.monotonic()
        self._lock = asyncio.Lock()

    async def acquire(self, tokens: int = 1) -> None:
        async with self._lock:
            while True:
                now = time.monotonic()
                self._tokens = min(
                    self.burst, self._tokens + (now - self._updated) * self.rate
                )
                self._updated = now
                if self._tokens >= tokens:
                    self._tokens -= tokens
                    return
                await asyncio.sleep((tokens - self._tokens) / self.rate)


async def _read_capped(response: httpx.Response, limit: int) -> bytes:
    """Read a response body, refusing more than ``limit`` decoded bytes."""
    chunks: list[bytes] = []
    total = 0
    async for chunk in response.aiter_bytes():
        total += len(chunk)
        if total > limit:
            raise RuntimeError(
                f"response from {response.url.host} exceeded the {limit}-byte limit"
            )
        chunks.append(chunk)
    return b"".join(chunks)


async def fetch_json(
    ctx,
    url: str,
    *,
    params: dict | None = None,
    headers: dict | None = None,
    bucket: TokenBucket | None = None,
    follow_redirects: bool | None = None,
) -> Any:
    """GET a URL as JSON, honouring Retry-After and transient 5xx errors.

    Pass ``follow_redirects=False`` for requests carrying credentials: httpx
    forwards custom headers (and query parameters) across hosts on redirects.
    Bodies larger than ``max_response_bytes`` are refused before parsing.
    """
    limit = getattr(ctx.settings, "max_response_bytes", DEFAULT_MAX_RESPONSE_BYTES)
    last_error: Exception | None = None
    for attempt in range(4):
        if bucket is not None:
            await bucket.acquire()
        try:
            async with ctx.http.stream(
                "GET", url, params=params, headers=headers, follow_redirects=follow_redirects
            ) as response:
                if follow_redirects is False and response.is_redirect:
                    raise RuntimeError(f"unexpected redirect from {response.url.host}")

                if response.status_code == 429:
                    try:
                        delay = float(response.headers.get("Retry-After", "2"))
                    except ValueError:
                        delay = 2**attempt
                    await asyncio.sleep(min(delay, 60.0))
                    continue
                if response.status_code in (500, 502, 503, 504):
                    await asyncio.sleep(2**attempt)
                    continue

                response.raise_for_status()
                body = await _read_capped(response, limit)
        except httpx.HTTPStatusError:
            raise  # callers handle status codes without leaking credentials
        except httpx.HTTPError as exc:
            last_error = exc
            await asyncio.sleep(2**attempt)
            continue

        try:
            return json.loads(body)
        except ValueError:
            raise RuntimeError(f"invalid JSON from {url}") from None

    # Exception text can contain the full URL (and therefore credentials).
    reason = type(last_error).__name__ if last_error else "no response"
    raise RuntimeError(f"request failed after retries: {url} ({reason})")
