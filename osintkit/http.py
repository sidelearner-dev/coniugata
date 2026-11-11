"""Shared HTTP plumbing: one client per scan, throttling, on-disk caching."""

from __future__ import annotations

import asyncio
import logging
import time
from pathlib import Path
from typing import Any

import httpx

from .config import Settings

DEFAULT_USER_AGENT = "osintkit/0.1 (authorized security research; contact: you@example.com)"
logger = logging.getLogger("osintkit.http")


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

    cache_dir = Path(settings.cache_dir if settings else ".cache/osintkit")
    try:
        cache_dir.mkdir(parents=True, exist_ok=True)
        cache_dir.chmod(0o700)
        db_path = cache_dir / "http.db"
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
    user_agent = settings.user_agent if settings and settings.user_agent else DEFAULT_USER_AGENT
    return httpx.AsyncClient(
        transport=next_transport,
        timeout=httpx.Timeout(timeout, connect=min(10.0, timeout)),
        limits=httpx.Limits(max_connections=50, max_keepalive_connections=20),
        http2=True,
        follow_redirects=True,
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


async def fetch_json(
    ctx,
    url: str,
    *,
    params: dict | None = None,
    headers: dict | None = None,
    bucket: TokenBucket | None = None,
) -> Any:
    """GET a URL as JSON, honouring Retry-After and transient 5xx errors."""
    last_error: Exception | None = None
    for attempt in range(4):
        if bucket is not None:
            await bucket.acquire()
        try:
            response = await ctx.http.get(url, params=params, headers=headers)
        except httpx.HTTPError as exc:
            last_error = exc
            await asyncio.sleep(2**attempt)
            continue

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
        return response.json()

    raise RuntimeError(f"request failed after retries: {url} ({last_error})")
