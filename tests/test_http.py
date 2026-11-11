"""HTTP layer tests: verify that the client caches GET responses on disk."""

from __future__ import annotations

import httpx
import pytest

from coniugata.config import Settings
from coniugata.http import make_client

pytest.importorskip("hishel")
pytest.importorskip("anysqlite")


async def test_make_client_caches_get_responses(tmp_path):
    calls = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        return httpx.Response(200, json={"n": calls["n"]})

    settings = Settings(cache_dir=str(tmp_path / "cache"))
    async with make_client(settings, transport=httpx.MockTransport(handler)) as client:
        first = (await client.get("https://cache.test/x")).json()
        second = (await client.get("https://cache.test/x")).json()

    assert calls["n"] == 1
    assert first == second == {"n": 1}


async def test_make_client_no_cache(tmp_path):
    calls = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        return httpx.Response(200, json={"n": calls["n"]})

    settings = Settings(cache_dir=str(tmp_path / "cache"))
    async with make_client(
        settings, use_cache=False, transport=httpx.MockTransport(handler)
    ) as client:
        await client.get("https://cache.test/x")
        await client.get("https://cache.test/x")

    assert calls["n"] == 2
