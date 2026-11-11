"""Engine behaviour: target classification, de-duplication, provenance."""

from __future__ import annotations

import logging

import httpx

from coniugata.config import Settings
from coniugata.engine import Context, build_seeds, detect_type, run_scan
from coniugata.models import Entity, EntityType
from coniugata.registry import Module


def test_detect_type():
    assert detect_type("https://Example.com/path") == (EntityType.DOMAIN, "example.com")
    assert detect_type("user@Example.com") == (EntityType.EMAIL, "user@example.com")
    assert detect_type("203.0.113.7")[0] is EntityType.IP


class FakeSource(Module):
    name = "fake"
    accepts = frozenset({EntityType.DOMAIN})
    produces = frozenset({EntityType.SUBDOMAIN})

    async def run(self, entity, ctx):
        value = f"a.{entity.value}"
        yield Entity(
            type=EntityType.SUBDOMAIN, value=value, source=self.name, parent=entity.value
        )
        # Same value from another source: must not be re-expanded, but must be kept.
        yield Entity(
            type=EntityType.SUBDOMAIN, value=value, source="other", parent=entity.value
        )


async def test_run_scan_dedupes_expansion_but_keeps_provenance():
    ctx = Context(
        http=httpx.AsyncClient(), settings=Settings(), log=logging.getLogger("test")
    )
    try:
        results = await run_scan(
            build_seeds(["example.com"]), [FakeSource()], ctx, max_depth=1
        )
    finally:
        await ctx.http.aclose()

    assert len(results) == 2
    assert {item.source for item in results} == {"fake", "other"}
    assert {item.value for item in results} == {"a.example.com"}
