"""Graph-expansion engine and per-scan context."""

from __future__ import annotations

import asyncio
import ipaddress
import logging
from dataclasses import dataclass, field
from urllib.parse import urlparse

import httpx

from .config import Settings
from .http import TokenBucket
from .models import Entity, EntityType
from .registry import Module


@dataclass
class Context:
    """Everything a module needs at runtime."""

    http: httpx.AsyncClient
    settings: Settings
    log: logging.Logger
    concurrency: int = 10
    buckets: dict[str, TokenBucket] = field(default_factory=dict)

    def bucket(self, mod: Module) -> TokenBucket:
        bucket = self.buckets.get(mod.name)
        if bucket is None:
            bucket = TokenBucket(mod.rate_limit)
            self.buckets[mod.name] = bucket
        return bucket


def detect_type(value: str) -> tuple[EntityType, str]:
    """Best-effort classification of a raw target string."""
    raw = value.strip()
    if raw.startswith(("http://", "https://")):
        raw = urlparse(raw).hostname or raw
    try:
        ipaddress.ip_address(raw)
        return EntityType.IP, raw
    except ValueError:
        pass
    if "@" in raw and "." in raw.rsplit("@", 1)[-1]:
        return EntityType.EMAIL, raw.lower()
    domain = raw.lower().rstrip(".")
    domain = domain.removeprefix("*.")
    return EntityType.DOMAIN, domain


def build_seeds(targets: list[str]) -> list[Entity]:
    seeds: list[Entity] = []
    for target in targets:
        entity_type, value = detect_type(target)
        seeds.append(Entity(type=entity_type, value=value, source="seed", confidence=1.0))
    return seeds


async def _collect(mod: Module, entity: Entity, ctx: Context) -> list[Entity]:
    try:
        return [item async for item in mod.run(entity, ctx)]
    except Exception as exc:  # isolate a failing source, keep the scan alive
        raise RuntimeError(f"{mod.name} failed on {entity.value}: {exc}") from exc


async def run_scan(
    seeds: list[Entity],
    modules: list[Module],
    ctx: Context,
    max_depth: int = 3,
) -> list[Entity]:
    """Breadth-first expansion: run every matching source, feed results back in."""
    seen = {seed.key for seed in seeds}
    frontier = list(seeds)
    results: list[Entity] = []
    semaphore = asyncio.Semaphore(max(1, ctx.concurrency))

    async def guarded(mod: Module, entity: Entity) -> list[Entity]:
        async with semaphore:
            return await _collect(mod, entity, ctx)

    for depth in range(max_depth):
        if not frontier:
            break

        tasks = [
            asyncio.create_task(guarded(mod, entity))
            for entity in frontier
            for mod in modules
            if entity.type in mod.accepts
        ]
        if not tasks:
            break

        discovered: list[Entity] = []
        for future in asyncio.as_completed(tasks):
            try:
                found = await future
            except Exception as exc:  # noqa: BLE001 - one bad plugin must not kill the scan
                ctx.log.warning("%s", exc)
                continue
            for item in found:
                # Keep every occurrence in the report (multi-source provenance) ...
                results.append(item)
                # ... but only expand genuinely new entities.
                if item.key not in seen:
                    seen.add(item.key)
                    discovered.append(item)

        ctx.log.info(
            "depth %d: %d new entities (%d results)", depth, len(discovered), len(results)
        )
        frontier = discovered

    return results
