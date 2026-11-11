"""Tiny plugin registry. Importing a module registers it automatically."""

from __future__ import annotations

from .models import Entity, EntityType

REGISTRY: dict[str, type[Module]] = {}


def register(cls: type[Module]) -> type[Module]:
    if not getattr(cls, "name", ""):
        raise ValueError(f"{cls.__name__} must define a unique `name`")
    if cls.name in REGISTRY:
        raise ValueError(f"duplicate module name: {cls.name}")
    REGISTRY[cls.name] = cls
    return cls


class Module:
    """Base class for a source.

    Subclasses implement ``async def run(self, entity, ctx)`` as an async
    generator that yields :class:`~coniugata.models.Entity` objects.
    """

    name: str = ""
    accepts: frozenset[EntityType] = frozenset()
    produces: frozenset[EntityType] = frozenset()
    requires_key: bool = False
    key_attr: str | None = None
    rate_limit: float = 1.0
    description: str = ""

    def run(self, entity: Entity, ctx):
        raise NotImplementedError
