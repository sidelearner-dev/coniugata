"""Core data model. Typed entities are the currency of the whole engine."""

from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum

from pydantic import BaseModel, Field


class EntityType(StrEnum):
    DOMAIN = "domain"
    SUBDOMAIN = "subdomain"
    IP = "ip"
    ASN = "asn"
    URL = "url"
    CERT = "cert"
    EMAIL = "email"
    BREACH = "breach"
    CREDENTIAL = "credential"  # metadata only, never plaintext secrets
    ORG = "org"


class Entity(BaseModel):
    """A single discovered fact, tagged with where it came from."""

    type: EntityType
    value: str
    source: str
    parent: str | None = None
    confidence: float = 0.5
    first_seen: datetime = Field(default_factory=lambda: datetime.now(UTC))
    raw: dict = Field(default_factory=dict)

    @property
    def key(self) -> str:
        """Canonical identity used for de-duplication."""
        return f"{self.type.value}:{self.value.strip().lower()}"
