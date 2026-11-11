"""Shodan host enrichment (requires an API key)."""

from __future__ import annotations

import httpx

from ..http import fetch_json
from ..models import Entity, EntityType
from ..registry import Module, register


@register
class Shodan(Module):
    name = "shodan"
    accepts = frozenset({EntityType.IP})
    produces = frozenset({EntityType.ORG, EntityType.ASN, EntityType.DOMAIN})
    requires_key = True
    key_attr = "shodan_key"
    rate_limit = 1.0
    description = "Shodan host lookups: org, ASN, hostnames (IP, API key required)"

    async def run(self, entity, ctx):
        try:
            data = await fetch_json(
                ctx,
                f"https://api.shodan.io/shodan/host/{entity.value}",
                params={"key": ctx.settings.shodan_key or "", "minify": "true"},
                bucket=ctx.bucket(self),
            )
        except httpx.HTTPStatusError as exc:
            if exc.response.status_code == 404:  # Shodan has no record for this IP
                return
            raise

        asn = data.get("asn")
        if asn:
            yield Entity(
                type=EntityType.ASN,
                value=str(asn),
                source=self.name,
                parent=entity.value,
                confidence=0.9,
                raw={"isp": data.get("isp"), "country": data.get("country_name")},
            )

        org = data.get("org") or data.get("isp")
        if org:
            yield Entity(
                type=EntityType.ORG,
                value=str(org),
                source=self.name,
                parent=entity.value,
                confidence=0.8,
                raw={"os": data.get("os"), "ports": data.get("ports", [])},
            )

        names = set(data.get("hostnames") or []) | set(data.get("domains") or [])
        for name in sorted(str(n).lower().rstrip(".") for n in names):
            if name:
                yield Entity(
                    type=EntityType.DOMAIN,
                    value=name,
                    source=self.name,
                    parent=entity.value,
                    confidence=0.7,
                    raw={"ports": data.get("ports", [])},
                )
