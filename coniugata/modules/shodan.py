"""Shodan host enrichment (requires an API key)."""

from __future__ import annotations

import httpx

from ..http import fetch_json
from ..models import Entity, EntityType
from ..registry import Module, register
from ..validators import is_valid_hostname, normalize_ip


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
        ip = normalize_ip(entity.value)
        if ip is None:
            raise ValueError(f"invalid IP for Shodan: {entity.value!r}")

        try:
            data = await fetch_json(
                ctx,
                f"https://api.shodan.io/shodan/host/{ip}",
                params={"key": ctx.settings.shodan_key or "", "minify": "true"},
                bucket=ctx.bucket(self),
                follow_redirects=False,
            )
        except httpx.HTTPStatusError as exc:
            if exc.response.status_code == 404:  # Shodan has no record for this IP
                return
            # Do not stringify the original error: its URL contains the API key.
            raise RuntimeError(
                f"Shodan request failed: HTTP {exc.response.status_code}"
            ) from None

        if not isinstance(data, dict):
            return

        asn = data.get("asn")
        if asn:
            yield Entity(
                type=EntityType.ASN,
                value=str(asn),
                source=self.name,
                parent=ip,
                confidence=0.9,
                raw={"isp": data.get("isp"), "country": data.get("country_name")},
            )

        org = data.get("org") or data.get("isp")
        if org:
            yield Entity(
                type=EntityType.ORG,
                value=str(org),
                source=self.name,
                parent=ip,
                confidence=0.8,
                raw={"os": data.get("os"), "ports": data.get("ports", [])},
            )

        names: set[str] = set()
        for key in ("hostnames", "domains"):
            values = data.get(key)
            if isinstance(values, list):
                names.update(str(name) for name in values)

        for name in sorted(names):
            name = name.strip().lower().rstrip(".")
            if not is_valid_hostname(name):
                continue
            yield Entity(
                type=EntityType.DOMAIN,
                value=name,
                source=self.name,
                parent=ip,
                confidence=0.7,
                raw={"ports": data.get("ports", [])},
            )
