"""HaveIBeenPwned: breach exposure for an email (paid API key required)."""

from __future__ import annotations

import httpx

from ..http import fetch_json
from ..models import Entity, EntityType
from ..registry import Module, register


@register
class HaveIBeenPwned(Module):
    name = "hibp"
    accepts = frozenset({EntityType.EMAIL})
    produces = frozenset({EntityType.BREACH})
    requires_key = True
    key_attr = "hibp_key"
    rate_limit = 1.0
    description = "HaveIBeenPwned breach exposure (email, API key required)"

    async def run(self, entity, ctx):
        url = f"https://haveibeenpwned.com/api/v3/breachedaccount/{entity.value}"
        headers = {"hibp-api-key": ctx.settings.hibp_key or ""}
        try:
            data = await fetch_json(
                ctx,
                url,
                headers=headers,
                params={"truncateResponse": "false"},
                bucket=ctx.bucket(self),
            )
        except httpx.HTTPStatusError as exc:
            if exc.response.status_code == 404:  # no breaches for this address
                return
            raise

        for breach in data or []:
            yield Entity(
                type=EntityType.BREACH,
                value=breach.get("Name", "unknown"),
                source=self.name,
                parent=entity.value,
                confidence=1.0,
                raw={
                    "title": breach.get("Title"),
                    "breach_date": breach.get("BreachDate"),
                    "pwn_count": breach.get("PwnCount"),
                    "data_classes": breach.get("DataClasses", []),
                    "is_verified": breach.get("IsVerified"),
                },
            )
