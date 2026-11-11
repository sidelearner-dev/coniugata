"""HaveIBeenPwned: breach exposure for an email (paid API key required)."""

from __future__ import annotations

from urllib.parse import quote

import httpx

from ..http import fetch_json
from ..models import Entity, EntityType
from ..registry import Module, register
from ..validators import is_valid_email


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
        email = entity.value.strip().lower()
        if not is_valid_email(email):
            raise ValueError(f"invalid email for HIBP: {entity.value!r}")

        # `+` and `/` are valid local-part characters, so encode them rather
        # than letting them change the request path or query.
        url = (
            "https://haveibeenpwned.com/api/v3/breachedaccount/"
            + quote(email, safe="@")
        )
        headers = {"hibp-api-key": ctx.settings.hibp_key or ""}
        try:
            data = await fetch_json(
                ctx,
                url,
                headers=headers,
                params={"truncateResponse": "false"},
                bucket=ctx.bucket(self),
                follow_redirects=False,
            )
        except httpx.HTTPStatusError as exc:
            if exc.response.status_code == 404:  # no breaches for this address
                return
            raise RuntimeError(
                f"HIBP request failed: HTTP {exc.response.status_code}"
            ) from None

        if not isinstance(data, list):
            return
        for breach in data:
            if not isinstance(breach, dict):
                continue
            yield Entity(
                type=EntityType.BREACH,
                value=str(breach.get("Name", "unknown")),
                source=self.name,
                parent=email,
                confidence=1.0,
                raw={
                    "title": breach.get("Title"),
                    "breach_date": breach.get("BreachDate"),
                    "pwn_count": breach.get("PwnCount"),
                    "data_classes": breach.get("DataClasses", []),
                    "is_verified": breach.get("IsVerified"),
                },
            )
