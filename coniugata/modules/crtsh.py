"""crt.sh: certificate transparency logs -> subdomains (free, no key)."""

from __future__ import annotations

import re

from ..http import fetch_json
from ..models import Entity, EntityType
from ..registry import Module, register

_LABEL = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")


def _valid_hostname(name: str) -> bool:
    if len(name) > 253 or any(ch in name for ch in " @/"):
        return False
    labels = name.rstrip(".").split(".")
    return len(labels) >= 2 and all(_LABEL.match(label) for label in labels)


@register
class CrtSh(Module):
    name = "crtsh"
    accepts = frozenset({EntityType.DOMAIN})
    produces = frozenset({EntityType.SUBDOMAIN})
    rate_limit = 1.0
    description = "Certificate transparency (crt.sh) subdomain discovery"

    async def run(self, entity, ctx):
        data = await fetch_json(
            ctx,
            "https://crt.sh/",
            params={"q": f"%.{entity.value}", "output": "json"},
            bucket=ctx.bucket(self),
        )
        seen: set[str] = set()
        for row in data or []:
            for raw_name in str(row.get("name_value", "")).splitlines():
                name = raw_name.strip().lower().lstrip("*.").rstrip(".")
                # Keep only real subdomains of the target: no issuer CNs, emails,
                # and no lookalikes such as "testexample.com" for "example.com".
                if not _valid_hostname(name):
                    continue
                if name == entity.value or not name.endswith("." + entity.value):
                    continue
                if name in seen:
                    continue
                seen.add(name)
                yield Entity(
                    type=EntityType.SUBDOMAIN,
                    value=name,
                    source=self.name,
                    parent=entity.value,
                    confidence=0.8,
                    raw={
                        "issuer": row.get("issuer_name"),
                        "not_after": row.get("not_after"),
                    },
                )
