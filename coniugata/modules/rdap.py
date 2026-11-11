"""RDAP: structured registration data (a modern WHOIS replacement)."""

from __future__ import annotations

from ..http import fetch_json
from ..models import Entity, EntityType
from ..registry import Module, register
from ..validators import is_valid_hostname


def _first_text(entry: dict) -> str | None:
    vcard = entry.get("vcardArray")
    if not vcard or len(vcard) < 2:
        return None
    for prop in vcard[1]:
        if prop and prop[0] in {"org", "fn"} and len(prop) > 3:
            value = prop[3]
            if isinstance(value, list):
                value = " ".join(str(part) for part in value if part)
            if value:
                return str(value).strip()
    return None


@register
class Rdap(Module):
    name = "rdap"
    accepts = frozenset({EntityType.DOMAIN})
    produces = frozenset({EntityType.DOMAIN, EntityType.ORG})
    rate_limit = 2.0
    description = "RDAP registration data: nameservers and registrant org"

    async def run(self, entity, ctx):
        domain = entity.value.strip().lower().rstrip(".")
        if not is_valid_hostname(domain):
            raise ValueError(f"invalid domain for RDAP: {entity.value!r}")

        data = await fetch_json(
            ctx, f"https://rdap.org/domain/{domain}", bucket=ctx.bucket(self)
        )
        if not isinstance(data, dict):
            return

        servers = data.get("nameservers")
        if isinstance(servers, list):
            for server in servers:
                if not isinstance(server, dict):
                    continue
                name = str(server.get("ldhName", "")).lower().rstrip(".")
                if not name or not is_valid_hostname(name):
                    continue
                yield Entity(
                    type=EntityType.DOMAIN,
                    value=name,
                    source=self.name,
                    parent=domain,
                    confidence=0.9,
                    raw={"role": "nameserver"},
                )

        entities = data.get("entities")
        if isinstance(entities, list):
            for entry in entities:
                if not isinstance(entry, dict):
                    continue
                org = _first_text(entry)
                if org:
                    yield Entity(
                        type=EntityType.ORG,
                        value=org,
                        source=self.name,
                        parent=domain,
                        confidence=0.6,
                        raw={"roles": entry.get("roles", [])},
                    )
