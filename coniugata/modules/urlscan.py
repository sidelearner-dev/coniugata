"""urlscan.io search: URLs, IPs, ASNs and orgs seen for a domain."""

from __future__ import annotations

from ..http import fetch_json
from ..models import Entity, EntityType
from ..registry import Module, register


def _asn_value(raw) -> str:
    value = str(raw).strip().upper()
    return value if value.startswith("AS") else f"AS{value}"


@register
class Urlscan(Module):
    name = "urlscan"
    accepts = frozenset({EntityType.DOMAIN})
    produces = frozenset(
        {EntityType.URL, EntityType.IP, EntityType.ASN, EntityType.ORG}
    )
    # Search works anonymously; an API key just raises the rate limit.
    rate_limit = 1.0
    description = "urlscan.io search: recent scans, URLs, IPs, ASNs (optional API key)"

    async def run(self, entity, ctx):
        headers = {"API-Key": ctx.settings.urlscan_key} if ctx.settings.urlscan_key else None
        data = await fetch_json(
            ctx,
            "https://urlscan.io/api/v1/search/",
            params={"q": f"domain:{entity.value}", "size": 100},
            headers=headers,
            bucket=ctx.bucket(self),
        )

        for result in data.get("results") or []:
            page = result.get("page") or {}
            task = result.get("task") or {}

            # `domain:` also matches third-party pages that merely load target
            # resources, so keep only scans whose page belongs to the target.
            page_domain = str(page.get("domain") or "").lower().rstrip(".")
            if page_domain and page_domain != entity.value and not page_domain.endswith(
                "." + entity.value
            ):
                continue

            url = page.get("url") or task.get("url")
            if url:
                yield Entity(
                    type=EntityType.URL,
                    value=str(url),
                    source=self.name,
                    parent=entity.value,
                    confidence=0.8,
                    raw={
                        "uuid": task.get("uuid"),
                        "scanned": task.get("time"),
                        "server": page.get("server"),
                        "title": page.get("title"),
                    },
                )

            ip = page.get("ip")
            if ip:
                yield Entity(
                    type=EntityType.IP,
                    value=str(ip),
                    source=self.name,
                    parent=entity.value,
                    confidence=0.85,
                    raw={"country": page.get("country"), "server": page.get("server")},
                )

            asn = page.get("asn")
            if asn:
                yield Entity(
                    type=EntityType.ASN,
                    value=_asn_value(asn),
                    source=self.name,
                    parent=entity.value,
                    confidence=0.85,
                    raw={"asnname": page.get("asnname")},
                )

            org = page.get("asnname")
            if org:
                yield Entity(
                    type=EntityType.ORG,
                    value=str(org),
                    source=self.name,
                    parent=entity.value,
                    confidence=0.8,
                    raw={"asn": page.get("asn")},
                )
