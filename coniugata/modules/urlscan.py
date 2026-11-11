"""urlscan.io search: URLs, IPs, ASNs and orgs seen for a domain."""

from __future__ import annotations

from ..http import fetch_json
from ..models import Entity, EntityType
from ..registry import Module, register
from ..validators import is_valid_hostname, normalize_ip


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
        domain = entity.value.strip().lower().rstrip(".")
        if not is_valid_hostname(domain):
            raise ValueError(f"invalid domain for urlscan: {entity.value!r}")

        headers = {"API-Key": ctx.settings.urlscan_key} if ctx.settings.urlscan_key else None
        data = await fetch_json(
            ctx,
            "https://urlscan.io/api/v1/search/",
            params={"q": f"domain:{domain}", "size": 100},
            headers=headers,
            bucket=ctx.bucket(self),
            # An API key travels in a custom header; don't forward it on redirects.
            follow_redirects=not bool(ctx.settings.urlscan_key),
        )
        if not isinstance(data, dict):
            return
        results = data.get("results")
        if not isinstance(results, list):
            return

        for result in results:
            if not isinstance(result, dict):
                continue
            page = result.get("page")
            task = result.get("task")
            page = page if isinstance(page, dict) else {}
            task = task if isinstance(task, dict) else {}

            # `domain:` also matches third-party pages that merely load target
            # resources, so keep only scans whose page belongs to the target.
            page_domain = str(page.get("domain") or "").lower().rstrip(".")
            if page_domain and page_domain != domain and not page_domain.endswith(
                "." + domain
            ):
                continue

            url = page.get("url") or task.get("url")
            if url:
                url = str(url).strip()
                if url.lower().startswith(("http://", "https://")):
                    yield Entity(
                        type=EntityType.URL,
                        value=url,
                        source=self.name,
                        parent=domain,
                        confidence=0.8,
                        raw={
                            "uuid": task.get("uuid"),
                            "scanned": task.get("time"),
                            "server": page.get("server"),
                            "title": page.get("title"),
                        },
                    )

            ip = normalize_ip(page.get("ip") or "")
            if ip is not None:
                yield Entity(
                    type=EntityType.IP,
                    value=ip,
                    source=self.name,
                    parent=domain,
                    confidence=0.85,
                    raw={"country": page.get("country"), "server": page.get("server")},
                )

            asn = page.get("asn")
            if asn:
                yield Entity(
                    type=EntityType.ASN,
                    value=_asn_value(asn),
                    source=self.name,
                    parent=domain,
                    confidence=0.85,
                    raw={"asnname": page.get("asnname")},
                )

            org = page.get("asnname")
            if org:
                yield Entity(
                    type=EntityType.ORG,
                    value=str(org),
                    source=self.name,
                    parent=domain,
                    confidence=0.8,
                    raw={"asn": page.get("asn")},
                )
