"""DNS resolution via dnspython: A/AAAA, MX, NS, CNAME."""

from __future__ import annotations

import dns.asyncresolver
import dns.exception
import dns.resolver

from ..models import Entity, EntityType
from ..registry import Module, register
from ..validators import is_valid_hostname

_RECORD_TYPES = ("A", "AAAA", "MX", "NS", "CNAME")


def _domain_entity(value: str, source: str, parent: str, rdtype: str) -> Entity | None:
    name = value.strip().lower().rstrip(".")
    if not name:  # e.g. a null MX record ("0 .")
        return None
    return Entity(
        type=EntityType.DOMAIN,
        value=name,
        source=source,
        parent=parent,
        confidence=0.9,
        raw={"rdtype": rdtype},
    )


@register
class DnsEnum(Module):
    name = "dns"
    accepts = frozenset({EntityType.DOMAIN})
    produces = frozenset({EntityType.IP, EntityType.DOMAIN})
    rate_limit = 10.0
    description = "DNS lookups: A, AAAA, MX, NS, CNAME"

    async def run(self, entity, ctx):
        domain = entity.value.strip().lower().rstrip(".")
        if not is_valid_hostname(domain):
            raise ValueError(f"invalid domain for DNS: {entity.value!r}")

        resolver = dns.asyncresolver.Resolver()
        resolver.lifetime = ctx.settings.request_timeout
        for rdtype in _RECORD_TYPES:
            try:
                answer = await resolver.resolve(
                    domain, rdtype, raise_on_no_answer=False
                )
            except (dns.resolver.NXDOMAIN, dns.resolver.NoNameservers, dns.exception.Timeout):
                continue
            except dns.exception.DNSException as exc:  # malformed/transient DNS failure
                ctx.log.debug("dns %s %s: %s", entity.value, rdtype, exc)
                continue

            if answer.rrset is None:
                continue
            for record in answer.rrset:
                if rdtype in {"A", "AAAA"}:
                    yield Entity(
                        type=EntityType.IP,
                        value=str(record),
                        source=self.name,
                        parent=entity.value,
                        confidence=0.95,
                        raw={"rdtype": rdtype},
                    )
                else:
                    target = (
                        record.exchange if rdtype == "MX" else record.target
                    ).to_text(omit_final_dot=True)
                    child = _domain_entity(target, self.name, entity.value, rdtype)
                    if child is not None:
                        yield child
