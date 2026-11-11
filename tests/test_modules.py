"""Offline module tests. No network calls, no API keys needed."""

from __future__ import annotations

import logging

import httpx

from osintkit.config import Settings
from osintkit.engine import Context
from osintkit.models import Entity, EntityType
from osintkit.modules.crtsh import CrtSh
from osintkit.modules.rdap import Rdap
from osintkit.modules.shodan import Shodan
from osintkit.modules.urlscan import Urlscan


def make_ctx(handler, settings: Settings | None = None) -> Context:
    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    return Context(
        http=client,
        settings=settings or Settings(),
        log=logging.getLogger("test"),
    )


async def test_crtsh_extracts_subdomains():
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.params["q"] == "%.example.com"
        return httpx.Response(
            200,
            json=[
                {
                    "name_value": (
                        "*.dev.example.com\napi.example.com\n"
                        "m.testexample.com\nuser@example.com\n"
                        "Example Intermediate - example.com"
                    ),
                    "issuer_name": "LE",
                }
            ],
        )

    ctx = make_ctx(handler)
    try:
        found = [
            item
            async for item in CrtSh().run(
                Entity(type=EntityType.DOMAIN, value="example.com", source="seed"), ctx
            )
        ]
    finally:
        await ctx.http.aclose()

    assert {item.value for item in found} == {"dev.example.com", "api.example.com"}
    assert all(item.type is EntityType.SUBDOMAIN for item in found)


async def test_rdap_extracts_nameservers_and_org():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={
                "nameservers": [{"ldhName": "NS1.EXAMPLE.COM."}],
                "entities": [
                    {
                        "roles": ["registrant"],
                        "vcardArray": [
                            "vcard",
                            [["org", {}, "text", "Example Org"]],
                        ],
                    }
                ],
            },
        )

    ctx = make_ctx(handler)
    try:
        found = [
            item
            async for item in Rdap().run(
                Entity(type=EntityType.DOMAIN, value="example.com", source="seed"), ctx
            )
        ]
    finally:
        await ctx.http.aclose()

    pairs = {(item.type.value, item.value) for item in found}
    assert ("domain", "ns1.example.com") in pairs
    assert ("org", "Example Org") in pairs


async def test_shodan_enriches_ip():
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.params["key"] == "test-key"
        return httpx.Response(
            200,
            json={
                "org": "Example Hosting",
                "isp": "Example ISP",
                "asn": "AS64500",
                "hostnames": ["host1.example.com"],
                "domains": ["example.com"],
                "ports": [80, 443],
                "country_name": "Netherlands",
            },
        )

    ctx = make_ctx(handler, Settings(shodan_key="test-key"))
    try:
        found = [
            item
            async for item in Shodan().run(
                Entity(type=EntityType.IP, value="203.0.113.7", source="seed"), ctx
            )
        ]
    finally:
        await ctx.http.aclose()

    pairs = {(item.type.value, item.value) for item in found}
    assert ("asn", "AS64500") in pairs
    assert ("org", "Example Hosting") in pairs
    assert ("domain", "host1.example.com") in pairs
    assert ("domain", "example.com") in pairs


async def test_urlscan_extracts_page_entities():
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.params["q"] == "domain:example.com"
        assert request.headers.get("api-key") == "test-key"
        return httpx.Response(
            200,
            json={
                "results": [
                    {
                        "page": {
                            "url": "https://login.example.com/",
                            "domain": "example.com",
                            "ip": "203.0.113.9",
                            "asn": "AS64500",
                            "asnname": "Example ASN",
                            "server": "nginx",
                            "title": "Login",
                        },
                        "task": {"uuid": "abc", "time": "2026-01-01T00:00:00Z"},
                    },
                    {
                        "page": {
                            "url": "https://unrelated.test/",
                            "domain": "unrelated.test",
                            "ip": "198.51.100.5",
                        },
                        "task": {"uuid": "def", "time": "2026-01-02T00:00:00Z"},
                    },
                ]
            },
        )

    ctx = make_ctx(handler, Settings(urlscan_key="test-key"))
    try:
        found = [
            item
            async for item in Urlscan().run(
                Entity(type=EntityType.DOMAIN, value="example.com", source="seed"), ctx
            )
        ]
    finally:
        await ctx.http.aclose()

    pairs = {(item.type.value, item.value) for item in found}
    assert ("url", "https://login.example.com/") in pairs
    assert ("ip", "203.0.113.9") in pairs
    assert ("asn", "AS64500") in pairs
    assert ("org", "Example ASN") in pairs
    assert ("url", "https://unrelated.test/") not in pairs
