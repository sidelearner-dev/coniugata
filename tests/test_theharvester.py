"""Offline tests for the theHarvester subprocess wrapper."""

from __future__ import annotations

import logging
import stat
import sys

import httpx
import pytest

from coniugata.config import Settings
from coniugata.engine import Context
from coniugata.models import Entity, EntityType
from coniugata.modules.theharvester import TheHarvester


def make_ctx(settings: Settings) -> Context:
    def unreachable(request: httpx.Request) -> httpx.Response:
        raise AssertionError(f"theHarvester wrapper made an HTTP request: {request.url}")

    return Context(
        http=httpx.AsyncClient(transport=httpx.MockTransport(unreachable)),
        settings=settings,
        log=logging.getLogger("test"),
    )


def make_fake_binary(tmp_path, body: str) -> str:
    path = tmp_path / "fake-theharvester"
    path.write_text(f"#!{sys.executable}\n{body}")
    path.chmod(path.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    return str(path)


async def collect(module: TheHarvester, ctx: Context, domain: str = "example.com"):
    return [
        item
        async for item in module.run(
            Entity(type=EntityType.DOMAIN, value=domain, source="seed"), ctx
        )
    ]


async def test_theharvester_parses_hosts_emails_and_ips(tmp_path):
    binary = make_fake_binary(
        tmp_path,
        """
import json
import sys

args = sys.argv[1:]
assert args[args.index("-d") + 1] == "example.com"
assert args[args.index("-b") + 1] == "crtsh,otx"
assert args[args.index("-l") + 1] == "25"
assert "-q" in args
base = args[args.index("-f") + 1]
with open(base + ".json", "w", encoding="utf-8") as handle:
    json.dump(
        {
            "cmd": "fake",
            "hosts": [
                "api.example.com:203.0.113.5",
                "*.wild.example.com:198.51.100.7",
                "example.com:203.0.113.6",
                "lookalike.test:198.51.100.9",
                "www.example.com:not-an-ip",
                "db.example.com:2001:db8::10",
            ],
            "emails": ["Ops@Example.com", "sales@example.com"],
        },
        handle,
    )
with open(base + ".xml", "w", encoding="utf-8") as handle:
    handle.write(
        '<?xml version="1.0"?><theHarvester><cmd>-d example.com</cmd>'
        "<email>ceo@example.com</email><email>broken@</email></theHarvester>"
    )
print("* cmartorella@edge-security.com *")
""",
    )
    settings = Settings(
        theharvester_bin=binary,
        theharvester_sources="crtsh,otx",
        theharvester_limit=25,
        theharvester_timeout=30,
    )
    ctx = make_ctx(settings)
    try:
        found = await collect(TheHarvester(), ctx)
    finally:
        await ctx.http.aclose()

    subdomains = {item.value for item in found if item.type is EntityType.SUBDOMAIN}
    ips = {item.value for item in found if item.type is EntityType.IP}
    emails = {item.value for item in found if item.type is EntityType.EMAIL}

    assert subdomains == {"api.example.com", "www.example.com", "db.example.com"}
    assert ips == {"203.0.113.5", "203.0.113.6", "2001:db8::10"}
    assert emails == {"ops@example.com", "sales@example.com", "ceo@example.com"}
    assert "cmartorella@edge-security.com" not in emails
    assert all(item.source == "theharvester" for item in found)


async def test_theharvester_kills_process_on_timeout(tmp_path):
    binary = make_fake_binary(tmp_path, "\nimport time\n\ntime.sleep(30)\n")
    settings = Settings(theharvester_bin=binary, theharvester_timeout=0.2)
    ctx = make_ctx(settings)
    try:
        with pytest.raises(RuntimeError, match="timed out"):
            await collect(TheHarvester(), ctx)
    finally:
        await ctx.http.aclose()


async def test_theharvester_reports_missing_binary(tmp_path):
    settings = Settings(theharvester_bin=str(tmp_path / "does-not-exist"))
    ctx = make_ctx(settings)
    try:
        with pytest.raises(RuntimeError, match="not found"):
            await collect(TheHarvester(), ctx)
    finally:
        await ctx.http.aclose()
