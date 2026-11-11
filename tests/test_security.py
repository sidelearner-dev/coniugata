"""Adversarial tests: injection, untrusted upstream data, cache and output safety."""

from __future__ import annotations

import csv
import io
import logging
import os
import stat
import sys
from types import SimpleNamespace

import httpx
import pytest
from pydantic import ValidationError
from rich.console import Console

import coniugata.report as report_module
from coniugata.config import Settings
from coniugata.engine import Context
from coniugata.http import make_client
from coniugata.models import Entity, EntityType
from coniugata.modules.crtsh import CrtSh
from coniugata.modules.hibp import HaveIBeenPwned
from coniugata.modules.rdap import Rdap
from coniugata.modules.shodan import Shodan
from coniugata.modules.theharvester import TheHarvester
from coniugata.modules.urlscan import Urlscan
from coniugata.report import render, write_report
from coniugata.validators import is_valid_email, is_valid_hostname, normalize_ip


def make_ctx(handler, settings: Settings | None = None) -> Context:
    return Context(
        http=httpx.AsyncClient(transport=httpx.MockTransport(handler)),
        settings=settings or Settings(),
        log=logging.getLogger("test"),
    )


def unreachable(request: httpx.Request) -> httpx.Response:
    raise AssertionError(f"unexpected request: {request.url}")


async def collect(module, entity: Entity, ctx: Context) -> list[Entity]:
    return [item async for item in module.run(entity, ctx)]


def fake_binary(tmp_path, body: str) -> str:
    path = tmp_path / "fake-theharvester"
    path.write_text(f"#!{sys.executable}\n{body}")
    path.chmod(path.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    return str(path)


def test_validators_reject_injection_and_malformed_values():
    assert is_valid_hostname("example.com")
    assert is_valid_hostname("a-b.example.co.uk")
    for bad in (
        "-d",
        "--help",
        "example.com;id",
        "../etc/passwd",
        "exa mple.com",
        "*.example.com",
        "1.2.3.4",
        "",
    ):
        assert not is_valid_hostname(bad), bad

    assert is_valid_email("user+tag@example.com")
    for bad in (
        "user@example.com/../../admin",
        "user@example.com?x=1",
        "a@b..com",
        "a@@example.com",
        "a@-example.com",
    ):
        assert not is_valid_email(bad), bad

    assert normalize_ip("2001:0db8::1") == "2001:db8::1"
    assert normalize_ip("203.0.113.7") == "203.0.113.7"
    assert normalize_ip("not-an-ip") is None


@pytest.mark.parametrize(
    "domain",
    [
        "example.com; touch /tmp/pwned",
        "--help",
        "-d",
        "../etc/passwd",
        "exa mple.com",
        "example.com\n-b all",
    ],
)
async def test_theharvester_rejects_invalid_domains_without_spawning(tmp_path, domain):
    marker = tmp_path / "spawned"
    binary = fake_binary(
        tmp_path,
        f"from pathlib import Path\nPath({str(marker)!r}).write_text('spawned')\n",
    )
    settings = Settings(theharvester_bin=binary, theharvester_timeout=5)
    ctx = make_ctx(unreachable, settings)
    try:
        with pytest.raises(RuntimeError, match="invalid domain"):
            await collect(
                TheHarvester(),
                Entity(type=EntityType.DOMAIN, value=domain, source="seed"),
                ctx,
            )
    finally:
        await ctx.http.aclose()

    assert not marker.exists()


async def test_hibp_encodes_email_and_rejects_path_injection():
    seen: list[httpx.URL] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request.url)
        return httpx.Response(200, json=[{"Name": "ExampleBreach"}])

    settings = Settings(hibp_key="test-key")
    ctx = make_ctx(handler, settings)
    try:
        found = await collect(
            HaveIBeenPwned(),
            Entity(type=EntityType.EMAIL, value="user+tag@example.com", source="seed"),
            ctx,
        )
        assert [item.value for item in found] == ["ExampleBreach"]
        assert seen[0].path.endswith("user+tag@example.com")
        assert seen[0].raw_path.split(b"?")[0].endswith(b"user%2Btag@example.com")
        assert seen[0].params["truncateResponse"] == "false"

        with pytest.raises(ValueError, match="invalid email"):
            await collect(
                HaveIBeenPwned(),
                Entity(
                    type=EntityType.EMAIL,
                    value="user@example.com/../../admin",
                    source="seed",
                ),
                ctx,
            )
    finally:
        await ctx.http.aclose()
    assert len(seen) == 1  # the invalid address never reached the network


async def test_rdap_rejects_domain_used_for_path_injection():
    ctx = make_ctx(unreachable)
    try:
        with pytest.raises(ValueError, match="invalid domain"):
            await collect(
                Rdap(),
                Entity(
                    type=EntityType.DOMAIN,
                    value="example.com?x=1",
                    source="seed",
                ),
                ctx,
            )
    finally:
        await ctx.http.aclose()


async def test_shodan_rejects_non_ip_values():
    ctx = make_ctx(unreachable, Settings(shodan_key="test-key"))
    try:
        with pytest.raises(ValueError, match="invalid IP"):
            await collect(
                Shodan(),
                Entity(
                    type=EntityType.IP,
                    value="203.0.113.7/../../admin",
                    source="seed",
                ),
                ctx,
            )
    finally:
        await ctx.http.aclose()


@pytest.mark.parametrize(
    ("module", "entity", "settings", "payload"),
    [
        (CrtSh(), Entity(type=EntityType.DOMAIN, value="example.com", source="seed"), Settings(), {}),
        (Rdap(), Entity(type=EntityType.DOMAIN, value="example.com", source="seed"), Settings(), []),
        (
            Urlscan(),
            Entity(type=EntityType.DOMAIN, value="example.com", source="seed"),
            Settings(),
            {"results": "not-a-list"},
        ),
        (
            Shodan(),
            Entity(type=EntityType.IP, value="203.0.113.7", source="seed"),
            Settings(shodan_key="test-key"),
            [],
        ),
        (
            HaveIBeenPwned(),
            Entity(type=EntityType.EMAIL, value="user@example.com", source="seed"),
            Settings(hibp_key="test-key"),
            {},
        ),
    ],
)
async def test_modules_ignore_unexpected_json_shapes(module, entity, settings, payload):
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=payload)

    ctx = make_ctx(handler, settings)
    try:
        assert await collect(module, entity, ctx) == []
    finally:
        await ctx.http.aclose()


async def test_urlscan_drops_non_http_urls_and_invalid_ips():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={
                "results": [
                    {
                        "page": {
                            "domain": "example.com",
                            "url": "javascript:alert(1)",
                            "ip": "not-an-ip",
                        }
                    }
                ]
            },
        )

    ctx = make_ctx(handler)
    try:
        found = await collect(
            Urlscan(),
            Entity(type=EntityType.DOMAIN, value="example.com", source="seed"),
            ctx,
        )
    finally:
        await ctx.http.aclose()
    assert found == []


async def test_shodan_error_does_not_leak_api_key():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(401, json={"error": "invalid key"})

    ctx = make_ctx(handler, Settings(shodan_key="super-secret-key"))
    try:
        with pytest.raises(RuntimeError) as excinfo:
            await collect(
                Shodan(),
                Entity(type=EntityType.IP, value="203.0.113.7", source="seed"),
                ctx,
            )
    finally:
        await ctx.http.aclose()

    assert "401" in str(excinfo.value)
    assert "super-secret-key" not in str(excinfo.value)


@pytest.mark.parametrize(
    ("module", "entity", "settings"),
    [
        (
            Shodan(),
            Entity(type=EntityType.IP, value="203.0.113.7", source="seed"),
            Settings(shodan_key="super-secret-key"),
        ),
        (
            HaveIBeenPwned(),
            Entity(type=EntityType.EMAIL, value="user@example.com", source="seed"),
            Settings(hibp_key="super-secret-key"),
        ),
    ],
)
async def test_keyed_modules_do_not_follow_redirects(module, entity, settings):
    calls: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request)
        return httpx.Response(302, headers={"Location": "https://evil.test/steal"})

    ctx = make_ctx(handler, settings)
    try:
        with pytest.raises(RuntimeError, match="unexpected redirect"):
            await collect(module, entity, ctx)
    finally:
        await ctx.http.aclose()

    assert len(calls) == 1  # the Location header was never followed


def test_csv_report_neutralizes_formula_injection(tmp_path):
    values = ["=1+1", "+cmd|' /C calc'!A0", "-2+3", "@SUM(A1)", "Example Org"]
    entities = [
        Entity(type=EntityType.ORG, value=value, source="rdap") for value in values
    ]
    path = write_report(entities, str(tmp_path / "report.csv"))
    with open(path, newline="", encoding="utf-8") as handle:
        written = {row["value"] for row in csv.DictReader(handle)}

    assert "'=1+1" in written
    assert "'+cmd|' /C calc'!A0" in written
    assert "'-2+3" in written
    assert "'@SUM(A1)" in written
    assert "Example Org" in written


def test_markdown_report_escapes_table_and_html_injection(tmp_path):
    value = 'a|b\n<script>alert("x")</script>`'
    path = write_report(
        [Entity(type=EntityType.ORG, value=value, source="rdap")],
        str(tmp_path / "report.md"),
    )
    with open(path, encoding="utf-8") as handle:
        text = handle.read()

    assert "\\|" in text
    assert "&lt;script&gt;" in text
    assert "\n<script>" not in text
    assert "`a|b" not in text
    # The malicious value must stay on the single table row it belongs to.
    assert len([line for line in text.splitlines() if line.startswith("| org")]) == 1


def test_console_render_strips_terminal_escapes(monkeypatch):
    buffer = io.StringIO()
    monkeypatch.setattr(
        report_module,
        "console",
        Console(file=buffer, force_terminal=False, width=120),
    )
    render(
        [
            Entity(
                type=EntityType.ORG,
                value="safe\x1b[31mRED\x1b[0m\x07",
                source="rdap",
            )
        ]
    )
    output = buffer.getvalue()
    assert "\x1b" not in output
    assert "\x07" not in output
    assert "safe" in output and "RED" in output


@pytest.mark.parametrize(
    "kwargs",
    [
        {"theharvester_limit": 0},
        {"theharvester_limit": 5001},
        {"theharvester_timeout": 0},
        {"concurrency": 0},
        {"request_timeout": 0},
    ],
)
def test_settings_reject_unsafe_bounds(kwargs):
    with pytest.raises(ValidationError):
        Settings(**kwargs)


def test_theharvester_ignores_oversized_report(tmp_path, caplog):
    report = tmp_path / "report.json"
    with report.open("wb") as handle:
        handle.truncate(64 * 1024 * 1024 + 1)
    ctx = SimpleNamespace(log=logging.getLogger("test"))

    with caplog.at_level(logging.WARNING):
        assert TheHarvester._load_report(report, "", "", 0, ctx) == {}
    assert "oversized" in caplog.text


async def test_cache_files_are_private(tmp_path):
    pytest.importorskip("hishel")
    pytest.importorskip("anysqlite")

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"ok": True})

    cache_dir = tmp_path / "cache"
    settings = Settings(cache_dir=str(cache_dir))
    async with make_client(settings, transport=httpx.MockTransport(handler)) as client:
        await client.get("https://cache.test/x")

    assert cache_dir.stat().st_mode & 0o777 == 0o700
    assert (cache_dir / "http.db").stat().st_mode & 0o777 == 0o600


async def test_cache_refuses_symlinked_database(tmp_path):
    pytest.importorskip("hishel")
    pytest.importorskip("anysqlite")

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"ok": True})

    cache_dir = tmp_path / "cache"
    cache_dir.mkdir()
    victim = tmp_path / "victim.txt"
    victim.write_text("sentinel")
    os.symlink(victim, cache_dir / "http.db")

    settings = Settings(cache_dir=str(cache_dir))
    async with make_client(settings, transport=httpx.MockTransport(handler)) as client:
        response = await client.get("https://cache.test/x")

    assert response.json() == {"ok": True}
    assert victim.read_text() == "sentinel"


async def test_cache_refuses_symlinked_directory(tmp_path):
    pytest.importorskip("hishel")
    pytest.importorskip("anysqlite")

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"ok": True})

    real_dir = tmp_path / "real-cache"
    real_dir.mkdir()
    link = tmp_path / "cache"
    os.symlink(real_dir, link)

    settings = Settings(cache_dir=str(link))
    async with make_client(settings, transport=httpx.MockTransport(handler)) as client:
        response = await client.get("https://cache.test/x")

    assert response.json() == {"ok": True}
    assert not (real_dir / "http.db").exists()
