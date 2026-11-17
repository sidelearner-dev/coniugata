"""Per-install anonymous identity: generation, permissions, and User-Agent."""

from __future__ import annotations

import json
import os
from pathlib import Path

import httpx
import pytest
from pydantic import ValidationError

from coniugata.config import Settings
from coniugata.http import make_client
from coniugata.identity import (
    base_user_agent,
    fingerprint,
    instance_path,
    load_or_create_token,
    request_user_agent,
)


def test_token_is_generated_once_and_private(tmp_path):
    path = tmp_path / "state" / "instance.json"
    token = load_or_create_token(path)

    assert len(token) == 32
    assert load_or_create_token(path) == token
    assert path.stat().st_mode & 0o777 == 0o600
    assert path.parent.stat().st_mode & 0o777 == 0o700
    assert json.loads(path.read_text(encoding="utf-8"))["token"] == token


def test_default_path_lives_under_xdg_config(monkeypatch):
    monkeypatch.setenv("XDG_CONFIG_HOME", "/tmp/example-config")
    assert instance_path() == Path("/tmp/example-config/coniugata/instance.json")


def test_different_installs_get_different_tokens(tmp_path):
    first = load_or_create_token(tmp_path / "a" / "instance.json")
    second = load_or_create_token(tmp_path / "b" / "instance.json")
    assert first != second


def test_fingerprint_is_short_derived_and_repeatable():
    token = "ab" * 16
    value = fingerprint(token)
    assert len(value) == 12
    assert value != token
    assert token not in value
    assert fingerprint(token) == value


def test_user_agent_carries_only_the_fingerprint():
    token = "cd" * 16
    user_agent = request_user_agent(token)
    assert fingerprint(token) in user_agent
    assert token not in user_agent
    assert "you@example.com" not in user_agent
    assert "@" not in user_agent


def test_symlinked_identity_file_is_not_followed(tmp_path):
    victim = tmp_path / "victim.json"
    victim.write_text(json.dumps({"token": "deadbeef" * 4}), encoding="utf-8")
    link = tmp_path / "instance.json"
    os.symlink(victim, link)

    token = load_or_create_token(link)

    assert token != "deadbeef" * 4
    assert victim.read_text(encoding="utf-8") == json.dumps({"token": "deadbeef" * 4})


def test_symlinked_identity_directory_is_not_written(tmp_path):
    real = tmp_path / "real"
    real.mkdir()
    link = tmp_path / "config"
    os.symlink(real, link)

    token = load_or_create_token(link / "instance.json")

    assert len(token) == 32
    assert not (real / "instance.json").exists()


async def test_client_sends_anonymous_user_agent():
    seen: dict[str, str] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["user-agent"] = request.headers["user-agent"]
        return httpx.Response(200, json={"ok": True})

    token = "ef" * 16
    settings = Settings(instance_token=token)
    async with make_client(
        settings, use_cache=False, transport=httpx.MockTransport(handler)
    ) as client:
        await client.get("https://example.test/")

    assert fingerprint(token) in seen["user-agent"]
    assert token not in seen["user-agent"]
    assert "you@example.com" not in seen["user-agent"]


async def test_explicit_user_agent_override_wins():
    seen: dict[str, str] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["user-agent"] = request.headers["user-agent"]
        return httpx.Response(200, json={"ok": True})

    settings = Settings(instance_token="ef" * 16, user_agent="custom-agent/1")
    async with make_client(
        settings, use_cache=False, transport=httpx.MockTransport(handler)
    ) as client:
        await client.get("https://example.test/")

    assert seen["user-agent"] == "custom-agent/1"


async def _client_user_agent(settings: Settings) -> str:
    seen: dict[str, str] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["user-agent"] = request.headers["user-agent"]
        return httpx.Response(200, json={"ok": True})

    async with make_client(
        settings, use_cache=False, transport=httpx.MockTransport(handler)
    ) as client:
        await client.get("https://example.test/")
    return seen["user-agent"]


async def test_identity_mode_none_sends_no_fingerprint():
    user_agent = await _client_user_agent(Settings(identity_mode="none"))

    assert user_agent == base_user_agent()
    assert "instance:" not in user_agent


async def test_identity_mode_run_is_ephemeral_and_not_persisted(tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "config"))

    first = await _client_user_agent(Settings(identity_mode="run"))
    second = await _client_user_agent(Settings(identity_mode="run"))

    assert first != second
    assert "instance:" in first
    assert not instance_path().exists()


async def test_identity_mode_install_is_stable(tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "config"))

    first = await _client_user_agent(Settings(identity_mode="install"))
    second = await _client_user_agent(Settings(identity_mode="install"))

    assert first == second
    assert instance_path().exists()
    assert instance_path().stat().st_mode & 0o777 == 0o600


def test_identity_mode_rejects_unknown_values():
    with pytest.raises(ValidationError, match="identity_mode"):
        Settings(identity_mode="sometimes")
