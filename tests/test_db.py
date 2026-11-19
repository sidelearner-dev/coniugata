"""Local scan-history database: persistence, ordering, permissions, safety."""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest
from typer.testing import CliRunner

import coniugata.cli as cli_module
from coniugata.cli import app
from coniugata.db import default_db_path, get_scan, list_scans, save_scan
from coniugata.models import Entity, EntityType


def _entities() -> list[Entity]:
    return [
        Entity(type=EntityType.DOMAIN, value="example.com", source="seed", confidence=1.0),
        Entity(
            type=EntityType.IP,
            value="203.0.113.7",
            source="dns",
            parent="example.com",
            confidence=0.8,
            raw={"a": 1},
        ),
    ]


def test_default_path_uses_xdg_data(monkeypatch):
    monkeypatch.delenv("CONIUGATA_DB_PATH", raising=False)
    monkeypatch.setenv("XDG_DATA_HOME", "/tmp/example-data")
    assert default_db_path() == Path("/tmp/example-data/coniugata/coniugata.db")

    monkeypatch.setenv("CONIUGATA_DB_PATH", "/tmp/custom.db")
    assert default_db_path() == Path("/tmp/custom.db")


def test_save_and_read_scan(tmp_path):
    path = tmp_path / "history" / "coniugata.db"
    scan_id = save_scan(
        _entities(),
        target="example.com",
        target_type="domain",
        modules=["dns", "crtsh"],
        depth=2,
        profile="recon",
        path=path,
    )

    assert scan_id == 1
    found = get_scan(scan_id, path=path)
    assert found is not None
    scan, entities = found
    assert scan["target"] == "example.com"
    assert scan["result_count"] == 2
    assert scan["modules"] == "dns,crtsh"
    assert scan["profile"] == "recon"
    assert [row["value"] for row in entities] == ["example.com", "203.0.113.7"]
    assert json.loads(entities[1]["raw"]) == {"a": 1}

    rows = list_scans(path=path)
    assert [row["id"] for row in rows] == [1]


def test_list_is_newest_first_and_limited(tmp_path):
    path = tmp_path / "history.db"
    for target in ("one.example", "two.example", "three.example"):
        save_scan(
            [],
            target=target,
            target_type="domain",
            modules=["dns"],
            depth=1,
            path=path,
        )

    assert [row["target"] for row in list_scans(limit=2, path=path)] == [
        "three.example",
        "two.example",
    ]


def test_unknown_scan_returns_none(tmp_path):
    assert get_scan(999, path=tmp_path / "history.db") is None


def test_database_permissions(tmp_path):
    path = tmp_path / "state" / "coniugata.db"
    save_scan(
        [], target="example.com", target_type="domain", modules=[], depth=1, path=path
    )

    assert path.parent.stat().st_mode & 0o777 == 0o700
    assert path.stat().st_mode & 0o777 == 0o600


def test_database_does_not_chmod_existing_directory(tmp_path):
    existing = tmp_path / "project"
    existing.mkdir()
    existing.chmod(0o755)

    save_scan(
        [],
        target="example.com",
        target_type="domain",
        modules=[],
        depth=1,
        path=existing / "history.db",
    )

    assert existing.stat().st_mode & 0o777 == 0o755
    assert (existing / "history.db").stat().st_mode & 0o777 == 0o600


def test_database_refuses_symlinked_file(tmp_path):
    victim = tmp_path / "victim.db"
    victim.write_text("sentinel", encoding="utf-8")
    link = tmp_path / "coniugata.db"
    os.symlink(victim, link)

    with pytest.raises(OSError, match="symlinked"):
        save_scan(
            [],
            target="example.com",
            target_type="domain",
            modules=[],
            depth=1,
            path=link,
        )

    assert victim.read_text(encoding="utf-8") == "sentinel"


def test_cli_history_and_show(tmp_path):
    path = tmp_path / "history.db"
    save_scan(
        _entities(),
        target="history-target",
        target_type="domain",
        modules=["dns"],
        depth=1,
        path=path,
    )

    runner = CliRunner()
    history = runner.invoke(app, ["history", "--db-path", str(path)])
    assert history.exit_code == 0, history.output
    assert "history-target" in history.output

    shown = runner.invoke(app, ["show", "1", "--db-path", str(path)])
    assert shown.exit_code == 0, shown.output
    assert "203.0.113.7" in shown.output

    missing = runner.invoke(app, ["show", "999", "--db-path", str(path)])
    assert missing.exit_code == 1


def test_cli_history_uses_env_db_path(tmp_path, monkeypatch):
    path = tmp_path / "history.db"
    save_scan(
        _entities(),
        target="env-db-target",
        target_type="domain",
        modules=["dns"],
        depth=1,
        path=path,
    )
    monkeypatch.setenv("CONIUGATA_DB_PATH", str(path))

    result = CliRunner().invoke(app, ["history"])

    assert result.exit_code == 0, result.output
    assert "env-db-target" in result.output


def test_cli_scan_records_history(tmp_path, monkeypatch):
    async def fake_scan(seeds, modules, ctx, max_depth):
        return _entities()

    class FakeClient:
        async def __aenter__(self):
            return object()

        async def __aexit__(self, *exc):
            return False

    monkeypatch.setattr(cli_module, "run_scan", fake_scan)
    monkeypatch.setattr(cli_module, "make_client", lambda *a, **k: FakeClient())
    monkeypatch.setattr(cli_module, "write_report", lambda results, out: out)
    monkeypatch.setattr(cli_module, "render", lambda results: None)

    path = tmp_path / "history.db"
    runner = CliRunner()
    result = runner.invoke(
        app, ["scan", "example.com", "-m", "dns", "--db-path", str(path)]
    )

    assert result.exit_code == 0, result.output
    assert "Scan recorded as #1" in result.output
    assert [row["target"] for row in list_scans(path=path)] == ["example.com"]
    assert get_scan(1, path=path)[1][1]["value"] == "203.0.113.7"


def test_cli_scan_no_db_creates_nothing(tmp_path, monkeypatch):
    async def fake_scan(seeds, modules, ctx, max_depth):
        return []

    class FakeClient:
        async def __aenter__(self):
            return object()

        async def __aexit__(self, *exc):
            return False

    monkeypatch.setattr(cli_module, "run_scan", fake_scan)
    monkeypatch.setattr(cli_module, "make_client", lambda *a, **k: FakeClient())
    monkeypatch.setattr(cli_module, "write_report", lambda results, out: out)
    monkeypatch.setattr(cli_module, "render", lambda results: None)

    path = tmp_path / "history.db"
    runner = CliRunner()
    result = runner.invoke(
        app,
        ["scan", "example.com", "-m", "dns", "--no-db", "--db-path", str(path)],
    )

    assert result.exit_code == 0, result.output
    assert not path.exists()
