"""Keep generated state (identity, database) out of the developer's home."""

from __future__ import annotations

import pytest


@pytest.fixture(autouse=True)
def isolated_state(tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "config"))
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "data"))
    for name in (
        "CONIUGATA_CONFIG_DIR",
        "CONIUGATA_DB_PATH",
        "CONIUGATA_INSTANCE_TOKEN",
        "CONIUGATA_USER_AGENT",
    ):
        monkeypatch.delenv(name, raising=False)
