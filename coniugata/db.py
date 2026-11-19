"""Local scan history, kept in SQLite next to the user's other data.

The database is separate from the HTTP cache: the cache holds provider
responses (and sometimes API keys in URLs), while this store holds only the
scans you ran and the entities they produced. It lives under the XDG data
directory with mode ``0600`` and can be disabled per scan with ``--no-db``.
"""

from __future__ import annotations

import json
import os
import sqlite3
from datetime import UTC, datetime
from pathlib import Path

from .models import Entity

SCHEMA = """
CREATE TABLE IF NOT EXISTS scans (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    target        TEXT    NOT NULL,
    target_type   TEXT    NOT NULL,
    profile       TEXT,
    modules       TEXT    NOT NULL,
    depth         INTEGER NOT NULL,
    status        TEXT    NOT NULL,
    started_at    TEXT    NOT NULL,
    finished_at   TEXT    NOT NULL,
    result_count  INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS entities (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id     INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    type        TEXT    NOT NULL,
    value       TEXT    NOT NULL,
    source      TEXT    NOT NULL,
    parent      TEXT,
    confidence  REAL    NOT NULL,
    first_seen  TEXT    NOT NULL,
    raw         TEXT    NOT NULL DEFAULT '{}'
);
CREATE INDEX IF NOT EXISTS idx_entities_scan  ON entities(scan_id);
CREATE INDEX IF NOT EXISTS idx_entities_value ON entities(type, value);
CREATE INDEX IF NOT EXISTS idx_scans_target   ON scans(target);
"""


def data_home() -> Path:
    """Return the XDG data directory, or the conventional fallback."""
    base = os.environ.get("XDG_DATA_HOME")
    return Path(base).expanduser() if base else Path.home() / ".local" / "share"


def default_db_path() -> Path:
    override = os.environ.get("CONIUGATA_DB_PATH")
    if override:
        return Path(override).expanduser()
    return data_home() / "coniugata" / "coniugata.db"


def _prepare(path: Path) -> None:
    """Create the database with private permissions, refusing symlinks."""
    parent = path.parent
    if parent.is_symlink():
        raise OSError(f"refusing symlinked database directory: {parent}")
    # Only tighten permissions on a directory this code created. The path can
    # be user-supplied (--db-path), and chmod-ing an existing directory could
    # remove access the user relies on.
    created = not parent.exists()
    parent.mkdir(parents=True, exist_ok=True)
    if created:
        parent.chmod(0o700)

    flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags, 0o600)
    except OSError as exc:
        if path.is_symlink():
            raise OSError(f"refusing symlinked database: {path}") from exc
        raise
    os.close(descriptor)
    path.chmod(0o600)


def connect(path: str | Path | None = None) -> sqlite3.Connection:
    """Open (and initialise) the history database."""
    target = Path(path).expanduser() if path else default_db_path()
    _prepare(target)
    connection = sqlite3.connect(target, timeout=5.0)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    connection.execute("PRAGMA busy_timeout = 5000")
    connection.executescript(SCHEMA)
    return connection


def save_scan(
    entities: list[Entity],
    *,
    target: str,
    target_type: str,
    modules: list[str],
    depth: int,
    profile: str | None = None,
    started_at: datetime | None = None,
    status: str = "complete",
    path: str | Path | None = None,
) -> int:
    """Persist one scan and its findings. Returns the new scan id."""
    finished = datetime.now(UTC)
    started = started_at or finished
    connection = connect(path)
    try:
        with connection:
            cursor = connection.execute(
                """
                INSERT INTO scans
                    (target, target_type, profile, modules, depth, status,
                     started_at, finished_at, result_count)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    target,
                    target_type,
                    profile,
                    ",".join(modules),
                    depth,
                    status,
                    started.isoformat(),
                    finished.isoformat(),
                    len(entities),
                ),
            )
            scan_id = int(cursor.lastrowid)
            connection.executemany(
                """
                INSERT INTO entities
                    (scan_id, type, value, source, parent, confidence, first_seen, raw)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                [
                    (
                        scan_id,
                        entity.type.value,
                        entity.value,
                        entity.source,
                        entity.parent,
                        entity.confidence,
                        entity.first_seen.isoformat(),
                        json.dumps(entity.raw, ensure_ascii=False, default=str),
                    )
                    for entity in entities
                ],
            )
        return scan_id
    finally:
        connection.close()


def list_scans(
    *,
    limit: int = 20,
    path: str | Path | None = None,
) -> list[sqlite3.Row]:
    """Return the most recent scans, newest first."""
    connection = connect(path)
    try:
        return connection.execute(
            """
            SELECT id, target, target_type, profile, modules, depth,
                   status, started_at, finished_at, result_count
            FROM scans
            ORDER BY id DESC
            LIMIT ?
            """,
            (max(1, limit),),
        ).fetchall()
    finally:
        connection.close()


def get_scan(
    scan_id: int,
    *,
    path: str | Path | None = None,
) -> tuple[sqlite3.Row, list[sqlite3.Row]] | None:
    """Return ``(scan, entities)`` for one scan, or ``None`` if it is unknown."""
    connection = connect(path)
    try:
        scan = connection.execute("SELECT * FROM scans WHERE id = ?", (scan_id,)).fetchone()
        if scan is None:
            return None
        entities = connection.execute(
            """
            SELECT type, value, source, parent, confidence, first_seen, raw
            FROM entities
            WHERE scan_id = ?
            ORDER BY type, value, source
            """,
            (scan_id,),
        ).fetchall()
        return scan, entities
    finally:
        connection.close()
