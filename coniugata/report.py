"""Turn entities into JSON / CSV / Markdown, plus a console summary."""

from __future__ import annotations

import csv
import json
from pathlib import Path

from rich.console import Console
from rich.table import Table

from .models import Entity

console = Console()

# Spreadsheets execute cells beginning with these characters as formulas.
_CSV_FORMULA_PREFIXES = ("=", "+", "-", "@", "\t", "\r")


def _csv_cell(value: object) -> str:
    text = str(value)
    return "'" + text if text.startswith(_CSV_FORMULA_PREFIXES) else text


def _md_cell(value: object) -> str:
    """Collapse whitespace and escape Markdown/HTML table metacharacters."""
    text = " ".join(str(value).split())
    for old, new in (
        ("\\", "\\\\"),
        ("|", "\\|"),
        ("`", "'"),
        ("<", "&lt;"),
        (">", "&gt;"),
    ):
        text = text.replace(old, new)
    return text


def _display(value: object) -> str:
    """Strip control characters before printing untrusted data to a terminal."""
    chars: list[str] = []
    for char in str(value):
        if char in "\t\r\n":
            chars.append(" ")
        elif char.isprintable():
            chars.append(char)
        else:
            chars.append("\ufffd")
    return "".join(chars)


def _merge(entities: list[Entity]) -> list[dict]:
    """Collapse duplicate values while preserving every source/parent."""
    merged: dict[str, dict] = {}
    for entity in entities:
        row = merged.get(entity.key)
        if row is None:
            row = {
                "type": entity.type.value,
                "value": entity.value,
                "sources": set(),
                "parents": set(),
                "confidence": entity.confidence,
                "first_seen": entity.first_seen.isoformat(),
            }
            merged[entity.key] = row
        row["sources"].add(entity.source)
        if entity.parent:
            row["parents"].add(entity.parent)
        row["confidence"] = max(row["confidence"], entity.confidence)

    for row in merged.values():
        row["sources"] = sorted(row["sources"])
        row["parents"] = sorted(row["parents"])
    return sorted(merged.values(), key=lambda r: (r["type"], r["value"]))


def write_report(entities: list[Entity], path: str) -> str:
    rows = _merge(entities)
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    suffix = target.suffix.lower()

    if suffix == ".csv":
        with target.open("w", newline="", encoding="utf-8") as fh:
            writer = csv.writer(fh)
            writer.writerow(
                ["type", "value", "sources", "parents", "confidence", "first_seen"]
            )
            for row in rows:
                writer.writerow(
                    [
                        _csv_cell(row["type"]),
                        _csv_cell(row["value"]),
                        _csv_cell(";".join(row["sources"])),
                        _csv_cell(";".join(row["parents"])),
                        f"{row['confidence']:.2f}",
                        row["first_seen"],
                    ]
                )
    elif suffix in (".md", ".markdown"):
        lines = [
            "| Type | Value | Source(s) | Parent(s) | Confidence |",
            "|---|---|---|---|---|",
        ]
        for row in rows:
            lines.append(
                f"| {_md_cell(row['type'])} | `{_md_cell(row['value'])}` | "
                f"{_md_cell(', '.join(row['sources']))} | "
                f"{_md_cell(', '.join(row['parents'])) or '-'} | {row['confidence']:.2f} |"
            )
        target.write_text("\n".join(lines) + "\n", encoding="utf-8")
    else:
        target.write_text(json.dumps(rows, indent=2) + "\n", encoding="utf-8")

    return str(target)


def render(entities: list[Entity], limit: int = 100) -> None:
    rows = _merge(entities)
    table = Table(title=f"OSINT results ({len(rows)} unique entities)")
    table.add_column("Type", style="cyan", no_wrap=True)
    table.add_column("Value", style="bold")
    table.add_column("Source", style="green")
    table.add_column("Conf", justify="right")

    for row in rows[:limit]:
        table.add_row(
            _display(row["type"]),
            _display(row["value"]),
            _display(", ".join(row["sources"])),
            f"{row['confidence']:.2f}",
        )
    if len(rows) > limit:
        table.caption = f"… {len(rows) - limit} more rows not shown (see report file)"

    console.print(table)
