"""Turn entities into JSON / CSV / Markdown, plus a console summary."""

from __future__ import annotations

import csv
import json
from pathlib import Path

from rich.console import Console
from rich.table import Table

from .models import Entity

console = Console()


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
                        row["type"],
                        row["value"],
                        ";".join(row["sources"]),
                        ";".join(row["parents"]),
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
                f"| {row['type']} | `{row['value']}` | {', '.join(row['sources'])} | "
                f"{', '.join(row['parents']) or '-'} | {row['confidence']:.2f} |"
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
            row["type"], row["value"], ", ".join(row["sources"]), f"{row['confidence']:.2f}"
        )
    if len(rows) > limit:
        table.caption = f"… {len(rows) - limit} more rows not shown (see report file)"

    console.print(table)
