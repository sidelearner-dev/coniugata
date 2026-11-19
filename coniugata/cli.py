"""Command-line entry point."""

from __future__ import annotations

import asyncio
import logging
import sqlite3
from datetime import UTC, datetime
from importlib.metadata import PackageNotFoundError, version

import typer
from rich.console import Console
from rich.table import Table
from rich.text import Text

from . import db
from .config import Settings, load_settings
from .engine import Context, build_seeds, run_scan
from .http import make_client
from .manual import render_manual, render_roff
from .registry import REGISTRY
from .report import render, write_report

APP_HELP = """A modular OSINT aggregation engine.

Scans a domain, IP address, or email and follows the graph of related entities: a domain yields subdomains and IPs, an email yields breaches. Every finding records its source and parent so results stay auditable.

Run [cyan]coniugata manual[/cyan] for the full manual, or [cyan]coniugata scan --help[/cyan] for scan options.

Only scan assets you own or have explicit written authorisation to test.
"""

# Libraries in this list log request lines, query strings and headers at DEBUG
# level. Shodan puts its key in the query string and HIBP/urlscan use headers,
# so enabling them in verbose mode would leak credentials to the terminal.
NOISY_LOGGERS = ("httpx", "httpcore", "hpack", "h2", "hishel")


def _configure_logging(verbose: bool) -> None:
    logging.basicConfig(
        level=logging.DEBUG if verbose else logging.INFO,
        format="[%(levelname)s] %(message)s",
    )
    for name in NOISY_LOGGERS:
        logging.getLogger(name).setLevel(logging.WARNING)

app = typer.Typer(
    no_args_is_help=True,
    add_completion=False,
    rich_markup_mode="rich",
    help=APP_HELP,
)
console = Console()

# Named bundles of modules. `None` means "everything in the registry".
PROFILES: dict[str, set[str] | None] = {
    "recon": {"crtsh", "rdap", "dns", "urlscan", "shodan", "theharvester"},
    "breach": {"hibp"},
    "all": None,
}

SCAN_EPILOG = """[bold]Examples[/bold]

[cyan]coniugata scan example.com -p recon -d 2 -o report.md[/cyan]
[cyan]coniugata scan example.com -m theharvester,hibp -d 3[/cyan]

[bold]More[/bold]

Run [cyan]coniugata manual scan[/cyan] for every option, profile and expansion rule.
"""


def _load_modules() -> dict[str, type]:
    import coniugata.modules  # noqa: F401  (importing registers every source)

    return REGISTRY


def _select(spec: str, profile: str | None, settings: Settings) -> list:
    registry = _load_modules()

    if profile:
        if profile not in PROFILES:
            raise typer.BadParameter(
                f"unknown profile '{profile}' (choose: {', '.join(PROFILES)})"
            )
        names = PROFILES[profile]
    elif spec == "all":
        names = set(registry)
    else:
        names = {name.strip() for name in spec.split(",") if name.strip()}

    missing = (names or set()) - set(registry)
    if missing:
        raise typer.BadParameter(f"unknown module(s): {', '.join(sorted(missing))}")

    selected = []
    for name in sorted(names or set()):
        cls = registry[name]
        if cls.requires_key and cls.key_attr and not getattr(settings, cls.key_attr, None):
            console.print(f"[yellow]skip[/yellow] {name}: set CONIUGATA_{cls.key_attr.upper()}")
            continue
        selected.append(cls())
    return selected


def _show_version(value: bool) -> None:
    if not value:
        return
    try:
        console.print(f"coniugata {version('coniugata')}")
    except PackageNotFoundError:  # running from a source tree without install metadata
        console.print("coniugata (development)")
    raise typer.Exit()


@app.callback()
def _root(
    version: bool = typer.Option(
        False,
        "--version",
        "-V",
        callback=_show_version,
        is_eager=True,
        help="Show the version and exit.",
    ),
) -> None:
    """Configure coniugata."""


@app.command(epilog=SCAN_EPILOG)
def scan(
    target: str = typer.Argument(
        ...,
        help="Domain, IP address, or email to investigate.",
    ),
    modules: str = typer.Option(
        "all",
        "--modules",
        "-m",
        help="Comma-separated source names, or 'all'. Ignored with --profile.",
    ),
    profile: str | None = typer.Option(
        None,
        "--profile",
        "-p",
        help="Bundle: recon, breach, or all. Overrides --modules.",
    ),
    depth: int = typer.Option(
        2,
        "--depth",
        "-d",
        min=1,
        max=5,
        help="Expansion rounds, 1-5 (default 2). Higher means more API calls.",
    ),
    out: str = typer.Option(
        "results.json",
        "--out",
        "-o",
        help="Report path: .json, .csv, or .md (default results.json).",
    ),
    concurrency: int = typer.Option(
        10,
        "--concurrency",
        "-c",
        min=1,
        help="Maximum source tasks in flight at once (default 10).",
    ),
    cache: bool = typer.Option(
        True,
        "--cache/--no-cache",
        help="Cache HTTP responses on disk. Use --no-cache for fresh data.",
    ),
    record: bool = typer.Option(
        True,
        "--db/--no-db",
        help="Record this scan in the local history database (default: record).",
    ),
    db_path: str | None = typer.Option(
        None,
        "--db-path",
        help="Override the local history database path.",
    ),
    verbose: bool = typer.Option(
        False,
        "--verbose",
        "-v",
        help="Debug logging, including per-depth progress.",
    ),
) -> None:
    """Run an OSINT scan against a domain, IP address, or email.

    Sources that accept the target run first; the entities they return feed up to --depth rounds of expansion. Keyed sources are skipped when their key is missing.

    Run 'coniugata manual scan' for the full reference.
    """
    _configure_logging(verbose)
    settings = load_settings()
    selected = _select(modules, profile, settings)
    seeds = build_seeds([target])
    started_at = datetime.now(UTC)

    if not selected:
        console.print("[red]No runnable modules selected.[/red]")
        raise typer.Exit(code=1)

    console.print(
        f"[bold]Scanning[/bold] {target} with {', '.join(m.name for m in selected)}"
    )

    async def _run() -> list:
        async with make_client(settings, use_cache=cache) as client:
            ctx = Context(
                http=client,
                settings=settings,
                log=logging.getLogger("coniugata"),
                concurrency=concurrency,
            )
            return await run_scan(seeds, selected, ctx, max_depth=depth)

    results = asyncio.run(_run())
    path = write_report(results, out)
    render(results)
    console.print(f"[green]Report written to[/green] {path}")

    if record:
        try:
            scan_id = db.save_scan(
                results,
                target=target,
                target_type=seeds[0].type.value,
                modules=[module.name for module in selected],
                depth=depth,
                profile=profile,
                started_at=started_at,
                path=db_path or settings.db_path,
            )
        except (OSError, sqlite3.Error) as exc:
            console.print(f"[yellow]warning[/yellow] scan not recorded: {exc}")
        else:
            console.print(f"[green]Scan recorded as[/green] #{scan_id}")


HISTORY_EPILOG = """[bold]Examples[/bold]

[cyan]coniugata history[/cyan]
List the 20 most recent scans.

[cyan]coniugata history -n 100[/cyan]
List up to 100 scans.

[cyan]coniugata show 3[/cyan]
Show the findings recorded for scan #3.
"""


def _open_history_error(exc: Exception) -> None:
    console.print(f"[red]Cannot read history database:[/red] {exc}")


def _history_db_path(override: str | None) -> str | None:
    """Resolve --db-path, then CONIUGATA_DB_PATH from the environment/.env."""
    return override or load_settings().db_path


@app.command("history", epilog=HISTORY_EPILOG)
def show_history(
    limit: int = typer.Option(
        20,
        "--limit",
        "-n",
        min=1,
        max=500,
        help="Maximum number of scans to list (default 20).",
    ),
    db_path: str | None = typer.Option(
        None,
        "--db-path",
        help="Override the local history database path.",
    ),
) -> None:
    """List scans recorded in the local history database."""
    try:
        rows = db.list_scans(limit=limit, path=_history_db_path(db_path))
    except (OSError, sqlite3.Error) as exc:
        _open_history_error(exc)
        raise typer.Exit(code=1) from exc

    if not rows:
        console.print("[dim]No scans recorded yet.[/dim]")
        return

    table = Table(title="Scan history")
    table.add_column("ID", style="cyan", justify="right", no_wrap=True)
    table.add_column("Target", style="bold")
    table.add_column("Type", no_wrap=True)
    table.add_column("Modules")
    table.add_column("Depth", justify="right")
    table.add_column("Findings", justify="right")
    table.add_column("Finished (UTC)")
    for row in rows:
        table.add_row(
            str(row["id"]),
            Text(row["target"]),
            Text(row["target_type"]),
            Text(row["modules"]),
            str(row["depth"]),
            str(row["result_count"]),
            Text(row["finished_at"]),
        )
    console.print(table)


@app.command("show")
def show_scan(
    scan_id: int = typer.Argument(..., help="Scan id shown by 'coniugata history'."),
    db_path: str | None = typer.Option(
        None,
        "--db-path",
        help="Override the local history database path.",
    ),
) -> None:
    """Show the findings recorded for one scan."""
    try:
        found = db.get_scan(scan_id, path=_history_db_path(db_path))
    except (OSError, sqlite3.Error) as exc:
        _open_history_error(exc)
        raise typer.Exit(code=1) from exc

    if found is None:
        console.print(f"[red]No scan with id[/red] {scan_id}")
        raise typer.Exit(code=1)

    scan, entities = found
    console.print(
        Text.assemble(
            ("Scan #", "bold"),
            (str(scan["id"]), "bold"),
            " ",
            (scan["target"], "bold"),
            f" ({scan['target_type']})",
        )
    )
    console.print(
        Text(
            f"{scan['modules']} · depth {scan['depth']} · "
            f"{scan['result_count']} findings · {scan['finished_at']}",
            style="dim",
        )
    )

    table = Table(title=f"Findings for scan #{scan['id']}")
    table.add_column("Type", style="cyan", no_wrap=True)
    table.add_column("Value", style="bold")
    table.add_column("Source", style="green")
    table.add_column("Parent")
    table.add_column("Conf", justify="right")
    for entity in entities:
        table.add_row(
            Text(entity["type"]),
            Text(entity["value"]),
            Text(entity["source"]),
            Text(entity["parent"] or "-"),
            f"{entity['confidence']:.2f}",
        )
    console.print(table)


MODULES_EPILOG = """[bold]More[/bold]

Run [cyan]coniugata manual sources[/cyan] for the same information in the manual.
"""


@app.command("modules", epilog=MODULES_EPILOG)
def list_modules() -> None:
    """List registered sources and what they accept and produce.

    Name is the value to pass to --modules. Key? marks sources that need a
    CONIUGATA_* API key; they are skipped when that key is not configured.
    """
    registry = _load_modules()
    table = Table(title="Available modules")
    table.add_column("Name", style="cyan", no_wrap=True)
    table.add_column("Accepts")
    table.add_column("Produces")
    table.add_column("Key?", justify="center")
    table.add_column("Description")
    for name in sorted(registry):
        cls = registry[name]
        table.add_row(
            name,
            ", ".join(sorted(t.value for t in cls.accepts)),
            ", ".join(sorted(t.value for t in cls.produces)),
            "yes" if cls.requires_key else ("optional" if cls.key_attr else ""),
            cls.description,
        )
    console.print(table)


MANUAL_EPILOG = """[bold]Examples[/bold]

[cyan]coniugata manual[/cyan]
Show the complete manual.

[cyan]coniugata manual scan[/cyan]
Show only sections whose title contains "scan".

[cyan]coniugata manual --roff > man/coniugata.1[/cyan]
Emit a roff man page for `man coniugata`.
"""


@app.command("manual", epilog=MANUAL_EPILOG)
def show_manual(
    section: str | None = typer.Argument(
        None,
        help="Only show sections whose title contains this text (for example 'scan').",
    ),
    roff: bool = typer.Option(
        False,
        "--roff",
        help="Emit a roff man page instead of formatted text.",
    ),
) -> None:
    """Show the full manual, or one section of it."""
    _load_modules()  # populate the registry used by the SOURCES section
    if roff:
        typer.echo(render_roff(), nl=False)
        return
    if not render_manual(console, section):
        console.print(f"[red]No manual section matches[/red] {section!r}")
        raise typer.Exit(code=1)


# Hidden alias: `coniugata man` behaves like `coniugata manual`.
app.command("man", hidden=True)(show_manual)


def main() -> None:
    app()


if __name__ == "__main__":
    main()
