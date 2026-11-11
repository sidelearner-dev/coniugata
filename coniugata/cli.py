"""Command-line entry point."""

from __future__ import annotations

import asyncio
import logging
from importlib.metadata import PackageNotFoundError, version

import typer
from rich.console import Console
from rich.table import Table

from .config import Settings
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
    logging.basicConfig(
        level=logging.DEBUG if verbose else logging.INFO,
        format="[%(levelname)s] %(message)s",
    )
    # httpx logs full URLs, which can contain API keys in query strings.
    logging.getLogger("httpx").setLevel(logging.WARNING)
    settings = Settings()
    selected = _select(modules, profile, settings)
    seeds = build_seeds([target])

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
