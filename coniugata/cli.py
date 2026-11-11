"""Command-line entry point."""

from __future__ import annotations

import asyncio
import logging

import typer
from rich.console import Console
from rich.table import Table

from .config import Settings
from .engine import Context, build_seeds, run_scan
from .http import make_client
from .registry import REGISTRY
from .report import render, write_report

app = typer.Typer(no_args_is_help=True, add_completion=False)
console = Console()

# Named bundles of modules. `None` means "everything in the registry".
PROFILES: dict[str, set[str] | None] = {
    "recon": {"crtsh", "rdap", "dns", "urlscan", "shodan", "theharvester"},
    "breach": {"hibp"},
    "all": None,
}


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


@app.command()
def scan(
    target: str = typer.Argument(..., help="Domain, IP, or email to investigate"),
    modules: str = typer.Option(
        "all", "--modules", "-m", help="Comma-separated module names, or 'all'"
    ),
    profile: str | None = typer.Option(
        None, "--profile", "-p", help="recon | breach | all"
    ),
    depth: int = typer.Option(2, "--depth", "-d", min=1, max=5, help="Expansion depth"),
    out: str = typer.Option(
        "results.json", "--out", "-o", help="Report path (.json/.csv/.md)"
    ),
    concurrency: int = typer.Option(
        10, "--concurrency", "-c", min=1, help="Max in-flight source tasks"
    ),
    cache: bool = typer.Option(
        True, "--cache/--no-cache", help="Cache HTTP responses on disk"
    ),
    verbose: bool = typer.Option(False, "--verbose", "-v"),
) -> None:
    """Run an OSINT scan against a target."""
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


@app.command("modules")
def list_modules() -> None:
    """List registered sources."""
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
            "yes" if cls.requires_key else "",
            cls.description,
        )
    console.print(table)


def main() -> None:
    app()


if __name__ == "__main__":
    main()
