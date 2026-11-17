"""Long-form manual shared by `coniugata manual` and the roff man page."""

from __future__ import annotations

import datetime as dt
from importlib.metadata import PackageNotFoundError, version

from rich.console import Console
from rich.text import Text

from .registry import REGISTRY


def _version() -> str:
    try:
        return version("coniugata")
    except PackageNotFoundError:  # running from a source tree without install metadata
        return "development"


def _sources() -> list[str]:
    """Build one paragraph per registered source."""
    blocks: list[str] = []
    for name in sorted(REGISTRY):
        cls = REGISTRY[name]
        accepts = ", ".join(sorted(t.value for t in cls.accepts)) or "none"
        produces = ", ".join(sorted(t.value for t in cls.produces)) or "none"
        if cls.requires_key:
            key = "required"
        elif cls.key_attr:
            key = "optional"
        else:
            key = "not needed"
        blocks.append(
            f"{name}: accepts {accepts}; produces {produces}; API key {key}.\n"
            f"{cls.description}"
        )
    return blocks


def sections() -> list[tuple[str, list[str]]]:
    """Return the manual as (heading, paragraphs) pairs.

    A paragraph containing a newline is rendered verbatim (as a code block);
    every other paragraph is reflowed to the terminal width.
    """
    return [
        ("NAME", ["coniugata - modular OSINT aggregation engine"]),
        (
            "SYNOPSIS",
            [
                ("coniugata [--version] [--help] COMMAND [ARGS]...\n"
                "\n"
                "coniugata scan TARGET [OPTIONS]\n"
                "\n"
                "coniugata modules\n"
                "\n"
                "coniugata history [--limit N]\n"
                "\n"
                "coniugata show ID\n"
                "\n"
                "coniugata manual [SECTION] [--roff]")
            ],
        ),
        (
            "DESCRIPTION",
            [
                ("coniugata collects open-source intelligence about a domain, IP address, or "
                "email address. Sources are plugins: each accepts one or more entity types "
                "and yields new typed entities, which the engine feeds back in for further "
                "rounds of expansion. Every finding records its source and the entity it was "
                "derived from, so a report can be audited."),
                ("The target type is detected automatically. URLs are reduced to their "
                "hostname, email addresses are lower-cased, and domains have a trailing dot "
                "and a leading '*.' removed."),
                ("Sources that need an API key are skipped, with a notice, when the key is "
                "not configured. urlscan also works anonymously; a key only raises its rate "
                "limit."),
            ],
        ),
        (
            "COMMANDS",
            [
                "scan TARGET - run a scan against a domain, IP address, or email.",
                "modules - list registered sources and what they accept and produce.",
                "history - list scans recorded in the local history database.",
                "show ID - show the findings recorded for one scan.",
                "manual [SECTION] - show this manual. Add --roff to emit a roff man page.",
                "Run 'coniugata COMMAND --help' for a summary of a command's options.",
            ],
        ),
        (
            "SCAN OPTIONS",
            [
                "TARGET - domain, IP address, or email to investigate. Required.",
                ("-m, --modules LIST - comma-separated source names (see SOURCES), or 'all' "
                "(the default). Ignored when --profile is set."),
                ("-p, --profile NAME - curated bundle: recon, breach, or all. Overrides "
                "--modules."),
                ("-d, --depth N - rounds of graph expansion, from 1 to 5 (default 2). Depth 1 "
                "scans only the target."),
                ("-o, --out PATH - report path. The format is inferred from the extension: "
                ".json (default results.json), .csv, or .md. Existing files are overwritten."),
                "-c, --concurrency N - maximum source tasks in flight at once (default 10).",
                "--cache / --no-cache - cache HTTP responses on disk (default: cache).",
                ("--db / --no-db - record the scan and its findings in the local history "
                "database (default: record)."),
                "--db-path PATH - override the local history database path for this run.",
                "-v, --verbose - debug logging, including per-depth progress.",
                "-V, --version - print the version and exit.",
                "--help - show summary help and exit.",
            ],
        ),
        (
            "PROFILES",
            [
                ("recon - crtsh, rdap, dns, urlscan, shodan and theharvester. Keyed sources "
                "in the bundle are skipped when their keys are missing."),
                ("breach - hibp only; it consumes email entities discovered earlier in the "
                "scan."),
                ("all - every registered source. This is also the default when neither "
                "--profile nor --modules is given."),
            ],
        ),
        (
            "EXPANSION",
            [
                ("Runs are breadth-first. Round 1 runs every selected source that accepts the "
                "target type. Entities returned by a source become the frontier for round 2, "
                "and so on up to --depth."),
                ("Duplicate entities are reported once, with all sources and parents merged, "
                "but only newly seen entities are expanded. This keeps a scan from looping "
                "while preserving multi-source provenance."),
                ("Depth 2 or higher can multiply API calls quickly. Start at depth 1 or 2 on "
                "an unfamiliar target."),
            ],
        ),
        ("SOURCES", _sources()),
        (
            "CONFIGURATION",
            [
                ("Settings are read from a .env file in the current working directory, then "
                "from the environment. Every setting uses the CONIUGATA_ prefix. See "
                ".env.example for the complete list. A .env that is a symlink, not owned by "
                "you, or writable by group/others is ignored so an untrusted repository "
                "cannot redirect theHarvester or the database. A .env readable by "
                "group/others is loaded with a warning, since it exposes API keys; run "
                "chmod 600 .env to fix it. Override the path with CONIUGATA_ENV_FILE."),
                "CONIUGATA_SHODAN_KEY - Shodan API key. Required by shodan.",
                "CONIUGATA_HIBP_KEY - HaveIBeenPwned API key. Required by hibp.",
                ("CONIUGATA_URLSCAN_KEY - optional urlscan.io key; raises the anonymous rate "
                "limit."),
                "CONIUGATA_VT_KEY - reserved for a VirusTotal source; currently unused.",
                "CONIUGATA_REQUEST_TIMEOUT - HTTP timeout in seconds (default 20).",
                "CONIUGATA_CACHE_DIR - cache directory (default .cache/coniugata).",
                "CONIUGATA_CACHE_TTL - cache lifetime in seconds (default 3600).",
                "CONIUGATA_USER_AGENT - override the default User-Agent.",
                ("CONIUGATA_IDENTITY_MODE - install (persist one token), run (fresh "
                "token each run) or none (no fingerprint). Default: install."),
                ("CONIUGATA_INSTANCE_TOKEN - override the anonymous per-install token. "
                "Normally generated on first run and stored under the config directory."),
                ("CONIUGATA_MAX_RESPONSE_BYTES - refuse HTTP bodies larger than this many "
                "decompressed bytes (default 16777216)."),
                ("CONIUGATA_MAX_ENTITIES - stop expanding after this many findings per scan; "
                "0 disables the cap (default 50000)."),
                ("CONIUGATA_DB_PATH - local history database path (default "
                "~/.local/share/coniugata/coniugata.db)."),
                "CONIUGATA_THEHARVESTER_BIN - theHarvester executable (default theHarvester).",
                ("CONIUGATA_THEHARVESTER_SOURCES - comma-separated theHarvester sources "
                "(default crtsh,otx,hackertarget,rapiddns)."),
                "CONIUGATA_THEHARVESTER_LIMIT - result limit (default 500).",
                "CONIUGATA_THEHARVESTER_TIMEOUT - subprocess timeout in seconds (default 180).",
                ("Scan concurrency is controlled by --concurrency, not by an environment "
                "variable."),
            ],
        ),
        (
            "IDENTITY AND PRIVACY",
            [
                ("coniugata ships no author contact details, API keys or shared identifiers. "
                "By default it generates a random 128-bit token in "
                "~/.config/coniugata/instance.json (mode 0600) and puts only a truncated "
                "SHA-256 fingerprint of that token in the User-Agent. Two installs therefore "
                "look different to providers, while neither the token nor the author can be "
                "recovered from the header."),
                ("CONIUGATA_IDENTITY_MODE selects the behaviour: install keeps one token per "
                "install, run generates a fresh token for every run and writes nothing, and "
                "none sends no fingerprint at all. An explicit CONIUGATA_INSTANCE_TOKEN "
                "overrides all three."),
                ("Set CONIUGATA_USER_AGENT to send a different header, or "
                "CONIUGATA_INSTANCE_TOKEN to reuse a token across machines. Neither the token "
                "nor the fingerprint is a secret, but keep the identity file private: anyone "
                "who can read it can impersonate your install."),
                ("No telemetry is sent anywhere. Scans are stored only in the local history "
                "database, and the HTTP cache stays in the cache directory you configure."),
            ],
        ),
        (
            "FILES",
            [
                ".env - local configuration and API keys. Never commit it.",
                "results.json - default report path, or whatever is passed to --out.",
                ("Report files are created with mode 0600 and symlinked report paths are "
                "refused, because they can contain personal data."),
                (".cache/coniugata/http.db - HTTP response cache, created with mode 0600. "
                "Some providers (notably Shodan) put API keys in query strings, so cached "
                "URLs can contain secrets. Treat the cache as sensitive."),
                ("~/.config/coniugata/instance.json - anonymous per-install token, created "
                "with mode 0600 on first use. Only a truncated hash is sent in the "
                "User-Agent."),
                ("~/.local/share/coniugata/coniugata.db - local scan history, created with "
                "mode 0600. Disable per run with --no-db."),
            ],
        ),
        (
            "EXAMPLES",
            [
                ("# Default scan: all sources, depth 2, JSON report\n"
                "coniugata scan example.com\n"
                "\n"
                "# Recon bundle with three expansion rounds, Markdown report\n"
                "coniugata scan example.com --profile recon --depth 3 -o recon.md\n"
                "\n"
                "# Discover emails, then check them against HIBP\n"
                "coniugata scan example.com -m theharvester,hibp -d 3\n"
                "\n"
                "# Single-IP enrichment with Shodan\n"
                "coniugata scan 203.0.113.7 -m shodan -o host.json\n"
                "\n"
                "# Only certificate-transparency and DNS sources, one round\n"
                "coniugata scan example.com -m crtsh,dns --depth 1\n"
                "\n"
                "# Show one manual section\n"
                "coniugata manual configuration")
            ],
        ),
        (
            "EXIT STATUS",
            [
                "0 - success.",
                ("1 - no runnable sources were selected, for example because every selected "
                "source needs a missing API key."),
                "2 - invalid arguments or a usage error.",
            ],
        ),
        (
            "SECURITY AND ETHICS",
            [
                ("Only scan assets you own or have explicit written authorisation to test. "
                "Respect provider terms of service and rate limits, handle personal data in "
                "line with applicable law (for example GDPR), never store plaintext "
                "credentials, and keep an audit trail of what you scanned and why."),
                ("Reports neutralise CSV formula injection, Markdown/HTML injection and "
                "terminal escape sequences, because all values come from untrusted third "
                "parties."),
            ],
        ),
        (
            "SEE ALSO",
            [
                ("coniugata modules, coniugata scan --help, the project README, and "
                ".env.example."),
            ],
        ),
    ]


def render_manual(console: Console, only: str | None = None) -> bool:
    """Print the manual, or the sections matching `only`. Returns False if none match."""
    chosen = sections()
    if only:
        needle = only.strip().lower()
        chosen = [(title, paras) for title, paras in chosen if needle in title.lower()]
        if not chosen:
            return False

    console.print(f"[bold]CONIUGATA(1)[/bold]  [dim]version {_version()}[/dim]")
    for title, paragraphs in chosen:
        console.print()
        console.rule(f"[bold cyan]{title}[/bold cyan]", align="left")
        for paragraph in paragraphs:
            console.print(Text(paragraph))
            console.print()
    return True


def _escape_roff(text: str) -> str:
    """Escape text for roff: backslashes, hyphens, and leading control characters."""
    text = text.replace("\\", r"\\").replace("-", r"\-")
    if text[:1] in (".", "'"):
        text = r"\&" + text
    return text


def render_roff() -> str:
    """Emit a roff(7) man page for `man coniugata`."""
    lines = [
        (f'.TH CONIUGATA 1 "{dt.date.today():%Y-%m-%d}" '
        f'"coniugata {_version()}" "User Commands"')
    ]
    for title, paragraphs in sections():
        lines.append(f".SH {title}")
        for paragraph in paragraphs:
            if "\n" in paragraph:
                lines.append(".nf")
                lines.extend(_escape_roff(line) for line in paragraph.split("\n"))
                lines.append(".fi")
            else:
                lines.append(".PP")
                lines.append(_escape_roff(paragraph))
    return "\n".join(lines) + "\n"
