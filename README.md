# coniugata

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-blue.svg)](https://www.python.org/downloads/)
[![Code style: ruff](https://img.shields.io/badge/code%20style-ruff-000000.svg)](https://github.com/astral-sh/ruff)

A small, modular OSINT aggregation engine in Python. Sources are plugins; the
engine expands typed entities breadth-first (`domain -> subdomain -> IP`,
`email -> breach`) and reports every finding with its provenance.

```
coniugata/
├── coniugata/
│   ├── cli.py        # Typer commands: scan, modules
│   ├── config.py     # pydantic-settings (CONIUGATA_* env vars)
│   ├── models.py     # Entity / EntityType
│   ├── registry.py   # @register plugin registry
│   ├── http.py       # shared httpx client + token-bucket throttling
│   ├── identity.py   # anonymous per-install token and User-Agent
│   ├── db.py         # local scan-history database (SQLite)
│   ├── engine.py     # async BFS orchestrator
│   ├── report.py     # JSON / CSV / Markdown output
│   └── modules/      # one file per source
└── tests/            # offline tests (httpx.MockTransport)
```

## Quickstart

```bash
cd ~/Projects/coniugata
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev,cache]"

coniugata modules                       # list sources
coniugata scan example.com --profile recon
coniugata scan example.com --depth 2 -o report.md

coniugata --help                        # short overview
coniugata scan --help                   # summary of scan options
coniugata manual                        # full manual
coniugata manual scan                   # one section of the manual
```

The first run writes `results.json` and prints a summary table.

## Commands

| Command | Purpose |
|---|---|
| `coniugata modules` | List every registered source and what it accepts/produces |
| `coniugata scan <target>` | Run a scan against a domain, IP, or email |
| `coniugata history` | List scans recorded in the local history database |
| `coniugata show <id>` | Show the findings recorded for one scan |
| `coniugata manual [section]` | Full manual; `--roff` emits a man page |
| `--profile recon\|breach\|all` | Named module bundles |
| `--modules crtsh,dns` | Pick modules explicitly |
| `--depth N` | How many rounds of expansion (1–5) |
| `--out report.csv` | Report format chosen by extension (`.json`/`.csv`/`.md`) |
| `--cache / --no-cache` | Cache HTTP responses in `.cache/coniugata/http.db` |
| `--db / --no-db` | Record the scan in the local history database (default: record) |
| `--version` | Print the installed version and exit |

## Manual and man page

`--help` stays deliberately short. `coniugata manual` prints the long-form
reference: description, commands, every scan option, profiles, expansion rules,
the source list, configuration, files, examples, exit status and security notes.
Filter it by section name:

```bash
coniugata manual scan
coniugata manual configuration
```

The same content is available as a roff man page. A generated copy lives at
`man/coniugata.1`; install it into your user manpath with:

```bash
install -Dm644 man/coniugata.1 ~/.local/share/man/man1/coniugata.1
man coniugata
```

Regenerate it whenever the manual changes:

```bash
coniugata manual --roff > man/coniugata.1
```

## Bundled modules

| Name | Accepts | Produces | Key |
|---|---|---|---|
| `crtsh` | domain | subdomain | no |
| `rdap` | domain | domain, org | no |
| `dns` | domain | ip, domain | no |
| `urlscan` | domain | url, ip, asn, org | optional (`CONIUGATA_URLSCAN_KEY`) |
| `shodan` | ip | org, asn, domain | yes (`CONIUGATA_SHODAN_KEY`) |
| `theharvester` | domain | subdomain, email, ip | no (local binary) |
| `hibp` | email | breach | yes (`CONIUGATA_HIBP_KEY`) |

Keyed modules are automatically skipped (with a notice) when their key is absent.
`urlscan` works anonymously; a key only raises its rate limit.

`theharvester` shells out to the [theHarvester](https://github.com/laramies/theHarvester)
binary installed on your system, so it adds no Python dependency. It supplies the
`email` entities that `hibp` consumes, letting a depth-2 recon scan feed breach
lookups automatically:

```bash
coniugata scan example.com --modules theharvester -d 2 -o recon.json
```

## Configuration

Copy `.env.example` to `.env`:

```bash
CONIUGATA_HIBP_KEY=...
CONIUGATA_SHODAN_KEY=...
CONIUGATA_URLSCAN_KEY=...
CONIUGATA_REQUEST_TIMEOUT=20
CONIUGATA_CONCURRENCY=10
CONIUGATA_CACHE_TTL=3600
CONIUGATA_MAX_RESPONSE_BYTES=16777216
CONIUGATA_MAX_ENTITIES=50000
CONIUGATA_DB_PATH=
CONIUGATA_INSTANCE_TOKEN=
CONIUGATA_THEHARVESTER_BIN=theHarvester
CONIUGATA_THEHARVESTER_SOURCES=crtsh,otx,hackertarget,rapiddns
CONIUGATA_THEHARVESTER_LIMIT=500
CONIUGATA_THEHARVESTER_TIMEOUT=180
```

Every field maps to a `CONIUGATA_`-prefixed env var.

`coniugata` reads `.env` from the current directory, so an untrusted repository
could try to plant one. A `.env` that is a symlink, not owned by you, or
writable by group/others is ignored; set `CONIUGATA_ENV_FILE` to use a specific
file instead. A `.env` that is merely readable by group/others is loaded but
warns, because it can expose your API keys to other local users. Run
`chmod 600 .env` to silence the warning.

## Caching

HTTP responses are cached on disk with [hishel](https://hishel.com) in
`.cache/coniugata/http.db`, with a TTL controlled by `CONIUGATA_CACHE_TTL` (default
3600s). This saves API credits and makes repeat scans fast. Disable a run with
`--no-cache`; delete the cache directory to start fresh.

Caching requires the `cache` extra (`pip install -e ".[cache]"`). Without it the
tool still runs, just uncached. The cache directory is created with `0700`
permissions and is gitignored, but treat it as sensitive: some providers
(notably Shodan) authenticate via query-string API keys, which appear in cached
request URLs.

## Local history database

Every scan is recorded in SQLite at `~/.local/share/coniugata/coniugata.db`
(override with `CONIUGATA_DB_PATH` or `--db-path`). The database is created with
mode `0600` inside a `0700` directory and holds two tables: one row per scan and
one row per finding, including its source and parent. Reports are still written
to the path you pass `--out`; the database is for audit and repeat lookups.

```bash
coniugata history             # 20 most recent scans
coniugata history -n 100      # page through more
coniugata show 3              # findings recorded for scan #3
coniugata scan example.com --no-db   # skip recording for one run
```

The database is deliberately separate from the HTTP cache: the cache can contain
provider API keys in cached URLs, while the history database only contains what
you scanned and what came back.

## Anonymous install identity

The package ships no author contact details or shared identifier. The default
`CONIUGATA_IDENTITY_MODE=install` generates a random 128-bit token at
`~/.config/coniugata/instance.json` (mode `0600`) and sends only a truncated
SHA-256 fingerprint of it in the User-Agent. Two installs are therefore
distinguishable to providers, but the header cannot be traced back to the author
or to the token. No telemetry is sent.

| Mode | Behaviour |
|---|---|
| `install` | One persisted token per install; the same fingerprint across runs. Default. |
| `run` | A fresh random token for each run; nothing is written to disk and runs are not linkable. |
| `none` | No `instance:` fingerprint at all; only the generic `coniugata/0.1` UA. |

Set `CONIUGATA_USER_AGENT` to send a different header, or
`CONIUGATA_INSTANCE_TOKEN` to reuse an explicit token across machines.

## Adding a source

Create `coniugata/modules/mysource.py`:

```python
from ..http import fetch_json
from ..models import Entity, EntityType
from ..registry import Module, register

@register
class MySource(Module):
    name = "mysource"
    accepts = frozenset({EntityType.DOMAIN})
    produces = frozenset({EntityType.URL})
    rate_limit = 2.0            # requests/second
    description = "Example source"

    async def run(self, entity, ctx):
        data = await fetch_json(
            ctx, "https://api.example/search",
            params={"q": entity.value}, bucket=ctx.bucket(self),
        )
        for item in data.get("results", []):
            yield Entity(
                type=EntityType.URL, value=item["url"], source=self.name,
                parent=entity.value, confidence=0.7, raw=item,
            )
```

Then add it to `coniugata/modules/__init__.py`. It becomes available to `--modules`
and any profile automatically.

## Testing

```bash
pytest
```

Tests use `httpx.MockTransport` and fake subprocesses, so they never touch the
network. `tests/test_security.py` covers injection attempts, malformed upstream
payloads, report sanitisation and cache permissions.

Run the security scanners too:

```bash
ruff check . && ruff check --select S coniugata
bandit -q -r coniugata
pip-audit
```

## Security notes

- Domain, email and IP values are validated before they reach a URL, DNS query
  or subprocess argument; external commands are invoked without a shell.
- Keyed requests do not follow redirects, and error messages never include API
  keys (Shodan passes its key in the query string).
- Reports neutralise CSV formula injection, Markdown/HTML injection and terminal
  escape sequences, since all values come from untrusted third parties.
- The HTTP cache directory is `0700`, the database `0600`, and symlinked cache
  paths are refused.
- The scan-history database, identity file and report files are `0600`;
  symlinked paths are refused, and none of them stores API keys.
- `.env` files that are symlinks, not owned by you, or writable by group/others
  are ignored, so a planted file cannot point theHarvester at another binary.
  Group/other-readable files are loaded with a warning recommending
  `chmod 600 .env`.
- Responses larger than `CONIUGATA_MAX_RESPONSE_BYTES` (default 16 MiB,
  decompressed) are refused before parsing, and expansion stops at
  `CONIUGATA_MAX_ENTITIES` findings per scan (default 50000).
- Requests carry only a truncated hash of a randomly generated per-install
  token, never author contact details or the token itself.
- theHarvester runs with a timeout, in its own process group, and its report
  files are size-capped before parsing.

## Legal / ethical use

Only scan assets you own or have written authorization to test. Respect each
provider's terms of service and rate limits, handle any personal data in line
with applicable law (e.g. GDPR), never store plaintext credentials, and keep an
audit trail of what you scanned and why.

## License

Released under the [MIT License](LICENSE).

Maintained by [@sidelearner-dev](https://github.com/sidelearner-dev).
