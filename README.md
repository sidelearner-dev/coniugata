# coniugata

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
| `coniugata manual [section]` | Full manual; `--roff` emits a man page |
| `--profile recon\|breach\|all` | Named module bundles |
| `--modules crtsh,dns` | Pick modules explicitly |
| `--depth N` | How many rounds of expansion (1–5) |
| `--out report.csv` | Report format chosen by extension (`.json`/`.csv`/`.md`) |
| `--cache / --no-cache` | Cache HTTP responses in `.cache/coniugata/http.db` |
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
CONIUGATA_THEHARVESTER_BIN=theHarvester
CONIUGATA_THEHARVESTER_SOURCES=crtsh,otx,hackertarget,rapiddns
CONIUGATA_THEHARVESTER_LIMIT=500
CONIUGATA_THEHARVESTER_TIMEOUT=180
```

Every field maps to a `CONIUGATA_`-prefixed env var.

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
- theHarvester runs with a timeout, in its own process group, and its report
  files are size-capped before parsing.

## Legal / ethical use

Only scan assets you own or have written authorization to test. Respect each
provider's terms of service and rate limits, handle any personal data in line
with applicable law (e.g. GDPR), never store plaintext credentials, and keep an
audit trail of what you scanned and why.
