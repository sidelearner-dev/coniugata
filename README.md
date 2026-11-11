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
```

The first run writes `results.json` and prints a summary table.

## Commands

| Command | Purpose |
|---|---|
| `coniugata modules` | List every registered source and what it accepts/produces |
| `coniugata scan <target>` | Run a scan against a domain, IP, or email |
| `--profile recon\|breach\|all` | Named module bundles |
| `--modules crtsh,dns` | Pick modules explicitly |
| `--depth N` | How many rounds of expansion (1–5) |
| `--out report.csv` | Report format chosen by extension (`.json`/`.csv`/`.md`) |
| `--cache / --no-cache` | Cache HTTP responses in `.cache/coniugata/http.db` |

## Bundled modules

| Name | Accepts | Produces | Key |
|---|---|---|---|
| `crtsh` | domain | subdomain | no |
| `rdap` | domain | domain, org | no |
| `dns` | domain | ip, domain | no |
| `urlscan` | domain | url, ip, asn, org | optional (`CONIUGATA_URLSCAN_KEY`) |
| `shodan` | ip | org, asn, domain | yes (`CONIUGATA_SHODAN_KEY`) |
| `hibp` | email | breach | yes (`CONIUGATA_HIBP_KEY`) |

Keyed modules are automatically skipped (with a notice) when their key is absent.
`urlscan` works anonymously; a key only raises its rate limit.

## Configuration

Copy `.env.example` to `.env`:

```bash
CONIUGATA_HIBP_KEY=...
CONIUGATA_SHODAN_KEY=...
CONIUGATA_URLSCAN_KEY=...
CONIUGATA_REQUEST_TIMEOUT=20
CONIUGATA_CONCURRENCY=10
CONIUGATA_CACHE_TTL=3600
```

Every field maps to an `CONIUGATA_`-prefixed env var.

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

Tests use `httpx.MockTransport`, so they never touch the network.

## Legal / ethical use

Only scan assets you own or have written authorization to test. Respect each
provider's terms of service and rate limits, handle any personal data in line
with applicable law (e.g. GDPR), never store plaintext credentials, and keep an
audit trail of what you scanned and why.
