# Security assessment — coniugata 0.1.0

**Date:** 2026-11-17
**Scope:** the `coniugata` source tree in this repository (CLI, engine, modules,
HTTP/cache layer, reporting, local database, per-install identity,
theHarvester wrapper, packaging metadata).
**Type:** source review + automated scanners + adversarial tests + local smoke test.
**Result:** no critical or high-severity issues remain after the fixes below.
Three residual low risks and two informational notes are documented.

> This is a best-effort assessment of this codebase, not a formal third-party
> audit or a guarantee. Re-run the checks after dependency or code changes.

## 1. Threat model

The tool is a local CLI that makes outbound requests on the user's behalf.

| Trust boundary | Untrusted input |
|---|---|
| Target argument | Domain, IP or email, plus arbitrary CLI strings |
| Provider responses | JSON from crt.sh, RDAP, DNS, Shodan, urlscan, HIBP, theHarvester files |
| Local filesystem | `.env` in the current directory, report paths, cache/database paths, symlinks |
| Subprocess | theHarvester binary and its stdout/stderr/report files |
| Third-party code | Python dependencies and the installed theHarvester binary |

Primary goals: no command/argument injection, no credential leakage, no
untrusted-data injection into CSV/Markdown/terminal output, predictable
filesystem permissions, and bounded resource consumption.

## 2. Method

- Manual review of every package module and the CLI wiring.
- `pytest` — 84 tests, including the existing adversarial suite plus new tests
  for env-file trust, response-size limits, entity caps, identity modes,
  report permissions and symlink handling.
- `ruff check .`, `ruff check --select S coniugata`, `bandit -q -r coniugata`.
- `pip-audit` against the installed virtual environment.
- `python -m compileall`.
- Live smoke test: `coniugata scan example.com -m dns -d 1` in a temporary
  `XDG_CONFIG_HOME`/`XDG_DATA_HOME`, followed by `coniugata history` and
  `coniugata show 1`.
- Targeted local-server check of verbose logging against a fake API key.

## 3. Findings

| ID | Severity | Status | Finding |
|---|---|---|---|
| F-01 | High | Fixed | A planted `.env` in the working directory could redirect `CONIUGATA_THEHARVESTER_BIN` to an attacker binary (code execution when `-m theharvester` runs), or change the database/report locations. |
| F-02 | Medium | Fixed | HTTP response bodies were read fully into memory; a hostile or broken provider could cause a memory-exhaustion DoS. |
| F-03 | Medium | Fixed | Graph expansion had no upper bound; a large upstream result set could create unbounded tasks/results and exhaust memory or API credits. |
| F-04 | Medium | Fixed | Report files were created with the process umask (commonly `0644`), potentially exposing personal OSINT data to other local users. |
| F-05 | Low | Fixed | Report paths were followed if they were symlinks; identity writes did not refuse a symlinked config directory. |
| F-06 | Low | Hardened | `httpx` logs full request URLs at INFO (query strings can contain the Shodan key) and related libraries log request metadata at DEBUG. The CLI already suppressed `httpx`; the other loggers are now suppressed too, in normal and verbose mode. |
| F-07 | Low | Fixed | Redirect handling allowed the library default of 20 hops; capped at 5. |
| F-08 | Low | Residual | theHarvester stdout/stderr are read with `communicate()` without a byte cap. A malicious local binary could exhaust memory before the report-file cap applies. |
| F-09 | Low | Residual | The scan-history database is not encrypted at rest. It is `0600`, but a local user who can read your files can read your scan history. |
| F-10 | Low | Residual | Runtime dependencies use lower bounds, not pinned versions or hashes. `pip-audit` is clean today, but builds are not reproducible and a future compromised release could be picked up. |
| F-11 | Info | Accepted | Shodan authenticates with a query-string key, so cached request URLs contain it. The cache is `0700`/`0600` and documented as sensitive. |
| F-12 | Info | Accepted | Individual provider values are not length-capped, but whole responses are capped at 16 MiB and findings at 50,000 per scan. |

### F-01 — Untrusted `.env` (fixed)

`pydantic-settings` read `.env` from the current directory. An attacker who can
drop a file into a repository could set `CONIUGATA_THEHARVESTER_BIN` to an
executable they control. `load_settings()` now ignores a `.env` that is:

- a symlink,
- not owned by the current user (where the platform exposes `getuid`), or
- writable by group or others (`mode & 0o022`).

`CONIUGATA_ENV_FILE` selects an explicit path. A `.env` that is merely readable
by group or others is still loaded, but logs a warning recommending
`chmod 600 .env`, because it can expose API keys. Tests cover unsafe, private,
group-readable and symlinked env files.

### F-02 — Response-size cap (fixed)

`fetch_json()` now streams the body and raises once the decoded size exceeds
`CONIUGATA_MAX_RESPONSE_BYTES` (default 16 MiB), before JSON parsing. The limit
counts decompressed bytes, so a compression bomb is also bounded.

### F-03 — Expansion cap (fixed)

`run_scan()` stops at `CONIUGATA_MAX_ENTITIES` findings (default 50,000; `0`
disables the cap), logs a warning, and cancels outstanding tasks so they do not
outlive the HTTP client.

### F-04 — Report permissions (fixed)

Reports are opened with `O_NOFOLLOW` and mode `0600` for `.json`, `.csv` and
`.md`. Symlinked report paths are refused.

## 4. Controls verified as working

- **Input validation:** hostnames, emails and IPs are validated before use in
  URLs, DNS queries or subprocess arguments; option-like and injection strings
  (`--help`, `;`, `../`, spaces, newlines) are rejected.
- **No shell execution:** theHarvester runs via `create_subprocess_exec` with a
  validated domain, no shell, a timeout, its own process group, and a 64 MiB
  report-file cap.
- **Credential handling:** keyed requests set `follow_redirects=False`; 401/404
  handling re-raises status-only errors; the Shodan and HIBP API keys do not
  appear in error text. `httpx` URL logging is suppressed.
- **Output injection:** CSV formula injection is neutralised, Markdown/HTML
  table injection is escaped, and terminal escape sequences are stripped before
  rendering.
- **Filesystem:** cache directory `0700`, cache DB `0600`, history DB `0600`,
  identity file `0600`, reports `0600`; symlinked cache/DB/identity/report
  paths are refused.
- **Local state separation:** the history database stores scan metadata and
  findings only; provider API keys stay in the HTTP cache, which is documented
  as sensitive.
- **Anonymous identity:** `install` (persisted token), `run` (per-run token,
  nothing written) and `none` (no fingerprint) modes; only a truncated SHA-256
  fingerprint is sent, never the token or author contact data.
- **No telemetry:** nothing is sent anywhere except the selected source APIs.

## 5. Evidence

```
$ pytest -q
84 passed

$ ruff check . && ruff check --select S coniugata
All checks passed!

$ bandit -q -r coniugata
(no findings)

$ pip-audit
No known vulnerabilities found
(coniugata itself is not on PyPI and was skipped)
```

Live scan (temporary XDG dirs):

```
$ coniugata scan example.com -m dns -d 1 -o .../report.json
Scan recorded as #1

$ find ... -type f -printf '%m %p\n'
600 .../data/coniugata/coniugata.db
600 .../report.json
600 .../config/coniugata/instance.json
700 .../data/coniugata
700 .../config/coniugata
```

Logging check against a local HTTP server:

```
httpx INFO leaks key: True   # demonstrates the underlying risk
normal mode leaks key: False # CLI configuration
verbose mode leaks key: False
```

## 6. Recommendations

1. Pin and hash runtime dependencies for releases (or ship a lock file/SBOM).
2. Cap theHarvester stdout/stderr (F-08) or run it inside a memory-limited
   wrapper if you routinely scan untrusted infrastructure.
3. If scan history is sensitive, add opt-in encryption (for example SQLCipher)
   or store the database on an encrypted volume; `0600` is not encryption.
4. Prefer HTTPS-only redirects, or an allow-list of provider hosts, if you want
   to reduce the chance of a redirected request reaching an internal address.
5. Keep the existing test suite in CI together with `ruff --select S`,
   `bandit`, and `pip-audit`; re-run this assessment after dependency updates.
6. Treat the installed `theHarvester` binary and any `.env` you load as trusted
   code/config, even with the new checks.
