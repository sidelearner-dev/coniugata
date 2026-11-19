#!/usr/bin/env bash
# One-command setup for coniugata.
#
# Creates .venv, installs the package with caching enabled, and prints the
# three commands needed for a first scan. Safe to re-run. Use --dev to also
# install the test/lint tools.
set -euo pipefail

ROOT="$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT"

PY="${PYTHON:-python3}"
if ! command -v "$PY" >/dev/null 2>&1; then
    echo "error: '$PY' not found. Install Python 3.11+ and try again." >&2
    exit 1
fi

if ! "$PY" -c 'import sys; sys.exit(0 if sys.version_info >= (3, 11) else 1)' 2>/dev/null; then
    echo "error: Python 3.11 or newer is required (found: $($PY --version 2>&1))." >&2
    exit 1
fi

DEV=0
case "${1:-}" in
    "")
        ;;
    --dev)
        DEV=1
        ;;
    -h | --help)
        echo "Usage: ./setup.sh [--dev]"
        echo "  --dev   also install pytest, ruff, bandit and pip-audit"
        exit 0
        ;;
    *)
        echo "error: unknown option: $1" >&2
        echo "Usage: ./setup.sh [--dev]" >&2
        exit 1
        ;;
esac

if [[ ! -f pyproject.toml ]]; then
    echo "error: run this script from the coniugata repository root." >&2
    exit 1
fi

if [[ -d .venv ]]; then
    echo "Reusing existing .venv ..."
else
    echo "Creating virtual environment in .venv ..."
    "$PY" -m venv .venv
fi

VENV_PY="$ROOT/.venv/bin/python"
if [[ ! -x "$VENV_PY" ]]; then
    echo "error: virtual environment is missing $VENV_PY" >&2
    exit 1
fi

EXTRA="cache"
if [[ $DEV -eq 1 ]]; then
    EXTRA="dev,cache"
fi

echo "Installing coniugata (extra: $EXTRA) ..."
"$VENV_PY" -m pip install -e ".[$EXTRA]"

CLI="$ROOT/.venv/bin/coniugata"
if command -v theHarvester >/dev/null 2>&1; then
    HARVEST="theHarvester detected: the optional 'theharvester' module is available."
else
    HARVEST="theHarvester not found (optional). Install it only if you need the 'theharvester' module."
fi

cat <<EOF

Setup complete.

Start here (no activation needed):

  $CLI scan example.com
  $CLI scan example.com -p recon -o recon.md
  $CLI history

$HARVEST

No API keys are required: keyed modules are skipped with a notice.
Full reference: $CLI manual
Contributors:  ./setup.sh --dev
EOF
