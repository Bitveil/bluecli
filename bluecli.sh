#!/usr/bin/env bash
# BlueCLI launcher for Linux and macOS.
#
# Auto-elevates with sudo on first launch. WireGuard tunnel management
# requires root; the V2Ray local tunnel doesn't, but we elevate uniformly
# so the user is prompted once at startup rather than mid-session.

set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$HERE"

# --- 1. Elevate if not already root. ---------------------------------------
if [ "$(id -u)" -ne 0 ]; then
    if command -v sudo >/dev/null 2>&1; then
        echo "Requesting root privileges (needed for the VPN tunnel)..."
        # -E preserves environment so BLUECLI_HOME etc. carry over if set.
        exec sudo -E "$0" "$@"
    else
        echo "Error: this needs to run as root, and sudo is not installed." >&2
        echo "Re-run as root: # ./bluecli.sh" >&2
        exit 1
    fi
fi

export BLUECLI_HOME="$HERE"

# --- 2. Ensure Python 3.10+ is present. ------------------------------------
PYTHON_BIN="${PYTHON:-python3}"
if ! command -v "$PYTHON_BIN" >/dev/null 2>&1; then
    echo "Error: python3 is not installed or not on PATH." >&2
    echo "Install Python 3.10+ and try again." >&2
    exit 1
fi

# --- 3. Create the local venv on first run. --------------------------------
if [ ! -x venv/bin/python ]; then
    echo "First-time setup: creating a local virtual environment..."
    "$PYTHON_BIN" -m venv venv
    venv/bin/pip install --upgrade pip >/dev/null
    # Pre-install the bundled shim wheels (safe-pysha3 and ed25519-blake2b).
    # These satisfy two transitive deps of sentinel-sdk that ship as
    # C-extension sources on PyPI — pip would try to compile them, which
    # fails on machines without a C toolchain (very common on Windows; the
    # same hazard exists on minimal Linux installs). Pre-installing the
    # shims means pip treats those deps as already satisfied.
    venv/bin/pip install --quiet --no-deps \
        wheels/safe_pysha3-1.0.5-py3-none-any.whl \
        wheels/ed25519_blake2b-1.4.1-py3-none-any.whl \
        wheels/coincurve-18.0.0-py3-none-any.whl
    venv/bin/pip install --quiet .
    # Force bip-utils onto its pure-Python ecdsa secp256k1 backend. The
    # coincurve shim above keeps pip's resolver happy without compiling
    # the real coincurve C extension (which has no wheel for Python 3.13+
    # in the version bip-utils pins, so pip would try — and fail — to
    # build it from source on machines without autotools, e.g. Kali).
    # ecdsa derives byte-identical keys/addresses; this just flips the
    # backend selector that ships defaulted to coincurve.
    venv/bin/python -c "import pathlib; [p.write_text(p.read_text().replace('USE_COINCURVE: bool = True', 'USE_COINCURVE: bool = False')) for p in pathlib.Path('venv').rglob('bip_utils/ecc/conf.py')]"
    rm -rf build src/bluecli.egg-info
    echo "Setup complete."
fi

# --- 4. Run BlueCLI. -------------------------------------------------------
exec venv/bin/python -m bluecli "$@"
