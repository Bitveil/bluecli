#!/usr/bin/env bash
# Removes everything BlueCLI ever wrote to disk:
#   - data/   the wallet, config, and connection state
#   - venv/   the Python virtual environment created on first launch
#
# After running this script, the folder is back to the way it was right
# after you unzipped it. To uninstall BlueCLI completely, also delete the
# folder this script lives in.

set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$HERE"

removed=0
for target in data venv build src/bluecli.egg-info; do
    if [ -e "$target" ]; then
        rm -rf "$target"
        echo "  removed: $target"
        removed=1
    fi
done

if [ "$removed" -eq 0 ]; then
    echo "Nothing to clean up."
else
    echo "Done. To uninstall BlueCLI completely, delete this folder."
fi
