# Packaging

Source-mode release builds. Each archive contains the BlueCLI source tree
+ the right platform's bundled binaries + a launcher script that sets up
a Python venv on first run. End user needs only Python 3.10+ on PATH.

## Build scripts

| Script | Run on | Produces |
|---|---|---|
| `build_linux.sh` | Linux (or WSL) | `bluecli-<VERSION>-linux-x64.tar.gz` **and** `bluecli-<VERSION>-windows-x64.zip` |
| `build_windows.bat` | Windows | `bluecli-<VERSION>-windows-x64.zip` only |

The Linux script produces both because the Windows package is just file
copying + zip — no PyInstaller, no compilation, no Windows-specific build
step. Single command, both archives. The Windows .bat exists for the
case where you're on a Windows-only machine and can't run bash.

## How to release

See [`../RELEASING.md`](../RELEASING.md) for the full guide. Short
version:

```bash
$EDITOR src/bluecli/__init__.py     # bump __version__
./packaging/build_linux.sh          # produces both archives
```

Then upload `bluecli-<VERSION>-{linux,windows}-x64.{tar.gz,zip}` and
their `.sha256` sidecars to GitHub Releases. Or push a `v<VERSION>` tag
and let `.github/workflows/release.yml` do it for you.

## Why we don't bundle Python (anymore)

We tried PyInstaller and ran into the classic glibc-version trap: a
Linux build done on Ubuntu 24 (glibc 2.39) refuses to start on a user
machine running Ubuntu 22 (glibc 2.35). Workarounds (build on manylinux,
musl, static-link Python) add layers of complexity that don't pay off
for a community tool.

Asking for Python 3.10+ is a one-time pip-installable thing that most
users already have. The launcher script handles everything else (venv,
shim wheels, the actual app install) on first run, takes 30-60s, and
never has to run again. We picked the latter trade-off and ship source
+ binaries + launcher.

## Archive contents

Both archives look the same except for the binaries:

```
bluecli-{linux,windows}-x64/
├── bluecli.sh / .bat       ← user-facing launcher (elevates + venv + run)
├── cleanup.sh / .bat       ← wipe venv + data
├── pyproject.toml          ← pip install metadata
├── src/                    ← the app
├── tests/                  ← optional but harmless
├── wheels/                 ← shim wheels (no MSVC / gcc needed)
├── wheelhouse_src/         ← shim wheel source for audit
├── bin/wireguard/{wg,wg-quick}      ← Linux archive
├── bin/wireguard/wireguard.exe       ← Windows archive
├── bin/v2ray/{v2ray,tun2socks,...}   ← Linux archive (binaries)
├── bin/v2ray/{v2ray.exe, tun2socks.exe, wintun.dll, ...}  ← Windows archive
└── README.txt              ← end-user instructions
```

`tests/` is included even in releases because it costs ~30 KB and lets
the user (or a security reviewer) run `tests/smoke.py` against the
shipped code without touching git.
