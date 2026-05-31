# Release guide

How to produce a new BlueCLI release, in any scenario you'll realistically
hit as a maintainer.

The model is intentionally simple: each release archive is the **source
tree + the right platform binaries + a launcher script that does venv-on-
first-run**. No PyInstaller, no compilation, no platform-specific build
steps — just `cp` + `tar` / `zip`. The launcher handles Python venv
creation on the user's machine.

End user requirements: **Python 3.10+ on PATH**. Nothing else.

---

## TL;DR

```bash
# 1. Bump the version in ONE place
$EDITOR src/bluecli/__init__.py     # change __version__ = "X.Y.Z"

# 2. Build BOTH archives from a Linux host (recommended)
./packaging/build_linux.sh

# 3. Publish to GitHub Releases (or wherever)
```

Output: `bluecli-X.Y.Z-linux-x64.tar.gz` + `bluecli-X.Y.Z-windows-x64.zip`
in the project root, plus their `.sha256` sidecar files.

If you have no Linux machine: run `packaging\build_windows.bat` on
Windows for the Windows archive, and use GitHub Actions (or a friend
with Linux) for the Linux archive.

---

## Where each thing lives

| File | Purpose | Touch when… |
|---|---|---|
| `src/bluecli/__init__.py` | `__version__ = "X.Y.Z"` | every release |
| `src/bluecli/**` | App code | code changes |
| `bin/wireguard/`, `bin/v2ray/` | Bundled binaries (both OSes coexist) | binary updates |
| `pyproject.toml` | Python dependencies | adding/removing deps |
| `wheels/`, `wheelhouse_src/` | Build-time-only shim wheels | almost never |
| `bluecli.sh`, `bluecli.bat` | User-facing launchers (in archives) | rare |
| `packaging/build_linux.sh` | Builds both archives from Linux | rare |
| `packaging/build_windows.bat` | Builds Windows archive from Windows | rare |
| `.github/workflows/release.yml` | CI build on tag push | rare |

The version is read from `__init__.py` by both build scripts — single
source of truth.

---

## Scenario 1: I changed some code

1. **Run the tests**:
   ```bash
   python3 -m venv .venv
   .venv/bin/pip install --quiet --no-deps wheels/*.whl
   .venv/bin/pip install --quiet .
   .venv/bin/python tests/smoke.py
   ```
   Must show `passed: N/N`. Fix any failure before continuing.

2. **Bump the version** in `src/bluecli/__init__.py`:
   - Patch (bugfix): `1.0.0` → `1.0.1`
   - Minor (new feature, backward-compatible): `1.0.0` → `1.1.0`
   - Major (breaking change to state.json / config / CLI flags): `1.0.0` → `2.0.0`

3. **Build**:
   ```bash
   ./packaging/build_linux.sh
   ```
   Produces both archives.

4. **Smoke-test the archives** (5 minutes, very worth it):
   ```bash
   mkdir /tmp/test && cd /tmp/test
   tar xzf /path/to/bluecli-X.Y.Z-linux-x64.tar.gz
   cd bluecli-linux-x64
   ./bluecli.sh        # first run installs venv; subsequent runs are instant
   ```
   On Windows: extract the zip, double-click `bluecli.bat`.

5. **Publish** — see below.

---

## Scenario 2: I updated a bundled binary

Example: new v2fly release, want to ship newer WireGuard, etc.

1. **Drop the new binary into `bin/`**, replacing the old one, keeping
   the exact filename. Both Windows and Linux variants live side by
   side under `bin/wireguard/` and `bin/v2ray/`:
   ```
   bin/wireguard/wireguard.exe        ← Windows
   bin/wireguard/wg                   ← Linux
   bin/wireguard/wg-quick             ← Linux (bash script)
   bin/v2ray/v2ray.exe                ← Windows
   bin/v2ray/v2ray                    ← Linux
   bin/v2ray/tun2socks.exe            ← Windows
   bin/v2ray/tun2socks                ← Linux
   bin/v2ray/wintun.dll               ← Windows
   bin/v2ray/geoip.dat                ← both
   bin/v2ray/geosite.dat              ← both
   ```

2. **Set the executable bit** on Linux binaries (Git often loses it):
   ```bash
   chmod +x bin/wireguard/wg bin/wireguard/wg-quick
   chmod +x bin/v2ray/v2ray bin/v2ray/tun2socks
   ```

3. **Smoke-test in isolation**:
   ```bash
   bin/v2ray/v2ray version
   bin/wireguard/wg --version
   ```
   Confirm they run on your system without missing-library errors.

4. **Bump the version** in `__init__.py` (patch bump is appropriate:
   `1.0.0` → `1.0.1`).

5. **Build, smoke-test, publish** — same as Scenario 1 steps 3-5.

---

## Scenario 3: I added a new Python dependency

Example: started using a new library in `src/bluecli/...`.

1. **Add it to `pyproject.toml`** under `dependencies`.

2. **Smoke-test the user's first-run flow** in a clean directory to
   verify pip can install the new dep without a C compiler:
   ```bash
   rm -rf /tmp/depcheck && mkdir /tmp/depcheck && cd /tmp/depcheck
   cp -r /path/to/bluecli/* .
   python3 -m venv venv
   venv/bin/pip install --quiet --no-deps wheels/*.whl
   venv/bin/pip install .             # must succeed without errors
   ```

3. If pip tries to compile something (look for `gcc` / `cc` invocations
   or "building wheel for X"), the new dep ships only as a source
   distribution and the end user's machine would need a compiler.
   Either:
   - Pick a different dep that ships pre-built wheels, OR
   - Build a shim wheel like `wheels/safe_pysha3-1.0.5-py3-none-any.whl`
     (see `wheelhouse_src/` for the pattern), OR
   - Document the requirement in the README ("This release needs gcc /
     MSVC" — acceptable only as a last resort)

4. **Bump, build, smoke-test, publish** as usual.

---

## Building from a Windows machine

If your only dev box is Windows, the Linux archive can't be built
locally (the `build_linux.sh` script is bash). Three options:

- **WSL** (recommended): from Windows, install WSL2 + Ubuntu, then run
  `./packaging/build_linux.sh` inside WSL. You'll get both archives.
- **GitHub Actions**: push a tag, let CI build. See below.
- **Skip the Linux archive**: ship Windows-only, link Linux users to
  build from source.

For the Windows-only path:

```cmd
packaging\build_windows.bat
```

Produces just `bluecli-X.Y.Z-windows-x64.zip` + sidecar.

---

## Building via GitHub Actions

If your repo is on GitHub (recommended for a community tool — adds
visibility and trust):

1. **Commit your changes** to the repo (`git push`).
2. **Tag the release**:
   ```bash
   git tag v1.0.1
   git push --tags
   ```
3. The workflow at `.github/workflows/release.yml` triggers on `v*`
   tags. It runs `build_linux.sh` on `ubuntu-latest` (which produces
   both archives), creates a GitHub Release for the tag, and attaches
   the archives + `.sha256` files.

You don't need any local build environment for this path — GitHub does
everything. The tag name (e.g. `v1.0.1`) should match `__version__` in
`__init__.py` (e.g. `1.0.1`) for filename consistency.

---

## Publishing a release

### To GitHub Releases (recommended)

If you used GitHub Actions: nothing to do, the release is already up.
Otherwise:

1. Go to `https://github.com/YOUR-ORG/bluecli/releases/new`
2. Choose the tag `vX.Y.Z` (create it if you didn't push one)
3. Title: `BlueCLI vX.Y.Z`
4. Description (template):
   ```
   ## Highlights
   - Faster node refresh: 30s → 8s
   - Fix: WireGuard reconnect now works after laptop sleep
   - Updated bundled v2ray to v5.20

   ## Downloads
   - Linux x86-64: bluecli-1.0.1-linux-x64.tar.gz
   - Windows x86-64: bluecli-1.0.1-windows-x64.zip

   SHA256 sidecar files are attached for verification.

   ## Requires
   - Python 3.10 or newer on PATH (see README for setup)
   ```
5. Drag-and-drop both archives + their `.sha256` files into the
   upload area
6. Publish

### Sanity check after publishing

Open the Releases page in a private browser window, download the
Linux (or Windows) archive, extract it, run the launcher. Easy
60-second sanity check; catches catastrophe.

### Announce

For a Sentinel-community tool:
- `r/Sentinel` post (link to the release, brief changelog)
- Sentinel Discord / Telegram if you're active there
- @ any beta testers who helped

---

## Versioning policy

Semver, with one practical note for a community tool:

| Change | Bump | Example |
|---|---|---|
| New feature, no breakage | minor | 1.0.0 → 1.1.0 |
| Bug fix, no API change | patch | 1.0.0 → 1.0.1 |
| Breaking change to state.json / config / CLI flags | major | 1.0.0 → 2.0.0 |
| Pre-1.0 anything | minor or patch | 0.1.0 → 0.2.0 |

**Major bumps are expensive** for users — they have to migrate. Avoid
them. If you must break compatibility, ship a migration path in
`__main__.py` that detects the old format and upgrades it in place.

---

## When something goes wrong mid-build

| Symptom | Likely cause | Fix |
|---|---|---|
| `pip install` fails with SSL error | corporate proxy / outdated CA bundle | `pip install --trusted-host pypi.org --trusted-host files.pythonhosted.org ...` |
| End user reports `ModuleNotFoundError` on first run | dep added to imports but not `pyproject.toml` | add to `pyproject.toml`, rebuild |
| End user reports "missing C compiler" on first run | new dep needs compilation (see Scenario 3) | swap dep / build a shim wheel |
| WireGuard fails on Linux: `wg-quick: command not found` | `wg-quick` not bundled or not +x | re-check bin/wireguard/ contents + `chmod +x` |
| `bin/v2ray/v2ray` missing on user's Linux box | shipped Windows archive by mistake | check the archive's `bin/v2ray/` listing |

---

## What does NOT require a release

You can change these without re-cutting an archive — users do nothing:

- The GitHub repo README (renders live on GitHub)
- `bin/README.md` / `packaging/README.md` (maintainer-only docs)
- The CI workflow itself
- `RELEASING.md` (this file)

Commit, push, done.

---

## Disaster recovery: I lost my dev box

Everything you need is in the source tree:

```bash
git clone https://github.com/YOUR-ORG/bluecli
cd bluecli
./packaging/build_linux.sh
```

The `wheels/` folder has the pre-built shim wheels. The `bin/` folder
has both Linux and Windows binaries committed. Builds don't reach out
to anywhere — PyPI being down doesn't stop you from building releases.

Even if you abandon the project, a successor can take over with the
same `git clone` + one shell command. By design.
