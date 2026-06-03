# BlueCLI

A minimal, self-contained command-line client for the [Sentinel](https://sentinel.co) decentralised VPN network.

![License](https://img.shields.io/badge/license-MIT-blue.svg)
![Python](https://img.shields.io/badge/python-3.10--3.14-blue.svg)
![Platforms](https://img.shields.io/badge/platforms-Linux%20%7C%20Windows-blue.svg)
![Release](https://img.shields.io/badge/release-v1.0.0-blue.svg)

Create or import a Cosmos/Sentinel wallet, browse active dVPN nodes, and route your traffic through **WireGuard** or **V2Ray** — both as a seamless full tunnel. BlueCLI is built for the Sentinel community: no accounts, no telemetry, no background services.

> **BlueCLI does not install itself.** No registry keys, no system services, no `PATH` changes, no `~/.bluecli/` directory. Everything — including the Python virtual environment it builds on first run — lives inside the folder you unpacked. To remove BlueCLI, delete that folder.

---

## Contents

- [Features](#features)
- [Requirements](#requirements)
- [Install](#install)
- [Verifying your download](#verifying-your-download)
- [First run](#first-run)
- [Using BlueCLI](#using-bluecli)
- [Data footprint & privacy](#data-footprint--privacy)
- [Uninstall](#uninstall)
- [Run & build from source](#run--build-from-source)
- [How it works](#how-it-works)
- [Troubleshooting](#troubleshooting)
- [Contributing](#contributing)
- [License](#license)
- [Acknowledgements](#acknowledgements)

---

## Features

- **Two protocols, both full-tunnel.** Connect through WireGuard or V2Ray; once connected, all traffic egresses through the node.
- **Multi-hop.** Chain two V2Ray nodes (entry → exit) so no single node sees both who you are and what you reach.
- **Real wallet, on-chain sessions.** Create or import a 24-word Sentinel wallet, pay per gigabyte or per hour, and manage your active sessions from the CLI.
- **Self-contained.** Bundles the WireGuard tools, V2Ray, and tun2socks. The only thing it needs from your system is Python.
- **No installation, no residue.** Runs entirely from its own folder; uninstalling is deleting it.
- **Background node refresh.** The active-node list is fetched and kept fresh in the background so browsing is instant.
- **Resilient routing.** The chain RPC endpoint is reached outside the tunnel, so connecting, disconnecting, and switching nodes don't cut off the client from the chain.

---

## Requirements

- **Python 3.10–3.14**, available on your `PATH`. (A just-released Python may not yet have prebuilt packages for every dependency — prefer the latest version in this range.)
  - Most Linux distributions ship it; if not, install it with your package manager (e.g. `sudo apt install python3`).
  - On Windows, install from [python.org](https://www.python.org/downloads/) and tick **“Add Python to PATH”** during setup.
- **Administrator / root.** Managing a VPN tunnel needs elevated privileges. The launcher elevates for you (UAC prompt on Windows, `sudo` on Linux).
- **No compiler or build tools.** Every dependency installs over plain HTTPS; the few that normally need a C toolchain are satisfied by tiny bundled pure-Python wheels.

Supported platforms: **Linux x86-64** and **Windows x64**.

---

## Install

1. Download the archive for your platform from the [latest release](https://github.com/YOUR-ORG/bluecli/releases/latest):
   - Linux — `bluecli-<version>-linux-x64.tar.gz`
   - Windows — `bluecli-<version>-windows-x64.zip`
2. Extract it anywhere you like (your home folder, a USB stick, wherever).
3. Launch it:

   **Linux**
   ```bash
   tar xzf bluecli-<version>-linux-x64.tar.gz
   cd bluecli-linux-x64
   ./bluecli.sh
   ```

   **Windows**
   ```
   Unzip, open the bluecli-windows-x64 folder, and double-click bluecli.bat
   (or run it from a terminal).
   ```

The **first launch** builds a local Python virtual environment inside the folder and installs dependencies — this takes roughly 30 seconds and happens only once. Every launch after that is instant.

---

## Verifying your download

Each archive ships with a `.sha256` sidecar. Verify integrity before running:

**Linux**
```bash
sha256sum -c bluecli-<version>-linux-x64.tar.gz.sha256
```

**Windows (PowerShell)**
```powershell
(Get-FileHash bluecli-<version>-windows-x64.zip -Algorithm SHA256).Hash -eq `
  (Get-Content bluecli-<version>-windows-x64.zip.sha256).Split(' ')[0].ToUpper()
```

---

## First run

1. Launch BlueCLI and choose **Create a new wallet** (or **Import** an existing 24-word mnemonic).
2. Set a password. It encrypts your mnemonic on disk (AES-GCM); BlueCLI never stores it in plaintext.
3. **Write your 24 words down on paper and keep them safe.** They are the *only* way to recover the wallet — there is no reset.
4. Send some **DVPN** to the address shown so the wallet exists on chain and can pay for sessions.
5. From the main menu pick **Browse nodes**, choose one, select gigabytes or hours, and confirm.

> **Tip:** if you're just trying BlueCLI out, use a fresh wallet funded with a small amount you're comfortable treating as disposable, rather than your main wallet.

---

## Using BlueCLI

From the main menu:

- **`1` Browse nodes** — page through active nodes, pick one, and connect (single-hop).
- **`m` Multi-hop** — pick an entry and an exit V2Ray node and chain them.
- **`2` My active sessions** — see what you're paying for, retry a session whose connection failed (`<num>r`), or end one to stop paying (`<num>e`).
- **`3` Wallet** — show your address, export, or delete the wallet.
- **`4` Settings** — change the chain gRPC endpoint or language.
- **`d` Disconnect** — tear the tunnel down and restore your normal network.
- **`5` Exit`** — disconnect (if connected) and quit.

Sessions on Sentinel are **ephemeral**: a per-hour or per-gigabyte session ends on its own once its allowance runs out. BlueCLI reconciles this for you — expired sessions drop out of your list, and if a session backing a live tunnel expires, opening **My active sessions** tears the dead tunnel down and restores your connection.

---

## Data footprint & privacy

Everything BlueCLI writes lives under the unpacked folder:

```
data/
├── wallet.enc         your mnemonic, AES-GCM encrypted with your password
├── config.json        chain endpoint and preferences
├── nodes_cache.json   background-refreshed node list
├── state.json         present only while connected
├── wg-blue.conf       present only while connected (WireGuard)
└── v2ray.json         present only while connected (V2Ray)
venv/                  the local Python virtual environment
```

No registry keys, no services, no system `PATH` changes, no telemetry, no network calls beyond the Sentinel chain and the node you connect to.

---

## Uninstall

```bash
./cleanup.sh        # Linux   — wipes data/ (wallet, config, state) and venv/
cleanup.bat         # Windows
```

Then delete the folder. That's the entire uninstall. **`cleanup` erases your wallet** — make sure you still have your 24 words if you intend to keep it.

---

## Run & build from source

BlueCLI runs straight from a clone — the launcher does the venv setup for you, exactly as it does from a release archive.

```bash
git clone https://github.com/YOUR-ORG/bluecli
cd bluecli
./bluecli.sh
```

### Running the tests

```bash
python3 -m venv .venv
.venv/bin/pip install --no-deps wheels/*.whl
.venv/bin/pip install .
# Force bip-utils onto its pure-Python secp256k1 backend (the launcher does
# this automatically; for a manual dev venv, do it once):
python3 -c "import pathlib;[p.write_text(p.read_text().replace('USE_COINCURVE: bool = True','USE_COINCURVE: bool = False')) for p in pathlib.Path('.venv').rglob('bip_utils/ecc/conf.py')]"
BLUECLI_HOME=$PWD .venv/bin/python tests/smoke.py
```

### Building the release archives

```bash
./packaging/build_linux.sh
```

This produces **both** archives (Linux `.tar.gz` and Windows `.zip`) plus their `.sha256` sidecars in the project root — no PyInstaller, no compilation, just file copies and an archive step. See [`RELEASING.md`](RELEASING.md) for the full release process and the Windows-host fallback.

---

## How it works

- **Routing.** A full tunnel is installed by overlaying a `0.0.0.0/1` + `128.0.0.0/1` default through the tunnel device (WireGuard via `wg-quick`; V2Ray via tun2socks). The original default route is preserved so teardown is clean.
- **Chain bypass.** A host route pins the Sentinel gRPC endpoint to the real network, so chain queries keep working regardless of tunnel state — connecting or disconnecting never strands the client from the chain.
- **Multi-hop.** A single V2Ray process is configured with two outbounds (entry → exit), chaining TCP-capable nodes so neither endpoint sees both sides of the connection.

---

## Troubleshooting

- **“python3 is not installed or not on PATH.”** Install Python 3.10–3.14 and make sure it's on `PATH` (on Windows, re-run the installer and tick *Add Python to PATH*).
- **First run is slow.** That's the one-time venv build (~30s). Later launches are instant.
- **The connection comes up but there's no internet.** Press `d` to disconnect and reconnect, or pick another node. A node can drop or a session can expire; BlueCLI restores your normal network on disconnect.
- **Windows SmartScreen / antivirus prompts.** The bundled WireGuard, V2Ray, and tun2socks binaries are unsigned upstream releases; allow them if your policy permits.
- **A paid session that never connected.** It's saved as an *orphan*; from **My active sessions** you can retry (`<num>r`) or release it (`<num>e`).

---

## Contributing

Issues and pull requests are welcome. Please keep changes focused, run `tests/smoke.py` before submitting, and avoid adding runtime dependencies beyond Python — keeping BlueCLI dependency-light and installation-free is a core goal.

---

## License

[MIT](LICENSE).

---

## Acknowledgements

BlueCLI stands on:

- [Sentinel](https://sentinel.co) and the [sentinel-python-sdk](https://github.com/MathNodes/sentinel-python-sdk)
- [v2fly/v2ray-core](https://github.com/v2fly/v2ray-core)
- [xjasonlyu/tun2socks](https://github.com/xjasonlyu/tun2socks)
- [WireGuard](https://www.wireguard.com/) and [wintun](https://www.wintun.net/)
