# BlueCLI v1.3.0

A minimal, self-contained command-line client for the [Sentinel](https://sentinel.co) decentralised VPN network: create or import a wallet, browse active dVPN nodes, and route your traffic through **WireGuard**, **AmneziaWG**, or **V2Ray** — all as a seamless full tunnel, with multi-hop and on-chain session management.

## What's new in this release

- **AmneziaWG support.** Connect to AmneziaWG nodes — WireGuard with DPI-resistant obfuscation — with the same click-and-run experience as the other protocols. Everything needed is bundled: on Windows the official AmneziaWG client runs the tunnel as a service; on Linux the `amneziawg-go` userspace engine is used (no kernel module, no driver install). AmneziaWG nodes now appear in the node browser alongside WireGuard and V2Ray ones; sessions, reconnect after restart, and clean teardown work identically.
- **Clearer Linux diagnostics.** If a bundled binary has lost its execute bit (it can happen when the folder is transferred as a zip made on Windows), BlueCLI now tells you exactly which file and the one-line fix, instead of a cryptic "command not found".

## Highlights

- WireGuard, AmneziaWG, and V2Ray connections, all full-tunnel
- Multi-hop V2Ray chaining (entry → exit)
- Wallet create/import (AES-GCM encrypted) with pay-per-gigabyte or per-hour sessions
- Session browsing, retry, and teardown; automatic cleanup of expired sessions
- Self-contained: bundled WireGuard / AmneziaWG / V2Ray / tun2socks — the only system requirement is **Python 3.10–3.14**
- No installation, no services, no telemetry; everything lives in the unpacked folder

## Download

| Platform | File |
|---|---|
| Linux x86-64 | `bluecli-1.3.0-linux-x64.tar.gz` |
| Windows x64 | `bluecli-1.3.0-windows-x64.zip` |

## Install

**Linux**
```bash
tar xzf bluecli-1.3.0-linux-x64.tar.gz
cd bluecli-linux-x64
./bluecli.sh
```

**Windows** — unzip and double-click `bluecli.bat`.

The first launch builds a local Python virtual environment inside the folder (~30 seconds, once). See the [README](README.md) for the full guide.

## Verify your download

Each archive ships with a matching `.sha256` sidecar; verify before running:

```bash
sha256sum -c bluecli-1.3.0-linux-x64.tar.gz.sha256
```

## Notes

- Requires **Python 3.10–3.14** on `PATH` and administrator/root (the launcher elevates for you).
- **Back up your 24-word mnemonic.** It is the only way to recover your wallet.
- Supported platforms: Linux x86-64 and Windows x64.

Full history in the [CHANGELOG](CHANGELOG.md).
