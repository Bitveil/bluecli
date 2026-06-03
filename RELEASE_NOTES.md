# BlueCLI v1.1.0

A minimal, self-contained command-line client for the [Sentinel](https://sentinel.co) decentralised VPN network: create or import a wallet, browse dVPN nodes, and route your traffic through **WireGuard** or **V2Ray** as a full tunnel — with multi-hop and on-chain session management.

## What's new in this release

- **Token ticker is now `P2P`.** Following the network's rebrand, every place the token is shown to you — node prices, your balance, connection and multi-hop confirmations, and funding prompts — now reads `P2P` instead of `DVPN`.
- **Per-hour price in the node browser.** The node list now shows each node's hourly price next to its per-gigabyte price, so duration-based plans are visible at a glance.
- **Manual refresh in the node browser.** Press `r` to refresh the node list on demand. It is mutually exclusive with the automatic background refresh: if a refresh is already running you are told to wait, otherwise yours runs — the two never overlap.

## Highlights

- WireGuard and V2Ray connections, both full-tunnel
- Multi-hop V2Ray chaining (entry → exit)
- Wallet create/import (AES-GCM encrypted) with pay-per-gigabyte or per-hour sessions
- Session browsing, retry, and teardown; automatic cleanup of expired sessions
- Self-contained: bundled WireGuard / V2Ray / tun2socks — the only system requirement is **Python 3.10–3.14**
- No installation, no services, no telemetry; everything lives in the unpacked folder

## Download

| Platform | File |
|---|---|
| Linux x86-64 | `bluecli-1.1.0-linux-x64.tar.gz` |
| Windows x64 | `bluecli-1.1.0-windows-x64.zip` |

## Install

**Linux**
```bash
tar xzf bluecli-1.1.0-linux-x64.tar.gz
cd bluecli-linux-x64
./bluecli.sh
```

**Windows** — unzip and double-click `bluecli.bat`.

The first launch builds a local Python virtual environment inside the folder (~30 seconds, once). See the [README](README.md) for the full guide.

## Verify your download

Each archive ships with a matching `.sha256` sidecar; verify before running:

```bash
sha256sum -c bluecli-1.1.0-linux-x64.tar.gz.sha256
```

## Notes

- Requires **Python 3.10–3.14** on `PATH` and administrator/root (the launcher elevates for you).
- **Back up your 24-word mnemonic.** It is the only way to recover your wallet.
- Supported platforms: Linux x86-64 and Windows x64.

Full history in the [CHANGELOG](CHANGELOG.md).
